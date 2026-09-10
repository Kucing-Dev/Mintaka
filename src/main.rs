mod live;
mod report;
mod risk;
mod static_analysis;
mod tui;
mod types;
mod virustotal;

use anyhow::{Context, Result};
use clap::Parser;
use std::fs;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;
use walkdir::WalkDir;

use report::{print_live_reports, print_static_report, save_live_csv_file, save_static_csv_file};
use static_analysis::analyze;
use types::AnalysisReport;
use virustotal::VtClient;

#[derive(Parser, Debug)]
#[command(
    name = "mintaka",
    about = "Mintaka - Static & Live Process Triage for Malware Analysis"
)]
struct Args {
    /// File or directory path to analyze statically (optional if using --live or --tui)
    path: Option<PathBuf>,

    /// Perform live process and network triage scan (single snapshot)
    #[arg(short, long)]
    live: bool,

    /// Launch interactive Ratatui TUI dashboard
    #[arg(short, long)]
    tui: bool,

    /// Continuous real-time stream mode (print stream to terminal)
    #[arg(short, long)]
    watch: bool,

    /// Watch/TUI refresh interval in seconds (default: 2)
    #[arg(short, long, default_value = "2")]
    interval: u64,

    /// Target specific PID for live scan (optional)
    #[arg(long)]
    pid: Option<u32>,

    /// Target specific process name for live scan (optional)
    #[arg(long)]
    name: Option<String>,

    /// VirusTotal API v3 Key for hash & IP reputation lookup
    #[arg(long, env = "VT_API_KEY")]
    vt_key: Option<String>,

    /// Output as JSON
    #[arg(long)]
    json: bool,

    /// Save result as CSV file (mintaka_report.csv or mintaka_live_report.csv)
    #[arg(long)]
    csv: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let vt_client = args.vt_key.as_ref().map(|k| VtClient::new(k.clone()));

    if args.tui {
        return tui::run_interactive_tui(args.vt_key, args.interval);
    }

    if args.watch {
        if !args.json && !args.csv {
            return tui::run_interactive_tui(args.vt_key, args.interval);
        }

        loop {
            print!("\x1B[2J\x1B[1H");
            let live_reports = live::scan_live_processes(args.pid, args.name.as_deref(), vt_client.as_ref())?;

            if args.json {
                println!("{}", serde_json::to_string_pretty(&live_reports)?);
            } else if args.csv {
                save_live_csv_file(&live_reports)?;
            } else {
                print_live_reports(&live_reports);
            }

            thread::sleep(Duration::from_secs(args.interval));
        }
    }

    if args.live {
        let live_reports = live::scan_live_processes(args.pid, args.name.as_deref(), vt_client.as_ref())?;

        if args.json {
            println!("{}", serde_json::to_string_pretty(&live_reports)?);
        } else if args.csv {
            save_live_csv_file(&live_reports)?;
        } else {
            print_live_reports(&live_reports);
        }
        return Ok(());
    }

    let target_path = match args.path {
        Some(p) => p,
        None => {
            eprintln!("Error: Please specify a file/directory path to analyze, or use '--tui' / '--live' for process scan.");
            eprintln!("Usage: mintaka --tui | mintaka --live | mintaka <PATH>");
            std::process::exit(1);
        }
    };

    if target_path.is_dir() {
        mass_scan(&target_path, args.json, args.csv)?;
    } else {
        let data = fs::read(&target_path)
            .with_context(|| format!("Failed to read file: {}", target_path.display()))?;
        let report = analyze(&target_path, &data)?;

        if args.json {
            println!("{}", serde_json::to_string_pretty(&report)?);
        } else if args.csv {
            save_static_csv_file(&[report])?;
        } else {
            print_static_report(&report);
        }
    }
    Ok(())
}

fn mass_scan(dir: &Path, json_output: bool, csv_output: bool) -> Result<()> {
    let mut reports: Vec<AnalysisReport> = Vec::new();

    for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        let metadata = match fs::metadata(path) {
            Ok(m) => m,
            Err(_) => continue,
        };

        if metadata.len() < 64 || metadata.len() > 80_000_000 {
            continue;
        }

        if let Ok(data) = fs::read(path) {
            if let Ok(report) = analyze(path, &data) {
                reports.push(report);
            }
        }
    }

    reports.sort_by(|a, b| b.risk_score.cmp(&a.risk_score));

    if json_output {
        println!("{}", serde_json::to_string_pretty(&reports)?);
        return Ok(());
    }

    if csv_output {
        save_static_csv_file(&reports)?;
        return Ok(());
    }

    for r in &reports {
        print_static_report(r);
    }

    Ok(())
}
