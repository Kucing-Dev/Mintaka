use crate::types::{AnalysisReport, LiveProcessReport};
use anyhow::{Context, Result};
use colored::*;
use std::fs::File;
use std::io::Write;
use std::path::Path;

pub fn print_static_report(report: &AnalysisReport) {
    let width = 66;

    println!("{}", "═".repeat(width).bright_cyan());
    println!(
        "{}",
        format!("{:^width$}", "MINTAKA v0.9", width = width)
            .bright_cyan()
            .bold()
    );
    println!(
        "{}",
        format!(
            "{:^width$}",
            "Static Analysis & Triage for Rust Binaries",
            width = width
        )
        .cyan()
    );
    println!("{}", "═".repeat(width).bright_cyan());
    println!();

    println!("{}  {}", "File".bold().white(), report.file);
    println!("{}  {} bytes", "Size".bold().white(), report.file_size);
    println!("{}  {}", "SHA256".bold().white(), report.sha256);
    println!("{}  {}", "Format".bold().white(), report.format);
    if let Some(arch) = &report.architecture {
        println!("{}  {}", "Architecture".bold().white(), arch);
    }
    println!("{}  {:.2}", "File Entropy".bold().white(), report.file_entropy);
    println!("{}  {}", "Sections".bold().white(), report.section_count);
    if let Some(ts) = &report.compile_timestamp {
        println!("{}  {}", "Compiled".bold().white(), ts);
    }
    if let Some(ep) = &report.entry_point {
        println!("{}  {}", "Entry Point".bold().white(), ep);
    }
    if let Some(p) = &report.packer_hint {
        println!("{}  {}", "Packer/Compiler".bold().white(), p.yellow());
    }

    if report.is_signed {
        let pub_name = report.signature_publisher.as_deref().unwrap_or("Valid");
        println!("{}  {}", "Signature".bold().white(), pub_name.green().bold());
    } else {
        println!("{}  {}", "Signature".bold().white(), "Un-signed".bright_black());
    }

    let res_info = if report.has_resources {
        match report.resource_size {
            Some(sz) => format!("Yes ({} bytes)", sz).cyan().to_string(),
            None => "Yes".cyan().to_string(),
        }
    } else {
        "No".to_string()
    };
    println!("{}  {}", "Resources".bold().white(), res_info);

    if let Some(ov) = report.overlay_size {
        println!("{}  {} bytes", "Overlay".bold().white(), ov);
    }
    println!();

    let (status_display, color) = match report.risk_level.as_str() {
        "HIGH RISK" => ("[HIGH RISK]".red().bold().to_string(), "red"),
        "NEEDS REVIEW" => ("[NEEDS REVIEW]".yellow().bold().to_string(), "yellow"),
        _ => ("[LOW]".green().bold().to_string(), "green"),
    };

    let border = "─".repeat(64);

    match color {
        "red" => {
            println!("{}", format!("┌{}┐", border).red());
            println!(
                "{}  Status      : {:<48} {}",
                "│".red(),
                status_display,
                "│".red()
            );
            println!(
                "{}  Risk Score  : {:>3} / 100{:<40} {}",
                "│".red(),
                report.risk_score,
                "",
                "│".red()
            );
            println!("{}", format!("└{}┘", border).red());
        }
        "yellow" => {
            println!("{}", format!("┌{}┐", border).yellow());
            println!(
                "{}  Status      : {:<48} {}",
                "│".yellow(),
                status_display,
                "│".yellow()
            );
            println!(
                "{}  Risk Score  : {:>3} / 100{:<40} {}",
                "│".yellow(),
                report.risk_score,
                "",
                "│".yellow()
            );
            println!("{}", format!("└{}┘", border).yellow());
        }
        _ => {
            println!("{}", format!("┌{}┐", border).green());
            println!(
                "{}  Status      : {:<48} {}",
                "│".green(),
                status_display,
                "│".green()
            );
            println!(
                "{}  Risk Score  : {:>3} / 100{:<40} {}",
                "│".green(),
                report.risk_score,
                "",
                "│".green()
            );
            println!("{}", format!("└{}┘", border).green());
        }
    }
    println!();

    print!("{}  ", "Is Rust".bold().white());
    if report.is_rust {
        println!("{}", "YES".green().bold());
    } else {
        println!("{}", "NO");
    }
    if let Some(v) = &report.rustc_version {
        println!("{}  {}", "rustc".bold().white(), v);
    }
    if let Some(h) = &report.rustc_commit_hash {
        println!("{}  {}", "Commit".bold().white(), h);
    }
    println!();

    if !report.suspicious_imports.is_empty() {
        println!("{}", "Suspicious Imports".bold().red());
        for imp in report.suspicious_imports.iter().take(10) {
            println!("  • {}", imp);
        }
        println!();
    }

    if !report.sections.is_empty() {
        println!("{}", "Sections".bold().white());
        println!(
            "  {:<12} {:>10} {:>8} {:>6}  {}",
            "Name", "Size", "Entropy", "Flags", "Note"
        );
        for sec in &report.sections {
            let note = if sec.suspicious {
                "← Suspicious".red().to_string()
            } else {
                "".to_string()
            };
            println!(
                "  {:<12} {:>10} {:>8.2} {:>6}  {}",
                sec.name, sec.size, sec.entropy, sec.characteristics, note
            );
        }
        println!();
    }

    if !report.iocs.is_empty() {
        println!("{}", "Extracted IOCs".bold().yellow());
        for ioc in &report.iocs {
            println!("  • {}", ioc);
        }
        println!();
    }

    println!("{}", "Dependencies".bold().white());
    if report.dependencies.is_empty() {
        println!("  (none recovered)");
    } else {
        for dep in report.dependencies.iter().take(8) {
            match &dep.version {
                Some(v) => println!("  • {:<24} {}", dep.name, v),
                None => println!("  • {}", dep.name),
            }
        }
    }
    println!();

    if !report.indicators.is_empty() {
        println!("{}", "Suspicious Indicators".bold().yellow());
        for ind in report.indicators.iter().take(10) {
            println!("  • {}", ind);
        }
        println!();
    }

    if !report.notes.is_empty() {
        println!("{}", "Notes".bold().white());
        for n in &report.notes {
            println!("  - {}", n);
        }
        println!();
    }
}

pub fn save_static_csv_file(reports: &[AnalysisReport]) -> Result<()> {
    let filename = "mintaka_report.csv";
    let mut file = File::create(filename)
        .with_context(|| format!("Failed to create {}", filename))?;

    writeln!(
        file,
        "file,size,sha256,format,architecture,risk_score,risk_level,is_rust,packer,resources,entropy,sections"
    )?;

    for r in reports {
        let name = Path::new(&r.file)
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| r.file.clone());

        let arch = r.architecture.clone().unwrap_or_else(|| "-".to_string());
        let packer = r.packer_hint.clone().unwrap_or_else(|| "-".to_string());
        let resources = if r.has_resources {
            match r.resource_size {
                Some(sz) => format!("Yes ({} bytes)", sz),
                None => "Yes".to_string(),
            }
        } else {
            "No".to_string()
        };

        let safe = |s: &str| {
            if s.contains(',') || s.contains('"') || s.contains('\n') {
                format!("\"{}\"", s.replace('"', "\"\""))
            } else {
                s.to_string()
            }
        };

        writeln!(
            file,
            "{},{},{},{},{},{},{},{},{},{},{:.2},{}",
            safe(&name),
            r.file_size,
            r.sha256,
            r.format,
            arch,
            r.risk_score,
            r.risk_level,
            if r.is_rust { "YES" } else { "NO" },
            safe(&packer),
            safe(&resources),
            r.file_entropy,
            r.section_count
        )?;
    }

    println!("{}  {}", "CSV report saved to:".green().bold(), filename);
    Ok(())
}

use chrono::Local;

pub fn print_live_reports(reports: &[LiveProcessReport]) {
    let width = 110;
    let now_str = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let header_title = format!("MINTAKA v0.9 - Real-Time Process & Network Triage ({})", now_str);

    println!("{}", "═".repeat(width).bright_cyan());
    println!(
        "{}",
        format!("{:^width$}", header_title, width = width)
            .bright_cyan()
            .bold()
    );
    println!("{}", "═".repeat(width).bright_cyan());
    println!();

    println!(
        "{:<8} {:<24} {:>6} {:<12} {:>6} {:>8} {:<12}",
        "PID".bold(),
        "Process Name".bold(),
        "Score".bold(),
        "Risk Level".bold(),
        "Conns".bold(),
        "DLLs".bold(),
        "VT Hits".bold()
    );
    println!("{}", "─".repeat(width));

    let mut high = 0;
    let mut medium = 0;
    let mut low = 0;

    for r in reports {
        match r.risk_level.as_str() {
            "HIGH RISK" => high += 1,
            "NEEDS REVIEW" => medium += 1,
            _ => low += 1,
        }

        let short_name = if r.name.len() > 22 {
            format!("{}...", &r.name[..19])
        } else {
            r.name.clone()
        };

        let risk_str = match r.risk_level.as_str() {
            "HIGH RISK" => format!("{:<12}", "HIGH RISK".red().bold()),
            "NEEDS REVIEW" => format!("{:<12}", "NEEDS REVIEW".yellow().bold()),
            _ => format!("{:<12}", "LOW".green()),
        };

        let conn_count = r.network_connections.len();
        let dll_count = r.loaded_dlls.len();

        let vt_str = if let Some(ref vt) = r.vt_report {
            if vt.exe_total > 0 {
                format!("{}/{}", vt.exe_positives, vt.exe_total)
            } else {
                "-".to_string()
            }
        } else {
            "-".to_string()
        };

        println!(
            "{:<8} {:<24} {:>6} {} {:>6} {:>8} {:<12}",
            r.pid, short_name, r.risk_score, risk_str, conn_count, dll_count, vt_str
        );

        // Sub-details for non-LOW or detailed processes
        if !r.indicators.is_empty() {
            for ind in r.indicators.iter().take(3) {
                println!("  └─ {} {}", "•".yellow(), ind);
            }
        }

        for conn in &r.network_connections {
            if conn.remote_ip != "-" && !conn.remote_ip.starts_with("127.") {
                let vt_info = if let Some(ref rep) = conn.vt_reputation {
                    if rep.malicious_votes > 0 {
                        format!(" [VT: {} Malicious]", rep.malicious_votes)
                            .red()
                            .bold()
                            .to_string()
                    } else {
                        "".to_string()
                    }
                } else {
                    "".to_string()
                };

                println!(
                    "  └─ {} {} -> {}:{}{}",
                    "Net:".cyan(),
                    conn.local_addr,
                    conn.remote_ip,
                    conn.remote_port,
                    vt_info
                );
            }
        }
    }

    println!();
    println!("{}", "─".repeat(width));
    println!("{}: {}", "Total Scanned".bold(), reports.len());
    println!("{}: {}", "HIGH RISK".red().bold(), high);
    println!("{}: {}", "NEEDS REVIEW".yellow().bold(), medium);
    println!("{}: {}", "LOW".green().bold(), low);
    println!();
}

pub fn save_live_csv_file(reports: &[LiveProcessReport]) -> Result<()> {
    let filename = "mintaka_live_report.csv";
    let mut file = File::create(filename)
        .with_context(|| format!("Failed to create {}", filename))?;

    writeln!(
        file,
        "pid,name,exe_path,risk_score,risk_level,network_connections,loaded_dlls,vt_exe_hits,indicators"
    )?;

    let safe = |s: &str| {
        if s.contains(',') || s.contains('"') || s.contains('\n') {
            format!("\"{}\"", s.replace('"', "\"\""))
        } else {
            s.to_string()
        }
    };

    for r in reports {
        let exe = r.exe_path.as_deref().unwrap_or("-");
        let vt_hits = r
            .vt_report
            .as_ref()
            .map(|vt| format!("{}/{}", vt.exe_positives, vt.exe_total))
            .unwrap_or_else(|| "-".to_string());
        let inds = r.indicators.join(" | ");

        writeln!(
            file,
            "{},{},{},{},{},{},{},{},{}",
            r.pid,
            safe(&r.name),
            safe(exe),
            r.risk_score,
            r.risk_level,
            r.network_connections.len(),
            r.loaded_dlls.len(),
            vt_hits,
            safe(&inds)
        )?;
    }

    println!("{}  {}", "Live CSV report saved to:".green().bold(), filename);
    Ok(())
}
