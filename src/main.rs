use anyhow::{Context, Result};
use chrono::{TimeZone, Utc};
use clap::Parser;
use colored::*;
use goblin::Object;
use regex::Regex;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "mintaka", about = "Mintaka - Static Analysis & Triage for Rust Binaries")]
struct Args {
    /// Path to the binary
    file: PathBuf,

    /// Output as JSON
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Serialize)]
struct AnalysisReport {
    file: String,
    file_size: u64,
    sha256: String,
    format: String,
    architecture: Option<String>,
    is_rust: bool,
    rustc_version: Option<String>,
    rustc_commit_hash: Option<String>,
    dependencies: Vec<CrateInfo>,
    risk_score: u32,
    risk_level: String,
    indicators: Vec<String>,
    notes: Vec<String>,
    // Extra info
    file_entropy: f64,
    section_count: usize,
    compile_timestamp: Option<String>,
    entry_point: Option<String>,
    packer_hint: Option<String>,
    overlay_size: Option<usize>,
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq, Hash)]
struct CrateInfo {
    name: String,
    version: Option<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let data = fs::read(&args.file)
        .with_context(|| format!("Failed to read file: {}", args.file.display()))?;

    let report = analyze(&args.file, &data)?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_report(&report);
    }
    Ok(())
}

fn analyze(path: &PathBuf, data: &[u8]) -> Result<AnalysisReport> {
    let mut notes = Vec::new();
    let mut indicators = Vec::new();
    let sha256 = hex::encode(Sha256::digest(data));
    let file_entropy = calculate_entropy(data);

    let mut section_count = 0;
    let mut compile_timestamp = None;
    let mut entry_point = None;
    let mut packer_hint = None;
    let mut overlay_size = None;
    let mut sections_info: Vec<(String, usize, f64)> = Vec::new();

    // === Parse binary ===
    let (format, architecture) = match Object::parse(data)? {
        Object::PE(pe) => {
            let arch = match pe.header.coff_header.machine {
                0x8664 => Some("x86_64".to_string()),
                0x14c => Some("x86".to_string()),
                0xaa64 => Some("aarch64".to_string()),
                _ => None,
            };

            // Timestamp
            let ts = pe.header.coff_header.time_date_stamp;
            if ts > 0 {
                if let Some(dt) = Utc.timestamp_opt(ts as i64, 0).single() {
                    compile_timestamp = Some(dt.format("%Y-%m-%d %H:%M:%S UTC").to_string());
                }
            }

            // Entry point
            if let Some(opt) = pe.header.optional_header {
                entry_point = Some(format!("0x{:08X}", opt.standard_fields.address_of_entry_point));
            }

            section_count = pe.sections.len();
            let mut max_end = 0usize;

            for section in &pe.sections {
                let name = String::from_utf8_lossy(&section.name)
                    .trim_end_matches('\0')
                    .to_string();
                let offset = section.pointer_to_raw_data as usize;
                let size = section.size_of_raw_data as usize;

                if offset + size <= data.len() && size > 0 {
                    let entropy = calculate_entropy(&data[offset..offset + size]);
                    sections_info.push((name.clone(), size, entropy));
                }

                let end = offset + size;
                if end > max_end {
                    max_end = end;
                }

                // Simple packer detection
                let lname = name.to_lowercase();
                if lname.contains("upx") {
                    packer_hint = Some("UPX".to_string());
                } else if lname.contains("vmp") || lname.contains("themida") {
                    packer_hint = Some("Protector (VMProtect/Themida-like)".to_string());
                }
            }

            if max_end > 0 && data.len() > max_end + 64 {
                overlay_size = Some(data.len() - max_end);
            }

            ("PE".to_string(), arch)
        }
        Object::Elf(elf) => {
            let arch = match elf.header.e_machine {
                goblin::elf::header::EM_X86_64 => Some("x86_64".to_string()),
                goblin::elf::header::EM_386 => Some("x86".to_string()),
                goblin::elf::header::EM_AARCH64 => Some("aarch64".to_string()),
                _ => None,
            };

            section_count = elf.section_headers.len();
            entry_point = Some(format!("0x{:X}", elf.header.e_entry));

            for section in &elf.section_headers {
                if let Some(name) = elf.shdr_strtab.get_at(section.sh_name) {
                    let offset = section.sh_offset as usize;
                    let size = section.sh_size as usize;
                    if offset + size <= data.len() && size > 64 {
                        let entropy = calculate_entropy(&data[offset..offset + size]);
                        sections_info.push((name.to_string(), size, entropy));
                    }
                }
            }
            ("ELF".to_string(), arch)
        }
        Object::Mach(_) => ("Mach-O".to_string(), None),
        _ => ("Unknown".to_string(), None),
    };

    // === Strings & Rust detection ===
    let strings = extract_strings(data, 5);
    let is_rust = detect_rust(&strings, data);
    let (rustc_version, rustc_commit_hash) = extract_rustc_info(&strings);

    // Dependencies
    let mut deps = extract_dependencies_from_paths(&strings);
    for d in extract_from_panic_messages(&strings) {
        deps.insert(d);
    }
    let mut dependencies: Vec<CrateInfo> = deps.into_iter().collect();
    dependencies.sort_by(|a, b| a.name.cmp(&b.name));

    // === Risk Scoring ===
    let mut score: u32 = 0;

    if is_rust {
        score += 40;
        indicators.push("Compiled with Rust".to_string());
    }

    // File entropy
    if file_entropy >= 7.2 {
        score += 12;
        indicators.push(format!("Very high file entropy ({:.2})", file_entropy));
    } else if file_entropy >= 6.8 {
        score += 7;
        indicators.push(format!("High file entropy ({:.2})", file_entropy));
    }

    // Section entropy
    for (name, _, entropy) in &sections_info {
        if *entropy >= 7.0 {
            score += 12;
            indicators.push(format!("High entropy section: {} ({:.2})", name, entropy));
        } else if *entropy >= 6.5 {
            score += 6;
            indicators.push(format!("Elevated entropy section: {} ({:.2})", name, entropy));
        }
    }

    // Packer
    if let Some(ref p) = packer_hint {
        score += 15;
        indicators.push(format!("Possible packer/protector: {}", p));
    }

    // Overlay
    if let Some(size) = overlay_size {
        if size > 80_000 {
            score += 12;
            indicators.push(format!("Large overlay ({} bytes)", size));
        } else if size > 15_000 {
            score += 6;
            indicators.push(format!("Overlay detected ({} bytes)", size));
        }
    }

    // Suspicious strings
    let sus = find_suspicious_strings(&strings);
    if !sus.is_empty() {
        let add = (sus.len() as u32 * 3).min(18);
        score += add;
        for s in sus.iter().take(5) {
            indicators.push(format!("Suspicious string: {}", truncate(s, 60)));
        }
        if sus.len() > 5 {
            indicators.push(format!("... +{} more suspicious strings", sus.len() - 5));
        }
    }

    if is_rust && rustc_version.is_none() {
        score += 8;
        indicators.push("No rustc version recovered (possibly stripped)".to_string());
    }

    if is_rust && dependencies.is_empty() {
        score += 5;
    }

    if score > 100 {
        score = 100;
    }

    let risk_level = if score >= 70 {
        "HIGH RISK".to_string()
    } else if score >= 40 {
        "NEEDS REVIEW".to_string()
    } else {
        "LOW".to_string()
    };

    if !is_rust {
        notes.push("This does not appear to be a Rust binary".to_string());
    }
    if data.len() < 50_000 && is_rust {
        notes.push("Unusually small for a typical Rust binary (static linking)".to_string());
    }

    Ok(AnalysisReport {
        file: path.display().to_string(),
        file_size: data.len() as u64,
        sha256,
        format,
        architecture,
        is_rust,
        rustc_version,
        rustc_commit_hash,
        dependencies,
        risk_score: score,
        risk_level,
        indicators,
        notes,
        file_entropy,
        section_count,
        compile_timestamp,
        entry_point,
        packer_hint,
        overlay_size,
    })
}

// ===== Helper functions =====

fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &c in &freq {
        if c > 0 {
            let p = c as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

fn extract_strings(data: &[u8], min_len: usize) -> Vec<String> {
    let mut result = Vec::new();
    let mut current = Vec::new();
    for &b in data {
        if b.is_ascii_graphic() || b == b' ' || b == b'\t' {
            current.push(b);
        } else {
            if current.len() >= min_len {
                if let Ok(s) = String::from_utf8(current.clone()) {
                    result.push(s);
                }
            }
            current.clear();
        }
    }
    if current.len() >= min_len {
        if let Ok(s) = String::from_utf8(current) {
            result.push(s);
        }
    }
    result
}

fn detect_rust(strings: &[String], data: &[u8]) -> bool {
    let keys = [
        "rustc version", "rust_begin_unwind", "core::panicking", "std::sys",
        "alloc::", "rust_eh_personality", ".cargo/registry", "rustc-stable", "rustc-nightly",
    ];
    for s in strings {
        for k in &keys {
            if s.contains(k) {
                return true;
            }
        }
    }
    data.windows(5).any(|w| w == b"rustc")
}

fn extract_rustc_info(strings: &[String]) -> (Option<String>, Option<String>) {
    let re_ver = Regex::new(r"rustc version (\d+\.\d+\.\d+(?:-nightly|-beta)?)").unwrap();
    let re_commit = Regex::new(r"\(([0-9a-f]{9,40})\s+\d{4}-\d{2}-\d{2}\)").unwrap();
    let mut version = None;
    let mut commit = None;
    for s in strings {
        if version.is_none() {
            if let Some(c) = re_ver.captures(s) {
                version = Some(c[1].to_string());
            }
        }
        if commit.is_none() {
            if let Some(c) = re_commit.captures(s) {
                commit = Some(c[1].to_string());
            }
        }
    }
    (version, commit)
}

fn extract_dependencies_from_paths(strings: &[String]) -> HashSet<CrateInfo> {
    let mut deps = HashSet::new();
    let re = Regex::new(r"[\\/]([a-zA-Z][a-zA-Z0-9_-]{1,64})-(\d+\.\d+\.\d+(?:-[a-zA-Z0-9.]+)?)").unwrap();
    for s in strings {
        if s.contains(".cargo") || s.contains("registry") {
            for caps in re.captures_iter(s) {
                let name = caps[1].to_string();
                if name.len() > 2 && !["src", "registry", "github", "crates"].contains(&name.as_str()) {
                    deps.insert(CrateInfo {
                        name,
                        version: Some(caps[2].to_string()),
                    });
                }
            }
        }
    }
    deps
}

fn extract_from_panic_messages(strings: &[String]) -> HashSet<CrateInfo> {
    let mut deps = HashSet::new();
    let re = Regex::new(r"\b([a-zA-Z][a-zA-Z0-9_-]{2,40})-(\d+\.\d+\.\d+)\b").unwrap();
    for s in strings {
        if s.contains("panicked") || s.contains(".rs:") {
            for caps in re.captures_iter(s) {
                deps.insert(CrateInfo {
                    name: caps[1].to_string(),
                    version: Some(caps[2].to_string()),
                });
            }
        }
    }
    deps
}

fn find_suspicious_strings(strings: &[String]) -> Vec<String> {
    let mut found = Vec::new();
    let ip_re = Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap();
    let url_re = Regex::new(r"https?://[^\s\"']+").unwrap();

    let keywords = [
        "cmd.exe", "powershell", "CreateRemoteThread", "VirtualAlloc", "WriteProcessMemory",
        "mutex", "HKEY_", "AppData", "Temp\\", "bitcoin", "wallet", "ransom", "encrypt",
        "discord.com", "telegram", "pastebin", "tor2web",
    ];

    for s in strings {
        let lower = s.to_lowercase();
        if ip_re.is_match(s) && !s.starts_with("127.") && !s.starts_with("0.") {
            found.push(s.clone());
        } else if url_re.is_match(s) {
            found.push(s.clone());
        } else {
            for kw in &keywords {
                if lower.contains(&kw.to_lowercase()) {
                    found.push(s.clone());
                    break;
                }
            }
        }
    }

    let mut unique = HashSet::new();
    found.into_iter().filter(|s| unique.insert(s.clone())).take(12).collect()
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max])
    }
}

fn print_report(report: &AnalysisReport) {
    let width = 62;

    // Header
    println!("{}", "┌".bright_cyan().to_string() + &"─".repeat(width) + "┐");
    println!("{}", format!("│{:^width$}│", "MINTAKA v0.3", width = width).bright_cyan());
    println!("{}", format!("│{:^width$}│", "Static Analysis & Triage for Rust Binaries", width = width).bright_cyan());
    println!("{}", "└".bright_cyan().to_string() + &"─".repeat(width) + "┘");
    println!();

    // Basic Info
    println!("  {:<16} {}", "File".bold().dimmed(), report.file);
    println!("  {:<16} {} bytes", "Size".bold().dimmed(), report.file_size);
    println!("  {:<16} {}", "SHA256".bold().dimmed(), report.sha256);
    println!("  {:<16} {}", "Format".bold().dimmed(), report.format);
    if let Some(arch) = &report.architecture {
        println!("  {:<16} {}", "Architecture".bold().dimmed(), arch);
    }
    println!("  {:<16} {:.2}", "File Entropy".bold().dimmed(), report.file_entropy);
    println!("  {:<16} {}", "Sections".bold().dimmed(), report.section_count);
    if let Some(ts) = &report.compile_timestamp {
        println!("  {:<16} {}", "Compiled".bold().dimmed(), ts);
    }
    if let Some(ep) = &report.entry_point {
        println!("  {:<16} {}", "Entry Point".bold().dimmed(), ep);
    }
    if let Some(p) = &report.packer_hint {
        println!("  {:<16} {}", "Packer Hint".bold().dimmed(), p.yellow());
    }
    if let Some(ov) = report.overlay_size {
        println!("  {:<16} {} bytes", "Overlay".bold().dimmed(), ov);
    }
    println!();

    // Triage Box
    let (status_text, color) = match report.risk_level.as_str() {
        "HIGH RISK" => ("[HIGH RISK]".red().bold().to_string(), "red"),
        "NEEDS REVIEW" => ("[NEEDS REVIEW]".yellow().bold().to_string(), "yellow"),
        _ => ("[LOW]".green().bold().to_string(), "green"),
    };

    let line = "─".repeat(width);
    match color {
        "red" => {
            println!("{}", format!("┌─ TRIAGE {}", &line[10..]).red());
            println!("│  Status      : {}", status_text);
            println!("│  Risk Score  : {:>3} / 100", report.risk_score);
            println!("{}", format!("└{}", line).red());
        }
        "yellow" => {
            println!("{}", format!("┌─ TRIAGE {}", &line[10..]).yellow());
            println!("│  Status      : {}", status_text);
            println!("│  Risk Score  : {:>3} / 100", report.risk_score);
            println!("{}", format!("└{}", line).yellow());
        }
        _ => {
            println!("{}", format!("┌─ TRIAGE {}", &line[10..]).green());
            println!("│  Status      : {}", status_text);
            println!("│  Risk Score  : {:>3} / 100", report.risk_score);
            println!("{}", format!("└{}", line).green());
        }
    }
    println!();

    // Rust Info
    println!("  {:<16} {}", "Is Rust".bold().dimmed(), 
        if report.is_rust { "YES".green().bold() } else { "NO".normal() });
    
    if let Some(v) = &report.rustc_version {
        println!("  {:<16} {}", "rustc".bold().dimmed(), v);
    }
    if let Some(h) = &report.rustc_commit_hash {
        println!("  {:<16} {}", "Commit".bold().dimmed(), h);
    }
    println!();

    // Dependencies
    println!("{}", "  Dependencies".bold());
    if report.dependencies.is_empty() {
        println!("    (none recovered)");
    } else {
        for dep in report.dependencies.iter().take(12) {
            match &dep.version {
                Some(v) => println!("    • {:<26} {}", dep.name, v),
                None => println!("    • {}", dep.name),
            }
        }
        if report.dependencies.len() > 12 {
            println!("    ... and {} more", report.dependencies.len() - 12);
        }
    }
    println!();

    // Indicators
    if !report.indicators.is_empty() {
        println!("{}", "  Suspicious Indicators".bold().yellow());
        for ind in &report.indicators {
            println!("    • {}", ind);
        }
        println!();
    }

    // Notes
    if !report.notes.is_empty() {
        println!("{}", "  Notes".bold());
        for n in &report.notes {
            println!("    - {}", n);
        }
        println!();
    }
}