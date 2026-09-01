use anyhow::{Context, Result};
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
#[command(
    name = "rustbin-analyzer",
    about = "Rust Binary Analyzer for malware triage (RIFT-inspired)"
)]
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

    // === Format & Architecture ===
    let (format, architecture, sections_info) = match Object::parse(data)? {
        Object::PE(pe) => {
            let arch = match pe.header.coff_header.machine {
                0x8664 => Some("x86_64".to_string()),
                0x14c => Some("x86".to_string()),
                0xaa64 => Some("aarch64".to_string()),
                _ => None,
            };

            let mut secs = Vec::new();
            for section in &pe.sections {
                let name = String::from_utf8_lossy(&section.name).trim_end_matches('\0').to_string();
                let offset = section.pointer_to_raw_data as usize;
                let size = section.size_of_raw_data as usize;
                if offset + size <= data.len() && size > 0 {
                    let entropy = calculate_entropy(&data[offset..offset + size]);
                    secs.push((name, size, entropy));
                }
            }
            ("PE".to_string(), arch, secs)
        }
        Object::Elf(elf) => {
            let arch = match elf.header.e_machine {
                goblin::elf::header::EM_X86_64 => Some("x86_64".to_string()),
                goblin::elf::header::EM_386 => Some("x86".to_string()),
                goblin::elf::header::EM_AARCH64 => Some("aarch64".to_string()),
                _ => None,
            };

            let mut secs = Vec::new();
            for section in &elf.section_headers {
                if let Some(name) = elf.shdr_strtab.get_at(section.sh_name) {
                    let offset = section.sh_offset as usize;
                    let size = section.sh_size as usize;
                    if offset + size <= data.len() && size > 64 {
                        let entropy = calculate_entropy(&data[offset..offset + size]);
                        secs.push((name.to_string(), size, entropy));
                    }
                }
            }
            ("ELF".to_string(), arch, secs)
        }
        Object::Mach(_) => ("Mach-O".to_string(), None, Vec::new()),
        _ => ("Unknown".to_string(), None, Vec::new()),
    };

    // === Strings ===
    let strings = extract_strings(data, 5);

    // === Rust Detection ===
    let is_rust = detect_rust(&strings, data);

    // === Compiler Info ===
    let (rustc_version, rustc_commit_hash) = extract_rustc_info(&strings);

    // === Dependencies ===
    let mut deps = extract_dependencies_from_paths(&strings);
    let deps_from_panic = extract_from_panic_messages(&strings);
    for d in deps_from_panic {
        deps.insert(d);
    }
    let mut dependencies: Vec<CrateInfo> = deps.into_iter().collect();
    dependencies.sort_by(|a, b| a.name.cmp(&b.name));

    // === Risk Scoring ===
    let mut score: u32 = 0;

    if is_rust {
        score += 40;
        indicators.push("Binary compiled with Rust".to_string());
    }

    // High entropy sections
    for (name, _size, entropy) in &sections_info {
        if *entropy >= 7.0 {
            score += 15;
            indicators.push(format!("High entropy section: {} ({:.2})", name, entropy));
        } else if *entropy >= 6.5 {
            score += 8;
            indicators.push(format!("Elevated entropy section: {} ({:.2})", name, entropy));
        }
    }

    // Suspicious strings
    let sus_strings = find_suspicious_strings(&strings);
    if !sus_strings.is_empty() {
        let add = (sus_strings.len() as u32 * 4).min(20);
        score += add;
        for s in sus_strings.iter().take(6) {
            indicators.push(format!("Suspicious string: {}", s));
        }
        if sus_strings.len() > 6 {
            indicators.push(format!("... and {} more suspicious strings", sus_strings.len() - 6));
        }
    }

    // Overlay detection (simple)
    if let Some(overlay_size) = detect_overlay(data, &format) {
        if overlay_size > 50_000 {
            score += 12;
            indicators.push(format!("Large overlay detected ({} bytes)", overlay_size));
        } else if overlay_size > 10_000 {
            score += 6;
            indicators.push(format!("Overlay detected ({} bytes)", overlay_size));
        }
    }

    // Heavily stripped / no version info
    if is_rust && rustc_version.is_none() {
        score += 8;
        indicators.push("No rustc version found (possibly heavily stripped)".to_string());
    }

    if is_rust && dependencies.is_empty() {
        score += 5;
        notes.push("Rust binary but no dependency information recovered".to_string());
    }

    // Cap score
    if score > 100 {
        score = 100;
    }

    // Risk level
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
    })
}

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
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
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
    let indicators = [
        "rustc version",
        "rust_begin_unwind",
        "core::panicking",
        "std::sys",
        "alloc::",
        "rust_eh_personality",
        ".cargo/registry",
        "rustc-stable",
        "rustc-nightly",
    ];

    for s in strings {
        for ind in &indicators {
            if s.contains(ind) {
                return true;
            }
        }
    }
    data.windows(5).any(|w| w == b"rustc")
}

fn extract_rustc_info(strings: &[String]) -> (Option<String>, Option<String>) {
    let re_version = Regex::new(r"rustc version (\d+\.\d+\.\d+(?:-nightly|-beta)?)").unwrap();
    let re_commit = Regex::new(r"\(([0-9a-f]{9,40})\s+\d{4}-\d{2}-\d{2}\)").unwrap();
    let re_full_hash = Regex::new(r"\b([0-9a-f]{40})\b").unwrap();

    let mut version = None;
    let mut commit = None;

    for s in strings {
        if version.is_none() {
            if let Some(caps) = re_version.captures(s) {
                version = Some(caps[1].to_string());
            }
        }
        if commit.is_none() {
            if let Some(caps) = re_commit.captures(s) {
                commit = Some(caps[1].to_string());
            } else if let Some(caps) = re_full_hash.captures(s) {
                if s.to_lowercase().contains("rustc") || s.contains("commit") {
                    commit = Some(caps[1].to_string());
                }
            }
        }
    }
    (version, commit)
}

fn extract_dependencies_from_paths(strings: &[String]) -> HashSet<CrateInfo> {
    let mut deps = HashSet::new();
    let re = Regex::new(
        r"[\\/]([a-zA-Z][a-zA-Z0-9_-]{1,64})-(\d+\.\d+\.\d+(?:-[a-zA-Z0-9.]+)?(?:\+[a-zA-Z0-9.]+)?)",
    )
    .unwrap();

    for s in strings {
        if s.contains(".cargo") || s.contains("registry") || s.contains("/src/") {
            for caps in re.captures_iter(s) {
                let name = caps[1].to_string();
                let version = caps[2].to_string();
                let blacklist = ["src", "registry", "github", "crates", "index", "cache"];
                if name.len() > 2 && !blacklist.contains(&name.as_str()) {
                    deps.insert(CrateInfo {
                        name,
                        version: Some(version),
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
        if s.contains("panicked") || s.contains(".rs:") || s.contains("at ") {
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
    let url_re = Regex::new(r"https?://[^\s/$.?#].[^\s]*").unwrap();
    let domain_re = Regex::new(r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|ru|cn|xyz|top|info)\b").unwrap();

    let keywords = [
        "cmd.exe", "powershell", "CreateRemoteThread", "VirtualAlloc",
        "WriteProcessMemory", "mutex", "HKEY_", "AppData\\", "Temp\\",
        "bitcoin", "wallet", "ransom", "encrypt", "decrypt", "tor2web",
        "pastebin", "discord.com/api", "telegram", "http://", "https://",
    ];

    for s in strings {
        let lower = s.to_lowercase();

        if ip_re.is_match(s) && !s.starts_with("0.") && !s.starts_with("127.") {
            found.push(s.clone());
            continue;
        }
        if url_re.is_match(s) {
            found.push(s.clone());
            continue;
        }
        if domain_re.is_match(s) {
            found.push(s.clone());
            continue;
        }
        for kw in &keywords {
            if lower.contains(&kw.to_lowercase()) {
                found.push(s.clone());
                break;
            }
        }
    }

    // Deduplicate & limit
    let mut unique = HashSet::new();
    let mut result = Vec::new();
    for s in found {
        if unique.insert(s.clone()) {
            result.push(s);
        }
        if result.len() >= 15 {
            break;
        }
    }
    result
}

fn detect_overlay(data: &[u8], format: &str) -> Option<usize> {
    // Very simple overlay detection
    if format == "PE" {
        if let Ok(Object::PE(pe)) = Object::parse(data) {
            let mut max_end = 0usize;
            for section in &pe.sections {
                let end = section.pointer_to_raw_data as usize + section.size_of_raw_data as usize;
                if end > max_end {
                    max_end = end;
                }
            }
            if max_end > 0 && data.len() > max_end + 256 {
                return Some(data.len() - max_end);
            }
        }
    }
    None
}

fn print_report(report: &AnalysisReport) {
    // Header
    println!("{}", "┌─────────────────────────────────────────────────────────────┐".bright_blue());
    println!("{}", "│           RUSTBIN ANALYZER  v0.2                            │".bright_blue());
    println!("{}", "│     Static Analysis & Triage for Rust Binaries              │".bright_blue());
    println!("{}", "└─────────────────────────────────────────────────────────────┘".bright_blue());
    println!();

    // Basic info
    println!("  {:<14} {}", "File".bold(), report.file);
    println!("  {:<14} {} bytes", "Size".bold(), report.file_size);
    println!("  {:<14} {}", "SHA256".bold(), report.sha256);
    println!("  {:<14} {}", "Format".bold(), report.format);
    if let Some(arch) = &report.architecture {
        println!("  {:<14} {}", "Architecture".bold(), arch);
    }
    println!();

    // Triage Box
    let (level_colored, border_color) = match report.risk_level.as_str() {
        "HIGH RISK" => (
            format!("[HIGH RISK]").red().bold().to_string(),
            "red",
        ),
        "NEEDS REVIEW" => (
            format!("[NEEDS REVIEW]").yellow().bold().to_string(),
            "yellow",
        ),
        _ => (
            format!("[LOW]").green().bold().to_string(),
            "green",
        ),
    };

    match border_color {
        "red" => {
            println!("{}", "┌─ TRIAGE ────────────────────────────────────────────────────┐".red());
            println!("│  Status     : {}                       │", level_colored);
            println!("│  Risk Score : {:>3} / 100                                         │", report.risk_score);
            println!("{}", "└─────────────────────────────────────────────────────────────┘".red());
        }
        "yellow" => {
            println!("{}", "┌─ TRIAGE ────────────────────────────────────────────────────┐".yellow());
            println!("│  Status     : {}                    │", level_colored);
            println!("│  Risk Score : {:>3} / 100                                         │", report.risk_score);
            println!("{}", "└─────────────────────────────────────────────────────────────┘".yellow());
        }
        _ => {
            println!("{}", "┌─ TRIAGE ────────────────────────────────────────────────────┐".green());
            println!("│  Status     : {}                              │", level_colored);
            println!("│  Risk Score : {:>3} / 100                                         │", report.risk_score);
            println!("{}", "└─────────────────────────────────────────────────────────────┘".green());
        }
    }
    println!();

    // Rust info
    println!("  {:<14} {}", "Is Rust".bold(), if report.is_rust { "YES".green() } else { "NO".normal() });
    if let Some(v) = &report.rustc_version {
        println!("  {:<14} {}", "rustc".bold(), v);
    }
    if let Some(h) = &report.rustc_commit_hash {
        println!("  {:<14} {}", "Commit".bold(), h);
    }
    println!();

    // Dependencies
    println!("{}", "  Dependencies:".bold());
    if report.dependencies.is_empty() {
        println!("    (none recovered)");
    } else {
        for dep in report.dependencies.iter().take(15) {
            match &dep.version {
                Some(v) => println!("    • {:<28} {}", dep.name, v),
                None => println!("    • {}", dep.name),
            }
        }
        if report.dependencies.len() > 15 {
            println!("    ... and {} more", report.dependencies.len() - 15);
        }
    }
    println!();

    // Indicators
    if !report.indicators.is_empty() {
        println!("{}", "  Suspicious Indicators:".bold().yellow());
        for ind in &report.indicators {
            println!("    • {}", ind);
        }
        println!();
    }

    // Notes
    if !report.notes.is_empty() {
        println!("{}", "  Notes:".bold());
        for n in &report.notes {
            println!("    - {}", n);
        }
        println!();
    }
}