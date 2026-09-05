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
    file_entropy: f64,
    section_count: usize,
    compile_timestamp: Option<String>,
    entry_point: Option<String>,
    packer_hint: Option<String>,
    overlay_size: Option<usize>,
    suspicious_imports: Vec<String>,
    sections: Vec<SectionInfo>,
    iocs: Vec<String>,
}

#[derive(Debug, Serialize, Clone)]
struct SectionInfo {
    name: String,
    size: usize,
    entropy: f64,
    characteristics: String,
    suspicious: bool,
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
    let mut overlay_size = None;
    let mut sections_info: Vec<SectionInfo> = Vec::new();
    let mut suspicious_imports: Vec<String> = Vec::new();

    let dangerous_apis: HashSet<&str> = [
        "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
        "WriteProcessMemory", "ReadProcessMemory", "CreateRemoteThread",
        "NtCreateThreadEx", "RtlCreateUserThread", "WinExec", "ShellExecuteA",
        "ShellExecuteW", "CreateProcessA", "CreateProcessW", "URLDownloadToFileA",
        "URLDownloadToFileW", "socket", "connect", "send", "recv", "WSAStartup",
        "InternetOpenA", "InternetOpenUrlA", "HttpSendRequestA", "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent", "OutputDebugStringA", "GetProcAddress",
        "LoadLibraryA", "LoadLibraryW", "GetModuleHandleA", "OpenProcess",
        "TerminateProcess", "CreateToolhelp32Snapshot", "Process32First",
        "SetWindowsHookExA", "SetWindowsHookExW", "RegSetValueExA", "RegSetValueExW",
    ]
    .iter()
    .cloned()
    .collect();

    let (format, architecture) = match Object::parse(data)? {
        Object::PE(pe) => {
            let arch = match pe.header.coff_header.machine {
                0x8664 => Some("x86_64".to_string()),
                0x14c => Some("x86".to_string()),
                0xaa64 => Some("aarch64".to_string()),
                _ => None,
            };

            let ts = pe.header.coff_header.time_date_stamp;
            if ts > 0 {
                if let Some(dt) = Utc.timestamp_opt(ts as i64, 0).single() {
                    compile_timestamp = Some(dt.format("%Y-%m-%d %H:%M:%S UTC").to_string());
                }
            }

            if let Some(opt) = pe.header.optional_header {
                entry_point = Some(format!("0x{:08X}", opt.standard_fields.address_of_entry_point));
            }

            section_count = pe.sections.len();
            let mut max_end = 0usize;

            // Section Analysis
            for section in &pe.sections {
                let name = String::from_utf8_lossy(&section.name)
                    .trim_end_matches('\0')
                    .to_string();
                let offset = section.pointer_to_raw_data as usize;
                let size = section.size_of_raw_data as usize;
                let chars = section.characteristics;

                let readable = chars & 0x40000000 != 0;
                let writable = chars & 0x80000000 != 0;
                let executable = chars & 0x20000000 != 0;

                let mut char_str = String::new();
                if readable {
                    char_str.push('R');
                }
                if writable {
                    char_str.push('W');
                }
                if executable {
                    char_str.push('X');
                }
                if char_str.is_empty() {
                    char_str.push('-');
                }

                let mut entropy = 0.0;
                if offset + size <= data.len() && size > 0 {
                    entropy = calculate_entropy(&data[offset..offset + size]);
                }

                let suspicious = writable && executable;
                if suspicious {
                    indicators.push(format!(
                        "Suspicious section: {} (Writable + Executable)",
                        name
                    ));
                }

                sections_info.push(SectionInfo {
                    name: name.clone(),
                    size,
                    entropy,
                    characteristics: char_str,
                    suspicious,
                });

                let end = offset + size;
                if end > max_end {
                    max_end = end;
                }
            }

            if max_end > 0 && data.len() > max_end + 64 {
                overlay_size = Some(data.len() - max_end);
            }

            // Import Table Analysis
            for import in &pe.imports {
                let dll = import.dll.to_lowercase();
                let api_name = import.name.as_ref();
                if dangerous_apis.contains(api_name) {
                    let entry = format!("{}!{}", dll, api_name);
                    suspicious_imports.push(entry.clone());
                    indicators.push(format!("Suspicious import: {}", entry));
                }
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
                        sections_info.push(SectionInfo {
                            name: name.to_string(),
                            size,
                            entropy,
                            characteristics: "-".to_string(),
                            suspicious: false,
                        });
                    }
                }
            }
            ("ELF".to_string(), arch)
        }
        Object::Mach(_) => ("Mach-O".to_string(), None),
        _ => ("Unknown".to_string(), None),
    };

    // Strings & Rust Detection
    let strings = extract_strings(data, 5);
    let is_rust = detect_rust(&strings, data);
    let (rustc_version, rustc_commit_hash) = extract_rustc_info(&strings);

    // ===== Better Packer / Compiler Detection =====
    let packer_hint = detect_packer_and_compiler(&sections_info, &strings, is_rust);

    // Dependencies
    let mut deps = extract_dependencies_from_paths(&strings);
    for d in extract_from_panic_messages(&strings) {
        deps.insert(d);
    }
    let mut dependencies: Vec<CrateInfo> = deps.into_iter().collect();
    dependencies.sort_by(|a, b| a.name.cmp(&b.name));

    // IOC Extraction
    let iocs = extract_iocs(&strings);

    // ====================== RISK SCORING ======================
    let mut score: u32 = 0;

    if is_rust {
        score += 35;
        indicators.push("Compiled with Rust".to_string());
    }

    let import_score = (suspicious_imports.len() as u32 * 6).min(30);
    score += import_score;

    if file_entropy >= 7.2 {
        score += 12;
        indicators.push(format!("Very high file entropy ({:.2})", file_entropy));
    } else if file_entropy >= 6.8 {
        score += 7;
        indicators.push(format!("High file entropy ({:.2})", file_entropy));
    }

    for sec in &sections_info {
        if sec.suspicious {
            score += 15;
        }
        if sec.entropy >= 7.0 {
            score += 10;
            indicators.push(format!(
                "High entropy section: {} ({:.2})",
                sec.name, sec.entropy
            ));
        } else if sec.entropy >= 6.5 {
            score += 5;
        }
    }

    // Packer scoring
    if let Some(ref p) = packer_hint {
        if p.contains("UPX")
            || p.contains("VMProtect")
            || p.contains("Themida")
            || p.contains("ASPack")
            || p.contains("PECompact")
        {
            score += 18;
        } else if p.contains("Possibly Packed") {
            score += 10;
        } else {
            score += 12;
        }
        indicators.push(format!("Packer/Compiler: {}", p));
    }

    if let Some(size) = overlay_size {
        if size > 80_000 {
            score += 12;
            indicators.push(format!("Large overlay ({} bytes)", size));
        } else if size > 15_000 {
            score += 6;
            indicators.push(format!("Overlay detected ({} bytes)", size));
        }
    }

    if !iocs.is_empty() {
        let add = (iocs.len() as u32 * 2).min(16);
        score += add;
    }

    if is_rust && rustc_version.is_none() {
        score += 8;
        indicators.push("No rustc version recovered (possibly stripped)".to_string());
    }

    if score > 100 {
        score = 100;
    }

    let risk_level = if score >= 75 {
        "HIGH RISK".to_string()
    } else if score >= 45 {
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
        file_entropy,
        section_count,
        compile_timestamp,
        entry_point,
        packer_hint,
        overlay_size,
        suspicious_imports,
        sections: sections_info,
        iocs,
    })
}

// ====================== HELPERS ======================

fn detect_packer_and_compiler(
    sections: &[SectionInfo],
    strings: &[String],
    is_rust: bool,
) -> Option<String> {
    let mut findings: Vec<String> = Vec::new();

    // Section name based
    for sec in sections {
        let name = sec.name.to_lowercase();

        if name.contains("upx") {
            findings.push("UPX".to_string());
        }
        if name.contains("vmp") {
            findings.push("VMProtect".to_string());
        }
        if name.contains("themida") {
            findings.push("Themida".to_string());
        }
        if name.contains("aspack") || name == ".aspack" || name == ".adata" {
            findings.push("ASPack".to_string());
        }
        if name.contains("pec") || name.contains("pecompact") {
            findings.push("PECompact".to_string());
        }
        if name.contains("mpress") {
            findings.push("MPRESS".to_string());
        }
        if name.contains("fsg") {
            findings.push("FSG".to_string());
        }
        if name.contains("petite") {
            findings.push("Petite".to_string());
        }
        if name.contains("enigma") {
            findings.push("Enigma Protector".to_string());
        }
        if name.contains("nsp") || name.contains("nspack") {
            findings.push("NSPack".to_string());
        }
        if name.contains("yoda") {
            findings.push("Yoda Protector".to_string());
        }
    }

    // String based detection
    for s in strings {
        let lower = s.to_lowercase();

        if lower.contains("mscoree.dll") || lower.contains("mscoreei.dll") {
            findings.push(".NET".to_string());
        }
        if lower.contains("go.buildid") || lower.contains("runtime.main") || lower.contains("runtime·") {
            findings.push("Go".to_string());
        }
        if lower.contains("pyi_") || lower.contains("pyinstaller") {
            findings.push("PyInstaller".to_string());
        }
        if lower.contains("autoit") {
            findings.push("AutoIt".to_string());
        }
    }

    if is_rust {
        findings.push("Rust".to_string());
    }

    // Fallback high entropy
    let high_entropy = sections.iter().any(|s| s.entropy >= 7.2);
    if high_entropy && findings.is_empty() {
        findings.push("Possibly Packed (High Entropy)".to_string());
    }

    // Unique
    let mut unique = Vec::new();
    for f in findings {
        if !unique.contains(&f) {
            unique.push(f);
        }
    }

    if unique.is_empty() {
        None
    } else {
        Some(unique.join(" + "))
    }
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
    let re = Regex::new(r"[\\/]([a-zA-Z][a-zA-Z0-9_-]{1,64})-(\d+\.\d+\.\d+(?:-[a-zA-Z0-9.]+)?)")
        .unwrap();

    for s in strings {
        if s.contains(".cargo") || s.contains("registry") {
            for caps in re.captures_iter(s) {
                let name = caps[1].to_string();
                if name.len() > 2 && !["src", "registry", "github", "crates"].contains(&name.as_str())
                {
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

fn extract_iocs(strings: &[String]) -> Vec<String> {
    let mut iocs = Vec::new();
    let mut seen = HashSet::new();

    let ip_re = Regex::new(
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
    )
    .unwrap();
    let url_re = Regex::new(r#"https?://[^\s"'<>]+"#).unwrap();
    let domain_re = Regex::new(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|ru|cn|xyz|top|info|biz|online)\b",
    )
    .unwrap();

    for s in strings {
        if let Some(m) = ip_re.find(s) {
            let ip = m.as_str().to_string();
            if !ip.starts_with("127.") && !ip.starts_with("0.") && seen.insert(ip.clone()) {
                iocs.push(format!("IP: {}", ip));
            }
        }
        if let Some(m) = url_re.find(s) {
            let url = m.as_str().to_string();
            if seen.insert(url.clone()) {
                iocs.push(format!("URL: {}", truncate(&url, 70)));
            }
        }
        if let Some(m) = domain_re.find(s) {
            let domain = m.as_str().to_string();
            if seen.insert(domain.clone()) {
                iocs.push(format!("Domain: {}", domain));
            }
        }

        let lower = s.to_lowercase();
        if lower.contains("hkey_") || lower.contains("software\\") {
            if seen.insert(s.clone()) {
                iocs.push(format!("Registry: {}", truncate(s, 60)));
            }
        }
        if lower.contains("appdata") || lower.contains("\\temp\\") || lower.contains("\\users\\") {
            if seen.insert(s.clone()) {
                iocs.push(format!("Path: {}", truncate(s, 60)));
            }
        }
    }

    iocs.into_iter().take(15).collect()
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max])
    }
}

fn print_report(report: &AnalysisReport) {
    let width = 66;

    println!("{}", "═".repeat(width).bright_cyan());
    println!(
        "{}",
        format!("{:^width$}", "MINTAKA v0.5", width = width)
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
    if let Some(ov) = report.overlay_size {
        println!("{}  {} bytes", "Overlay".bold().white(), ov);
    }
    println!();

    let (status_display, color) = match report.risk_level.as_str() {
        "HIGH RISK" => ("[HIGH RISK]".red().bold().to_string(), "red"),
        "NEEDS REVIEW" => ("[NEEDS REVIEW]".yellow().bold().to_string(), "yellow"),
        _ => ("[LOW]".green().bold().to_string(), "green"),
    };

    match color {
        "red" => {
            println!("{}", "┌────────────────────────────────────────────────────────────────┐".red());
            println!("{}  Status      : {:<49}{}", "│".red(), status_display, "│".red());
            println!("{}  Risk Score  : {:>3} / 100{:<41}{}", "│".red(), report.risk_score, "", "│".red());
            println!("{}", "└────────────────────────────────────────────────────────────────┘".red());
        }
        "yellow" => {
            println!("{}", "┌────────────────────────────────────────────────────────────────┐".yellow());
            println!("{}  Status      : {:<49}{}", "│".yellow(), status_display, "│".yellow());
            println!("{}  Risk Score  : {:>3} / 100{:<41}{}", "│".yellow(), report.risk_score, "", "│".yellow());
            println!("{}", "└────────────────────────────────────────────────────────────────┘".yellow());
        }
        _ => {
            println!("{}", "┌────────────────────────────────────────────────────────────────┐".green());
            println!("{}  Status      : {:<49}{}", "│".green(), status_display, "│".green());
            println!("{}  Risk Score  : {:>3} / 100{:<41}{}", "│".green(), report.risk_score, "", "│".green());
            println!("{}", "└────────────────────────────────────────────────────────────────┘".green());
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
        for imp in report.suspicious_imports.iter().take(12) {
            println!("  • {}", imp);
        }
        if report.suspicious_imports.len() > 12 {
            println!("  ... and {} more", report.suspicious_imports.len() - 12);
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
        for dep in report.dependencies.iter().take(10) {
            match &dep.version {
                Some(v) => println!("  • {:<26} {}", dep.name, v),
                None => println!("  • {}", dep.name),
            }
        }
        if report.dependencies.len() > 10 {
            println!("  ... and {} more", report.dependencies.len() - 10);
        }
    }
    println!();

    if !report.indicators.is_empty() {
        println!("{}", "Suspicious Indicators".bold().yellow());
        for ind in report.indicators.iter().take(12) {
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