use crate::types::{
    AnalysisReport, LoadedModule, NetworkConnection, VtProcessReport,
};

pub fn calculate_live_risk_score(
    name: &str,
    exe_path: Option<&str>,
    cmdline: &[String],
    parent_name: Option<&str>,
    loaded_dlls: &[LoadedModule],
    network_connections: &[NetworkConnection],
    static_report: Option<&AnalysisReport>,
    vt_report: Option<&VtProcessReport>,
) -> (u32, String, Vec<String>) {
    let mut score: u32 = 0;
    let mut indicators = Vec::new();

    // 1. Static score baseline (max 40 pts)
    if let Some(st) = static_report {
        let static_contrib = (st.risk_score as f64 * 0.4) as u32;
        score += static_contrib;
        if st.risk_score >= 70 {
            indicators.push(format!("High static risk score ({})", st.risk_score));
        }
        for ind in &st.indicators {
            if !indicators.contains(ind) {
                indicators.push(ind.clone());
            }
        }
    }

    // 2. Process path & Living-off-the-Land (LOLBin) anomalies
    let lower_name = name.to_lowercase();

    if let Some(path) = exe_path {
        let lower_path = path.to_lowercase();
        if lower_path.contains("/tmp/")
            || lower_path.contains("/var/tmp/")
            || lower_path.contains("/dev/shm/")
            || lower_path.contains("\\temp\\")
            || lower_path.contains("\\appdata\\")
            || lower_path.contains("\\users\\public\\")
        {
            score += 25;
            indicators.push(format!("Process running from temporary/user-writable directory: {}", path));
        }

        // Masquerading check (e.g. svchost.exe outside System32)
        if (lower_name == "svchost.exe" || lower_name == "lsass.exe" || lower_name == "csrss.exe")
            && !lower_path.contains("system32")
        {
            score += 35;
            indicators.push(format!("System process masquerading outside System32: {}", path));
        }
    }

    // LOLBin parent-child anomalies
    let lolbins = [
        "powershell.exe",
        "cmd.exe",
        "wmic.exe",
        "mshta.exe",
        "rundll32.exe",
        "regsvr32.exe",
        "certutil.exe",
        "bitsadmin.exe",
        "bash",
        "sh",
    ];

    if lolbins.contains(&lower_name.as_str()) {
        if let Some(parent) = parent_name {
            let p_lower = parent.to_lowercase();
            if p_lower.contains("winword")
                || p_lower.contains("excel")
                || p_lower.contains("outlook")
                || p_lower.contains("powerpnt")
                || p_lower.contains("httpd")
                || p_lower.contains("nginx")
            {
                score += 30;
                indicators.push(format!(
                    "LOLBin process '{}' spawned by unexpected parent '{}'",
                    name, parent
                ));
            }
        }
    }

    // Command-line indicators
    let full_cmd = cmdline.join(" ").to_lowercase();
    if full_cmd.contains("-enc")
        || full_cmd.contains("-encodedcommand")
        || full_cmd.contains("downloadstring")
        || full_cmd.contains("curl ")
        || full_cmd.contains("wget ")
        || full_cmd.contains("base64")
    {
        score += 15;
        indicators.push("Suspicious command-line arguments (download/encoded payload)".to_string());
    }

    // 3. Loaded DLL / Module anomalies & Authenticode verification
    let mut susp_dll_count = 0;
    let mut unsigned_sys_dll_count = 0;

    for dll in loaded_dlls {
        if dll.is_suspicious_location {
            susp_dll_count += 1;
        }
        if dll.is_unsigned_in_system_dir {
            unsigned_sys_dll_count += 1;
            indicators.push(format!(
                "Un-signed DLL loaded in system directory: {}",
                dll.name
            ));
        }
    }
    if susp_dll_count > 0 {
        score += (susp_dll_count * 15).min(30);
        indicators.push(format!(
            "{} loaded module(s) from suspicious directory",
            susp_dll_count
        ));
    }
    if unsigned_sys_dll_count > 0 {
        score += (unsigned_sys_dll_count * 20).min(40);
    }

    // 4. Network socket anomalies
    let mut active_ext_conns = 0;
    let suspicious_ports = [4444, 1337, 6667, 8088, 31337, 5555, 8443, 9001];

    for conn in network_connections {
        if conn.remote_ip != "-" && !conn.remote_ip.starts_with("127.") && conn.remote_ip != "0.0.0.0" {
            active_ext_conns += 1;

            if suspicious_ports.contains(&conn.remote_port) {
                score += 20;
                indicators.push(format!(
                    "Active connection to suspicious port: {}:{}",
                    conn.remote_ip, conn.remote_port
                ));
            }

            if let Some(ref rep) = conn.vt_reputation {
                if rep.malicious_votes > 0 {
                    score += 30;
                    indicators.push(format!(
                        "Connection to VirusTotal malicious IP: {} ({} flags)",
                        conn.remote_ip, rep.malicious_votes
                    ));
                }
            }
        }
    }

    if active_ext_conns > 0 {
        score += (active_ext_conns * 3).min(15);
    }

    // 5. VirusTotal execution statistics
    if let Some(vt) = vt_report {
        if vt.exe_positives > 0 {
            let vt_score = (vt.exe_positives * 5).min(50);
            score += vt_score;
            indicators.push(format!(
                "Executable flagged by VirusTotal: {}/{} engines",
                vt.exe_positives, vt.exe_total
            ));
        }

        if vt.malicious_dll_count > 0 {
            score += (vt.malicious_dll_count * 20).min(40);
            indicators.push(format!(
                "{} loaded DLL(s) flagged by VirusTotal",
                vt.malicious_dll_count
            ));
        }
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

    (score, risk_level, indicators)
}
