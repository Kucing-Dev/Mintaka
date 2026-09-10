use crate::risk::calculate_live_risk_score;
use crate::static_analysis::analyze;
use crate::types::{AnalysisReport, LoadedModule, LiveProcessReport, NetworkConnection};
use crate::virustotal::VtClient;
use anyhow::Result;
use netstat2::{get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use sysinfo::{Pid, System};

use std::net::IpAddr;
use std::str::FromStr;

// Thread-safe in-memory cache for static analysis, hashes & reverse DNS
lazy_static::lazy_static! {
    static ref STATIC_CACHE: Mutex<HashMap<PathBuf, AnalysisReport>> = Mutex::new(HashMap::new());
    static ref HASH_CACHE: Mutex<HashMap<PathBuf, String>> = Mutex::new(HashMap::new());
    static ref DNS_CACHE: Mutex<HashMap<String, Option<String>>> = Mutex::new(HashMap::new());
}

pub fn scan_live_processes(
    target_pid: Option<u32>,
    target_name: Option<&str>,
    vt_client: Option<&VtClient>,
) -> Result<Vec<LiveProcessReport>> {
    let mut sys = System::new();
    sys.refresh_processes();

    // Map PID -> Vec<NetworkConnection>
    let connections_by_pid = get_network_connections_by_pid();

    let mut reports = Vec::new();

    for (pid, process) in sys.processes() {
        let pid_u32 = pid.as_u32();

        if let Some(t_pid) = target_pid {
            if pid_u32 != t_pid {
                continue;
            }
        }

        let name = process.name().to_string();
        if let Some(t_name) = target_name {
            if !name.to_lowercase().contains(&t_name.to_lowercase()) {
                continue;
            }
        }

        let exe_path = process.exe().map(|p| p.display().to_string());
        let cmdline: Vec<String> = process.cmd().iter().map(|s| s.to_string()).collect();

        let parent_pid = process.parent().map(|p| p.as_u32());
        let parent_name = parent_pid.and_then(|ppid| {
            sys.process(Pid::from_u32(ppid)).map(|p| p.name().to_string())
        });

        // 1. Get Loaded Modules / Shared Objects / DLLs
        let loaded_dlls = get_loaded_modules(pid_u32, process.exe());

        // 2. Get Network Connections for this PID
        let mut net_conns = connections_by_pid.get(&pid_u32).cloned().unwrap_or_default();

        // Check VT IP reputation if client is provided
        if let Some(vt) = vt_client {
            for conn in &mut net_conns {
                if let Some(rep) = vt.check_ip(&conn.remote_ip) {
                    conn.vt_reputation = Some(rep);
                }
            }
        }

        // 3. Fast Static Analysis (with in-memory cache)
        let static_report = if let Some(ref path_str) = exe_path {
            let p = PathBuf::from(path_str);
            if p.is_file() {
                get_cached_static_analysis(&p)
            } else {
                None
            }
        } else {
            None
        };

        // 4. VirusTotal analysis for exe, DLLs, and remote IPs
        let exe_sha256 = static_report.as_ref().map(|r| r.sha256.as_str());
        let dll_hashes: Vec<String> = loaded_dlls.iter().filter_map(|d| d.sha256.clone()).collect();
        let remote_ips: Vec<String> = net_conns.iter().map(|c| c.remote_ip.clone()).collect();

        let vt_report = vt_client.map(|vt| vt.analyze_process_vt(exe_sha256, &dll_hashes, &remote_ips));

        // 5. Dynamic Risk Scoring
        let (risk_score, risk_level, indicators) = calculate_live_risk_score(
            &name,
            exe_path.as_deref(),
            &cmdline,
            parent_name.as_deref(),
            &loaded_dlls,
            &net_conns,
            static_report.as_ref(),
            vt_report.as_ref(),
        );

        reports.push(LiveProcessReport {
            pid: pid_u32,
            name,
            exe_path,
            cmdline,
            parent_pid,
            parent_name,
            loaded_dlls,
            network_connections: net_conns,
            static_report,
            vt_report,
            risk_score,
            risk_level,
            indicators,
            tree_prefix: String::new(),
            depth: 0,
        });
    }

    // Build process tree hierarchy & prefixes
    build_process_tree_hierarchy(&mut reports);

    reports.sort_by(|a, b| b.risk_score.cmp(&a.risk_score));
    Ok(reports)
}

fn build_process_tree_hierarchy(reports: &mut Vec<LiveProcessReport>) {
    let pids: HashSet<u32> = reports.iter().map(|r| r.pid).collect();
    let mut children_map: HashMap<Option<u32>, Vec<u32>> = HashMap::new();

    for r in reports.iter() {
        let parent = match r.parent_pid {
            Some(ppid) if pids.contains(&ppid) => Some(ppid),
            _ => None,
        };
        children_map.entry(parent).or_default().push(r.pid);
    }

    let mut report_map: HashMap<u32, LiveProcessReport> = reports.drain(..).map(|r| (r.pid, r)).collect();
    let mut ordered = Vec::new();

    if let Some(roots) = children_map.get(&None) {
        let root_pids = roots.clone();
        for (i, root_pid) in root_pids.iter().enumerate() {
            let is_last = i == root_pids.len() - 1;
            traverse_tree(
                *root_pid,
                "",
                is_last,
                0,
                &children_map,
                &mut report_map,
                &mut ordered,
            );
        }
    }

    // Drain remaining orphans
    for (_, r) in report_map {
        ordered.push(r);
    }

    *reports = ordered;
}

fn traverse_tree(
    pid: u32,
    prefix: &str,
    is_last: bool,
    depth: usize,
    children_map: &HashMap<Option<u32>, Vec<u32>>,
    report_map: &mut HashMap<u32, LiveProcessReport>,
    ordered: &mut Vec<LiveProcessReport>,
) {
    if let Some(mut report) = report_map.remove(&pid) {
        let current_prefix = if depth == 0 {
            "".to_string()
        } else if is_last {
            format!("{}└── ", prefix)
        } else {
            format!("{}├── ", prefix)
        };

        report.tree_prefix = current_prefix;
        report.depth = depth;
        ordered.push(report);

        if let Some(children) = children_map.get(&Some(pid)) {
            let child_pids = children.clone();
            let child_prefix = if depth == 0 {
                "".to_string()
            } else if is_last {
                format!("{}    ", prefix)
            } else {
                format!("{}│   ", prefix)
            };

            for (i, child_pid) in child_pids.iter().enumerate() {
                let last_child = i == child_pids.len() - 1;
                traverse_tree(
                    *child_pid,
                    &child_prefix,
                    last_child,
                    depth + 1,
                    children_map,
                    report_map,
                    ordered,
                );
            }
        }
    }
}

fn get_cached_static_analysis(path: &Path) -> Option<AnalysisReport> {
    {
        let cache = STATIC_CACHE.lock().unwrap();
        if let Some(report) = cache.get(path) {
            return Some(report.clone());
        }
    }

    if let Ok(metadata) = fs::metadata(path) {
        // Skip huge binaries (> 50MB) during live scan to remain fast
        if metadata.len() > 50_000_000 {
            return None;
        }
    }

    if let Ok(data) = fs::read(path) {
        if let Ok(report) = analyze(path, &data) {
            let mut cache = STATIC_CACHE.lock().unwrap();
            cache.insert(path.to_path_buf(), report.clone());
            return Some(report);
        }
    }

    None
}

fn get_cached_sha256(path: &Path) -> Option<String> {
    {
        let cache = HASH_CACHE.lock().unwrap();
        if let Some(hash) = cache.get(path) {
            return Some(hash.clone());
        }
    }

    if let Ok(data) = fs::read(path) {
        let hash = hex::encode(Sha256::digest(&data));
        let mut cache = HASH_CACHE.lock().unwrap();
        cache.insert(path.to_path_buf(), hash.clone());
        Some(hash)
    } else {
        None
    }
}

fn get_loaded_modules(pid: u32, exe_path: Option<&Path>) -> Vec<LoadedModule> {
    let mut modules = Vec::new();
    let mut seen_paths = HashSet::new();

    let exe_canonical = exe_path.and_then(|p| fs::canonicalize(p).ok());

    // Linux procfs maps reader
    let maps_path = format!("/proc/{}/maps", pid);
    if let Ok(file) = File::open(&maps_path) {
        let reader = BufReader::new(file);
        for line in reader.lines().flatten() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 6 {
                let path_str = parts[5];
                if path_str.starts_with('/') && (path_str.contains(".so") || path_str.contains(".dll")) {
                    let path = PathBuf::from(path_str);

                    // Skip the executable itself
                    if let Some(ref exe_c) = exe_canonical {
                        if let Ok(path_c) = fs::canonicalize(&path) {
                            if &path_c == exe_c {
                                continue;
                            }
                        }
                    }

                    if seen_paths.insert(path_str.to_string()) {
                        let name = path
                            .file_name()
                            .map(|s| s.to_string_lossy().to_string())
                            .unwrap_or_else(|| path_str.to_string());

                        let is_suspicious_location = is_path_suspicious(path_str);
                        let is_sys_lib = is_standard_system_lib(path_str);

                        // Signature verification
                        let (is_signed, signature_publisher) = check_authenticode_signature(&path);
                        let is_unsigned_in_system_dir = is_sys_lib && !is_signed;

                        // Only compute hash for suspicious locations, unsigned DLLs, or non-standard system libraries
                        let sha256 = if is_suspicious_location || is_unsigned_in_system_dir || !is_sys_lib {
                            get_cached_sha256(&path)
                        } else {
                            None
                        };

                        modules.push(LoadedModule {
                            name,
                            path: path_str.to_string(),
                            sha256,
                            is_suspicious_location,
                            is_signed,
                            signature_publisher,
                            is_unsigned_in_system_dir,
                            vt_malicious_hits: None,
                        });
                    }
                }
            }
        }
    }

    modules
}

fn check_authenticode_signature(path: &Path) -> (bool, Option<String>) {
    if let Ok(data) = fs::read(path) {
        if let Ok(goblin::Object::PE(pe)) = goblin::Object::parse(&data) {
            if let Some(opt) = pe.header.optional_header {
                if let Some(Some((_, sec_dir))) = opt.data_directories.data_directories.get(4) {
                    if sec_dir.virtual_address > 0 && sec_dir.size > 0 {
                        let offset = sec_dir.virtual_address as usize;
                        let size = sec_dir.size as usize;
                        if offset + size <= data.len() {
                            let cert_str = String::from_utf8_lossy(&data[offset..offset + size]);
                            if cert_str.contains("Microsoft Corporation") {
                                return (true, Some("Microsoft Corporation".to_string()));
                            } else if cert_str.contains("Google LLC") {
                                return (true, Some("Google LLC".to_string()));
                            } else if cert_str.contains("Apple Inc.") {
                                return (true, Some("Apple Inc.".to_string()));
                            }
                        }
                        return (true, Some("Signed PE".to_string()));
                    }
                }
            }
        }
    }
    (false, None)
}

fn is_standard_system_lib(path: &str) -> bool {
    path.starts_with("/usr/lib/")
        || path.starts_with("/lib/")
        || path.starts_with("/lib64/")
        || path.to_lowercase().contains("c:\\windows\\system32\\")
}

fn is_path_suspicious(path: &str) -> bool {
    let lower = path.to_lowercase();
    lower.contains("/tmp/")
        || lower.contains("/var/tmp/")
        || lower.contains("\\temp\\")
        || lower.contains("\\appdata\\")
        || lower.contains("\\users\\public\\")
        || lower.contains("/dev/shm/")
}

fn get_cached_dns(ip_str: &str) -> Option<String> {
    if ip_str == "-" || ip_str.starts_with("127.") || ip_str == "0.0.0.0" {
        return None;
    }

    {
        let cache = DNS_CACHE.lock().unwrap();
        if let Some(res) = cache.get(ip_str) {
            return res.clone();
        }
    }

    let hostname = if let Ok(ip) = IpAddr::from_str(ip_str) {
        dns_lookup::lookup_addr(&ip).ok()
    } else {
        None
    };

    let mut cache = DNS_CACHE.lock().unwrap();
    cache.insert(ip_str.to_string(), hostname.clone());
    hostname
}

fn get_network_connections_by_pid() -> HashMap<u32, Vec<NetworkConnection>> {
    let mut map: HashMap<u32, Vec<NetworkConnection>> = HashMap::new();

    let af_flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
    let proto_flags = ProtocolFlags::TCP | ProtocolFlags::UDP;

    if let Ok(sockets) = get_sockets_info(af_flags, proto_flags) {
        for socket in sockets {
            for pid in socket.associated_pids {
                let (protocol, local_addr, remote_addr, remote_ip, remote_port, state) =
                    match socket.protocol_socket_info {
                        ProtocolSocketInfo::Tcp(ref tcp_info) => (
                            "TCP".to_string(),
                            format!("{}:{}", tcp_info.local_addr, tcp_info.local_port),
                            format!("{}:{}", tcp_info.remote_addr, tcp_info.remote_port),
                            tcp_info.remote_addr.to_string(),
                            tcp_info.remote_port,
                            format!("{:?}", tcp_info.state),
                        ),
                        ProtocolSocketInfo::Udp(ref udp_info) => (
                            "UDP".to_string(),
                            format!("{}:{}", udp_info.local_addr, udp_info.local_port),
                            "-".to_string(),
                            "-".to_string(),
                            0,
                            "ACTIVE".to_string(),
                        ),
                    };

                let remote_hostname = get_cached_dns(&remote_ip);

                map.entry(pid).or_default().push(NetworkConnection {
                    local_addr,
                    remote_addr,
                    remote_ip,
                    remote_port,
                    remote_hostname,
                    protocol,
                    state,
                    vt_reputation: None,
                });
            }
        }
    }

    map
}
