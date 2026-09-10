use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AnalysisReport {
    pub file: String,
    pub file_size: u64,
    pub sha256: String,
    pub format: String,
    pub architecture: Option<String>,
    pub is_rust: bool,
    pub rustc_version: Option<String>,
    pub rustc_commit_hash: Option<String>,
    pub dependencies: Vec<CrateInfo>,
    pub risk_score: u32,
    pub risk_level: String,
    pub indicators: Vec<String>,
    pub notes: Vec<String>,
    pub file_entropy: f64,
    pub section_count: usize,
    pub compile_timestamp: Option<String>,
    pub entry_point: Option<String>,
    pub packer_hint: Option<String>,
    pub overlay_size: Option<usize>,
    pub suspicious_imports: Vec<String>,
    pub sections: Vec<SectionInfo>,
    pub iocs: Vec<String>,
    pub has_resources: bool,
    pub resource_size: Option<u32>,
    pub is_signed: bool,
    pub signature_publisher: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SectionInfo {
    pub name: String,
    pub size: usize,
    pub entropy: f64,
    pub characteristics: String,
    pub suspicious: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct CrateInfo {
    pub name: String,
    pub version: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LoadedModule {
    pub name: String,
    pub path: String,
    pub sha256: Option<String>,
    pub is_suspicious_location: bool,
    pub is_signed: bool,
    pub signature_publisher: Option<String>,
    pub is_unsigned_in_system_dir: bool,
    pub vt_malicious_hits: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NetworkConnection {
    pub local_addr: String,
    pub remote_addr: String,
    pub remote_ip: String,
    pub remote_port: u16,
    pub remote_hostname: Option<String>,
    pub protocol: String,
    pub state: String,
    pub vt_reputation: Option<VtIpReputation>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VtIpReputation {
    pub ip: String,
    pub malicious_votes: u32,
    pub harmless_votes: u32,
    pub country: Option<String>,
    pub owner: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VtProcessReport {
    pub exe_positives: u32,
    pub exe_total: u32,
    pub malicious_dll_count: u32,
    pub malicious_ip_count: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LiveProcessReport {
    pub pid: u32,
    pub name: String,
    pub exe_path: Option<String>,
    pub cmdline: Vec<String>,
    pub parent_pid: Option<u32>,
    pub parent_name: Option<String>,
    pub loaded_dlls: Vec<LoadedModule>,
    pub network_connections: Vec<NetworkConnection>,
    pub static_report: Option<AnalysisReport>,
    pub vt_report: Option<VtProcessReport>,
    pub risk_score: u32,
    pub risk_level: String,
    pub indicators: Vec<String>,
}
