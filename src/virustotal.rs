use crate::types::{VtIpReputation, VtProcessReport};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct VtCacheData {
    pub file_cache: HashMap<String, (u32, u32)>, // hash -> (positives, total)
    pub ip_cache: HashMap<String, VtIpReputation>, // ip -> reputation
}

pub struct VtClient {
    api_key: String,
    last_request: Mutex<Option<Instant>>,
    min_interval: Duration,
    cache: Mutex<VtCacheData>,
    cache_path: Option<PathBuf>,
}

impl VtClient {
    pub fn new(api_key: String) -> Self {
        let cache_path = dirs::cache_dir().map(|mut p| {
            p.push("mintaka");
            let _ = fs::create_dir_all(&p);
            p.push("vt_cache.json");
            p
        });

        let cache_data = if let Some(ref path) = cache_path {
            if path.exists() {
                fs::read_to_string(path)
                    .ok()
                    .and_then(|s| serde_json::from_str(&s).ok())
                    .unwrap_or_default()
            } else {
                VtCacheData::default()
            }
        } else {
            VtCacheData::default()
        };

        Self {
            api_key,
            last_request: Mutex::new(None),
            min_interval: Duration::from_secs(15), // Rate-limit for free tier (4 req/min)
            cache: Mutex::new(cache_data),
            cache_path,
        }
    }

    fn save_cache(&self) {
        if let Some(ref path) = self.cache_path {
            if let Ok(guard) = self.cache.lock() {
                if let Ok(json) = serde_json::to_string_pretty(&*guard) {
                    let _ = fs::write(path, json);
                }
            }
        }
    }

    fn throttle(&self) {
        let mut last_req = self.last_request.lock().unwrap();
        if let Some(instant) = *last_req {
            let elapsed = instant.elapsed();
            if elapsed < self.min_interval {
                thread::sleep(self.min_interval - elapsed);
            }
        }
        *last_req = Some(Instant::now());
    }

    pub fn check_file_hash(&self, sha256: &str) -> Option<(u32, u32)> {
        // Check cache first
        {
            let guard = self.cache.lock().unwrap();
            if let Some(hit) = guard.file_cache.get(sha256) {
                return Some(*hit);
            }
        }

        self.throttle();

        let url = format!("https://www.virustotal.com/api/v3/files/{}", sha256);
        let resp = ureq::get(&url)
            .set("x-api-key", &self.api_key)
            .call();

        match resp {
            Ok(r) => {
                if let Ok(json) = r.into_json::<serde_json::Value>() {
                    let stats = &json["data"]["attributes"]["last_analysis_stats"];
                    let malicious = stats["malicious"].as_u64().unwrap_or(0) as u32;
                    let harmless = stats["harmless"].as_u64().unwrap_or(0) as u32;
                    let suspicious = stats["suspicious"].as_u64().unwrap_or(0) as u32;
                    let undetected = stats["undetected"].as_u64().unwrap_or(0) as u32;

                    let total = malicious + harmless + suspicious + undetected;
                    let positives = malicious + suspicious;

                    let res = (positives, total);
                    {
                        let mut guard = self.cache.lock().unwrap();
                        guard.file_cache.insert(sha256.to_string(), res);
                    }
                    self.save_cache();
                    Some(res)
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    }

    pub fn check_ip(&self, ip: &str) -> Option<VtIpReputation> {
        // Skip local or private IPs
        if ip.starts_with("127.") || ip.starts_with("10.") || ip.starts_with("192.168.") || ip == "0.0.0.0" {
            return None;
        }

        // Check cache first
        {
            let guard = self.cache.lock().unwrap();
            if let Some(hit) = guard.ip_cache.get(ip) {
                return Some(hit.clone());
            }
        }

        self.throttle();

        let url = format!("https://www.virustotal.com/api/v3/ip_addresses/{}", ip);
        let resp = ureq::get(&url)
            .set("x-api-key", &self.api_key)
            .call();

        match resp {
            Ok(r) => {
                if let Ok(json) = r.into_json::<serde_json::Value>() {
                    let attrs = &json["data"]["attributes"];
                    let stats = &attrs["last_analysis_stats"];
                    let malicious = stats["malicious"].as_u64().unwrap_or(0) as u32;
                    let harmless = stats["harmless"].as_u64().unwrap_or(0) as u32;
                    let country = attrs["country"].as_str().map(|s| s.to_string());
                    let owner = attrs["as_owner"].as_str().map(|s| s.to_string());

                    let rep = VtIpReputation {
                        ip: ip.to_string(),
                        malicious_votes: malicious,
                        harmless_votes: harmless,
                        country,
                        owner,
                    };

                    {
                        let mut guard = self.cache.lock().unwrap();
                        guard.ip_cache.insert(ip.to_string(), rep.clone());
                    }
                    self.save_cache();
                    Some(rep)
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    }

    pub fn analyze_process_vt(
        &self,
        exe_sha256: Option<&str>,
        dll_sha256s: &[String],
        remote_ips: &[String],
    ) -> VtProcessReport {
        let mut exe_positives = 0;
        let mut exe_total = 0;
        let mut malicious_dll_count = 0;
        let mut malicious_ip_count = 0;

        if let Some(hash) = exe_sha256 {
            if let Some((pos, tot)) = self.check_file_hash(hash) {
                exe_positives = pos;
                exe_total = tot;
            }
        }

        for dll_hash in dll_sha256s {
            if let Some((pos, _)) = self.check_file_hash(dll_hash) {
                if pos > 0 {
                    malicious_dll_count += 1;
                }
            }
        }

        for ip in remote_ips {
            if let Some(ip_rep) = self.check_ip(ip) {
                if ip_rep.malicious_votes > 0 {
                    malicious_ip_count += 1;
                }
            }
        }

        VtProcessReport {
            exe_positives,
            exe_total,
            malicious_dll_count,
            malicious_ip_count,
        }
    }
}
