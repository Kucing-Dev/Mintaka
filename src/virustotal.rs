use crate::types::{VtIpReputation, VtProcessReport};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct VtCacheData {
    pub file_cache: HashMap<String, (u32, u32)>, // hash -> (positives, total)
    pub ip_cache: HashMap<String, VtIpReputation>, // ip -> reputation
}

pub struct VtClient {
    api_key: String,
    last_request: Arc<Mutex<Option<Instant>>>,
    min_interval: Duration,
    cache: Arc<Mutex<VtCacheData>>,
    pending_requests: Arc<Mutex<HashSet<String>>>,
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
            last_request: Arc::new(Mutex::new(None)),
            min_interval: Duration::from_secs(15), // Rate-limit for free tier (4 req/min)
            cache: Arc::new(Mutex::new(cache_data)),
            pending_requests: Arc::new(Mutex::new(HashSet::new())),
            cache_path,
        }
    }

    pub fn check_file_hash(&self, sha256: &str) -> Option<(u32, u32)> {
        // Return from cache immediately
        {
            let guard = self.cache.lock().unwrap();
            if let Some(hit) = guard.file_cache.get(sha256) {
                return Some(*hit);
            }
        }

        // Queue background fetch if not already pending
        {
            let mut pending = self.pending_requests.lock().unwrap();
            if !pending.insert(sha256.to_string()) {
                return None; // Already queued
            }
        }

        let api_key = self.api_key.clone();
        let hash_owned = sha256.to_string();
        let cache = Arc::clone(&self.cache);
        let last_request = Arc::clone(&self.last_request);
        let min_interval = self.min_interval;
        let cache_path = self.cache_path.clone();

        thread::spawn(move || {
            // Throttle rate limit in background thread
            {
                let mut last_req = last_request.lock().unwrap();
                if let Some(instant) = *last_req {
                    let elapsed = instant.elapsed();
                    if elapsed < min_interval {
                        thread::sleep(min_interval - elapsed);
                    }
                }
                *last_req = Some(Instant::now());
            }

            let url = format!("https://www.virustotal.com/api/v3/files/{}", hash_owned);
            if let Ok(resp) = ureq::get(&url).set("x-api-key", &api_key).call() {
                if let Ok(json) = resp.into_json::<serde_json::Value>() {
                    let stats = &json["data"]["attributes"]["last_analysis_stats"];
                    let malicious = stats["malicious"].as_u64().unwrap_or(0) as u32;
                    let harmless = stats["harmless"].as_u64().unwrap_or(0) as u32;
                    let suspicious = stats["suspicious"].as_u64().unwrap_or(0) as u32;
                    let undetected = stats["undetected"].as_u64().unwrap_or(0) as u32;

                    let total = malicious + harmless + suspicious + undetected;
                    let positives = malicious + suspicious;

                    let res = (positives, total);
                    {
                        let mut guard = cache.lock().unwrap();
                        guard.file_cache.insert(hash_owned, res);
                    }

                    if let Some(ref path) = cache_path {
                        if let Ok(guard) = cache.lock() {
                            if let Ok(json_str) = serde_json::to_string_pretty(&*guard) {
                                let _ = fs::write(path, json_str);
                            }
                        }
                    }
                }
            }
        });

        None
    }

    pub fn check_ip(&self, ip: &str) -> Option<VtIpReputation> {
        if ip.starts_with("127.") || ip.starts_with("10.") || ip.starts_with("192.168.") || ip == "0.0.0.0" {
            return None;
        }

        // Return from cache immediately
        {
            let guard = self.cache.lock().unwrap();
            if let Some(hit) = guard.ip_cache.get(ip) {
                return Some(hit.clone());
            }
        }

        // Queue background fetch if not already pending
        {
            let mut pending = self.pending_requests.lock().unwrap();
            if !pending.insert(ip.to_string()) {
                return None; // Already queued
            }
        }

        let api_key = self.api_key.clone();
        let ip_owned = ip.to_string();
        let cache = Arc::clone(&self.cache);
        let last_request = Arc::clone(&self.last_request);
        let min_interval = self.min_interval;
        let cache_path = self.cache_path.clone();

        thread::spawn(move || {
            // Throttle rate limit in background thread
            {
                let mut last_req = last_request.lock().unwrap();
                if let Some(instant) = *last_req {
                    let elapsed = instant.elapsed();
                    if elapsed < min_interval {
                        thread::sleep(min_interval - elapsed);
                    }
                }
                *last_req = Some(Instant::now());
            }

            let url = format!("https://www.virustotal.com/api/v3/ip_addresses/{}", ip_owned);
            if let Ok(resp) = ureq::get(&url).set("x-api-key", &api_key).call() {
                if let Ok(json) = resp.into_json::<serde_json::Value>() {
                    let attrs = &json["data"]["attributes"];
                    let stats = &attrs["last_analysis_stats"];
                    let malicious = stats["malicious"].as_u64().unwrap_or(0) as u32;
                    let harmless = stats["harmless"].as_u64().unwrap_or(0) as u32;
                    let country = attrs["country"].as_str().map(|s| s.to_string());
                    let owner = attrs["as_owner"].as_str().map(|s| s.to_string());

                    let rep = VtIpReputation {
                        ip: ip_owned.clone(),
                        malicious_votes: malicious,
                        harmless_votes: harmless,
                        country,
                        owner,
                    };

                    {
                        let mut guard = cache.lock().unwrap();
                        guard.ip_cache.insert(ip_owned, rep);
                    }

                    if let Some(ref path) = cache_path {
                        if let Ok(guard) = cache.lock() {
                            if let Ok(json_str) = serde_json::to_string_pretty(&*guard) {
                                let _ = fs::write(path, json_str);
                            }
                        }
                    }
                }
            }
        });

        None
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
