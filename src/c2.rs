//! Fetch public C2 indicators over HTTPS, keep local cache, and perform offline lookups.
//! No firewall modifications, packet capture, or sample uploads in this version.
use crate::Result;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashSet;
use std::fs;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAX_RESPONSE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_PER_FEED: usize = 50_000;
const FEEDS: [(&str, &str); 2] = [
    ("feodo", "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"),
    ("c2intel_verified", "https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPC2s.csv"),
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Indicator {
    ip: IpAddr,
    source: String,
    collected_at: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct Cache {
    version: u32,
    saved_at: u64,
    entries: Vec<Indicator>,
}

impl Default for Cache {
    fn default() -> Self {
        Self { version: 1, saved_at: 0, entries: vec![] }
    }
}

fn epoch() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

fn read_cache(path: &Path) -> Result<Cache> {
    if !path.exists() { return Ok(Cache::default()); }
    let metadata = fs::metadata(path)?;
    if metadata.len() > MAX_RESPONSE_BYTES {
        return Err("Local cache exceeds safe size limit".into());
    }
    let cache: Cache = serde_json::from_slice(&fs::read(path)?)?;
    if cache.version != 1 || cache.entries.len() > 2 * MAX_PER_FEED {
        return Err("Unsupported or oversized C2 cache".into());
    }
    Ok(cache)
}

fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a,b,c,_] = ip.octets();
            !(ip.is_private() || ip.is_loopback() || ip.is_link_local()
                || ip.is_broadcast() || ip.is_multicast() || ip.is_unspecified()
                || ip.is_documentation() || a == 0 || a >= 240
                || (a == 100 && (64..=127).contains(&b))
                || (a == 198 && (b == 18 || b == 19))
                || (a == 192 && b == 0 && c == 0))
        }
        IpAddr::V6(ip) => !(ip.is_loopback() || ip.is_unspecified() || ip.is_multicast()
            || ip.is_unique_local() || ip.is_unicast_link_local()),
    }
}

fn parse_indicator(line: &str) -> Option<IpAddr> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') { return None; }
    let candidate = line.split(',').next()?.trim().trim_matches('"').trim();
    let addr = candidate.parse::<IpAddr>().ok()?;
    public_ip(addr).then_some(addr)
}

fn parse_feed(body: &str) -> Vec<IpAddr> {
    let mut seen = HashSet::new();
    body.lines()
        .filter_map(parse_indicator)
        .filter(|ip| seen.insert(*ip))
        .take(MAX_PER_FEED)
        .collect()
}

fn fetch(client: &reqwest::blocking::Client, url: &str) -> Result<String> {
    let response = client.get(url).send()?.error_for_status()?;
    let mut bytes = Vec::new();
    response.take(MAX_RESPONSE_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_RESPONSE_BYTES {
        return Err("Feed download exceeded maximum response size".into());
    }
    Ok(String::from_utf8(bytes)?)
}

fn write_cache(path: &Path, data: &Cache) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() { fs::create_dir_all(parent)?; }
    }
    // Stage a fully serialized cache before altering the previous version.
    let temp = path.with_extension("tmp");
    fs::write(&temp, serde_json::to_vec_pretty(data)?)?;
    if !path.exists() {
        fs::rename(temp, path)?;
        return Ok(());
    }
    // Windows cannot always rename over an open/existing destination.
    let old = path.with_extension("bak");
    if old.exists() {
        return Err("A previous cache backup exists: resolve it before updating".into());
    }
    fs::rename(path, &old)?;
    if let Err(err) = fs::rename(&temp, path) {
        let _ = fs::rename(&old, path);
        return Err(err.into());
    }
    let _ = fs::remove_file(old);
    Ok(())
}

pub fn update(path: &Path) -> Result<()> {
    let mut cache = read_cache(path)?;
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(15))
        .user_agent("AegisGuard/0.1 (defensive IOC consumer)")
        .build()?;
    let mut updated_sources = 0usize;
    for (source, url) in FEEDS {
        match fetch(&client, url) {
            Ok(body) => {
                let ips = parse_feed(&body);
                // Feodo may legitimately publish an empty block list.
                // An unexpected empty CSV is more likely a format change.
                if source != "feodo" && ips.is_empty() {
                    eprintln!("{source}: zero valid IPs; retaining prior cache");
                    continue;
                }
                cache.entries.retain(|entry| entry.source != source);
                let now = epoch();
                cache.entries.extend(ips.iter().map(|&ip| Indicator {
                    ip,
                    source: source.to_owned(),
                    collected_at: now,
                }));
                eprintln!("{source}: loaded {} indicators", ips.len());
                updated_sources += 1;
            }
            Err(error) => eprintln!("{source}: update failed ({error}); preserving previous indicators"),
        }
    }
    if updated_sources == 0 {
        return Err("No C2 feed updated successfully; previous cache is unchanged".into());
    }
    cache.saved_at = epoch();
    write_cache(path, &cache)?;
    println!("{}", serde_json::to_string(&json!({
        "status": "updated",
        "sources_updated": updated_sources,
        "indicators": cache.entries.len(),
        "cache": path.display().to_string(),
    }))?);
    Ok(())
}

pub fn check(path: &Path, ip: IpAddr) -> Result<()> {
    let cache = read_cache(path)?;
    let matched: Vec<&Indicator> = cache.entries.iter().filter(|i| i.ip == ip).collect();
    println!("{}", serde_json::to_string(&json!({
        "ip": ip.to_string(),
        "matched": !matched.is_empty(),
        "sources": matched.iter().map(|i| i.source.as_str()).collect::<Vec<_>>(),
        "cache_updated_at_unix": cache.saved_at,
        "caution": "IOC match is not proof of infection; absence is not proof of safety",
    }))?);
    Ok(())
}

pub fn status(path: &Path) -> Result<()> {
    let cache = read_cache(path)?;
    let age = epoch().saturating_sub(cache.saved_at);
    println!("{}", serde_json::to_string(&json!({
        "cache": path.display().to_string(),
        "indicators": cache.entries.len(),
        "saved_at_unix": cache.saved_at,
        "age_hours": if cache.saved_at == 0 { serde_json::Value::Null }
                     else { json!(age / 3600) },
        "stale": cache.saved_at == 0 || age > 48 * 3600,
    }))?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ignores_nonpublic_and_headers() {
        assert!(parse_indicator("# comment").is_none());
        assert!(parse_indicator("192.168.1.1").is_none());
        assert!(parse_indicator("127.0.0.1").is_none());
        assert!(parse_indicator("ip,port").is_none());
    }
    #[test]
    fn accepts_and_deduplicates_feodo_and_csv_ip_format() {
        let addresses = parse_feed("1.2.3.4\n1.2.3.4\n5.6.7.8,443\n# comment");
        assert_eq!(addresses, vec![Ipv4Addr::new(1,2,3,4).into(), Ipv4Addr::new(5,6,7,8).into()]);
    }
    #[test]
    fn default_cache_does_not_claim_freshness() {
        assert_eq!(Cache::default().saved_at, 0);
    }
}
