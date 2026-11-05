//! Read-only defensive C2 indicator feeds with independent freshness per source.
//! Updates never alter firewall settings or upload local files.
use crate::Result;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io::Read;
use std::net::IpAddr;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const CACHE_VERSION: u32 = 2;
const MAX_RESPONSE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_PER_FEED: usize = 50_000;
const FEED_TTL_SECONDS: u64 = 48 * 3600;
const FEEDS: [(&str, &str); 2] = [
    (
        "feodo",
        "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
    ),
    (
        "c2intel_verified",
        "https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPC2s.csv",
    ),
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Indicator {
    ip: IpAddr,
    source: String,
    collected_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FeedState {
    source: String,
    last_success_at: u64,
    ttl_seconds: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct Cache {
    version: u32,
    /// Last *any* successful update. Never use this to judge a feed's freshness.
    saved_at: u64,
    sources: Vec<FeedState>,
    entries: Vec<Indicator>,
}

#[derive(Deserialize)]
struct LegacyCache {
    version: u32,
    saved_at: u64,
    entries: Vec<Indicator>,
}

impl Default for Cache {
    fn default() -> Self {
        Self {
            version: CACHE_VERSION,
            saved_at: 0,
            sources: Vec::new(),
            entries: Vec::new(),
        }
    }
}

fn epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn recognized(source: &str) -> bool {
    FEEDS.iter().any(|(name, _)| *name == source)
}

fn is_fresh(state: Option<&FeedState>, now: u64) -> bool {
    let Some(state) = state else {
        return false;
    };
    // Zero, future timestamps, and stale data never become effective IOC matches.
    state.last_success_at > 0
        && state.last_success_at <= now
        && now - state.last_success_at <= state.ttl_seconds
        && state.ttl_seconds > 0
        && state.ttl_seconds <= FEED_TTL_SECONDS
}

fn source_state<'a>(cache: &'a Cache, source: &str) -> Option<&'a FeedState> {
    cache.sources.iter().find(|state| state.source == source)
}

fn migrate_legacy(old: LegacyCache) -> Result<Cache> {
    if old.version != 1 || old.entries.len() > FEEDS.len() * MAX_PER_FEED {
        return Err("Unsupported or oversized legacy C2 cache".into());
    }
    // V1 updated its global saved_at even when one source failed; it cannot
    // establish individual source freshness. Conservatively use the oldest
    // indicator's collected_at for each source, never the global saved_at.
    let mut oldest: BTreeMap<String, u64> = BTreeMap::new();
    for entry in &old.entries {
        if !recognized(&entry.source) {
            return Err("Unknown source in legacy C2 cache".into());
        }
        oldest
            .entry(entry.source.clone())
            .and_modify(|timestamp| *timestamp = (*timestamp).min(entry.collected_at))
            .or_insert(entry.collected_at);
    }
    let sources = oldest
        .into_iter()
        .map(|(source, last_success_at)| FeedState {
            source,
            last_success_at,
            ttl_seconds: FEED_TTL_SECONDS,
        })
        .collect();
    Ok(Cache {
        version: CACHE_VERSION,
        saved_at: old.saved_at,
        sources,
        entries: old.entries,
    })
}

fn validate_cache(cache: &Cache) -> Result<()> {
    if cache.version != CACHE_VERSION
        || cache.entries.len() > FEEDS.len() * MAX_PER_FEED
        || cache.sources.len() > FEEDS.len()
    {
        return Err("Unsupported or oversized C2 cache".into());
    }
    let mut names = HashSet::new();
    for state in &cache.sources {
        if !recognized(&state.source)
            || !names.insert(state.source.as_str())
            || state.ttl_seconds != FEED_TTL_SECONDS
        {
            return Err("Invalid feed metadata in C2 cache".into());
        }
    }
    for entry in &cache.entries {
        if !recognized(&entry.source) || !public_ip(entry.ip) {
            return Err("Invalid IOC record in C2 cache".into());
        }
    }
    Ok(())
}

fn read_cache(path: &Path) -> Result<Cache> {
    if !path.exists() {
        return Ok(Cache::default());
    }
    if fs::metadata(path)?.len() > MAX_RESPONSE_BYTES {
        return Err("Local cache exceeds safe size limit".into());
    }
    let bytes = fs::read(path)?;
    let version: serde_json::Value = serde_json::from_slice(&bytes)?;
    let cache = match version.get("version").and_then(|v| v.as_u64()) {
        Some(1) => migrate_legacy(serde_json::from_slice(&bytes)?)?,
        Some(2) => serde_json::from_slice(&bytes)?,
        _ => return Err("Unsupported C2 cache version".into()),
    };
    validate_cache(&cache)?;
    Ok(cache)
}

fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !(ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_broadcast()
                || ip.is_multicast()
                || ip.is_unspecified()
                || ip.is_documentation()
                || a == 0
                || a >= 240
                || (a == 100 && (64..=127).contains(&b))
                || (a == 198 && (b == 18 || b == 19))
                || (a == 192 && b == 0 && c == 0))
        }
        IpAddr::V6(ip) => {
            !(ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || ip.is_unique_local()
                || ip.is_unicast_link_local())
        }
    }
}

fn parse_indicator(line: &str) -> Option<IpAddr> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let candidate = line.split(',').next()?.trim().trim_matches('"').trim();
    let ip = candidate.parse::<IpAddr>().ok()?;
    public_ip(ip).then_some(ip)
}

fn parse_feed(source: &str, body: &str) -> Option<Vec<IpAddr>> {
    let mut seen = HashSet::new();
    let mut ips = Vec::new();
    for line in body.lines() {
        if let Some(ip) = parse_indicator(line) {
            if seen.insert(ip) {
                if ips.len() >= MAX_PER_FEED {
                    return None;
                } // No silent truncation.
                ips.push(ip);
            }
        }
    }
    if !ips.is_empty() {
        return Some(ips);
    }

    // An empty Feodo list is legitimate when it contains only comments;
    // HTTP 200 with an empty body or HTML is NOT evidence of a valid empty feed.
    if source == "feodo"
        && body.lines().any(|l| l.trim_start().starts_with('#'))
        && body
            .lines()
            .all(|l| l.trim().is_empty() || l.trim_start().starts_with('#'))
    {
        return Some(Vec::new());
    }
    None
}

fn fetch(client: &reqwest::blocking::Client, url: &str) -> Result<String> {
    let response = client.get(url).send()?.error_for_status()?;
    let mut bytes = Vec::new();
    response
        .take(MAX_RESPONSE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_RESPONSE_BYTES {
        return Err("Feed download exceeded maximum response size".into());
    }
    Ok(String::from_utf8(bytes)?)
}

/// Update one source only if it passed parsing and validation; preserves
/// independent last-success dates for all other feeds on partial outages.
fn apply_feed(cache: &mut Cache, source: &str, body: &str, now: u64) -> bool {
    if !recognized(source) || now == 0 {
        return false;
    }
    let Some(ips) = parse_feed(source, body) else {
        return false;
    };
    cache.entries.retain(|entry| entry.source != source);
    cache
        .entries
        .extend(ips.iter().copied().map(|ip| Indicator {
            ip,
            source: source.to_owned(),
            collected_at: now,
        }));
    cache.sources.retain(|state| state.source != source);
    cache.sources.push(FeedState {
        source: source.to_owned(),
        last_success_at: now,
        ttl_seconds: FEED_TTL_SECONDS,
    });
    cache.saved_at = now;
    true
}

fn write_cache(path: &Path, cache: &Cache) -> Result<()> {
    validate_cache(cache)?;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let temp = path.with_extension("tmp");
    if temp.exists() {
        return Err("A previous incomplete cache update exists; resolve it first".into());
    }
    fs::write(&temp, serde_json::to_vec_pretty(cache)?)?;
    if !path.exists() {
        fs::rename(temp, path)?;
        return Ok(());
    }
    // Preserve a backup of the last-known-good file for Windows portability.
    let backup = path.with_extension("bak");
    if backup.exists() {
        let _ = fs::remove_file(&temp);
        return Err("A previous cache backup exists; resolve it first".into());
    }
    if let Err(e) = fs::rename(path, &backup) {
        let _ = fs::remove_file(&temp);
        return Err(e.into());
    }
    if let Err(e) = fs::rename(&temp, path) {
        let _ = fs::rename(&backup, path);
        return Err(e.into());
    }
    let _ = fs::remove_file(backup);
    Ok(())
}

pub fn update(path: &Path) -> Result<()> {
    let mut cache = read_cache(path)?;
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(15))
        .user_agent("AegisGuard/0.1 (defensive IOC consumer)")
        .build()?;
    let mut successes = 0usize;
    let mut failed = Vec::new();
    for (source, url) in FEEDS {
        match fetch(&client, url) {
            Ok(body) if apply_feed(&mut cache, source, &body, epoch()) => {
                let count = cache.entries.iter().filter(|e| e.source == source).count();
                eprintln!("{source}: accepted {count} indicators");
                successes += 1;
            }
            Ok(_) => {
                failed.push(source);
                eprintln!("{source}: malformed/empty feed; keeping previous data and timestamp");
            }
            Err(e) => {
                failed.push(source);
                eprintln!("{source}: update failed ({e}); retaining previous timestamp");
            }
        }
    }
    if successes == 0 {
        return Err("No C2 feed updated successfully; previous cache is unchanged".into());
    }
    write_cache(path, &cache)?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "status": if failed.is_empty() { "updated" } else { "partial_update" },
            "sources_updated": successes,
            "sources_failed": failed,
            "indicators": cache.entries.len(),
            "cache": path.display().to_string(),
        }))?
    );
    Ok(())
}

fn effective_matches(cache: &Cache, ip: IpAddr, now: u64) -> (Vec<&str>, Vec<&str>) {
    let mut fresh = Vec::new();
    let mut stale = Vec::new();
    for entry in cache.entries.iter().filter(|e| e.ip == ip) {
        if is_fresh(source_state(cache, &entry.source), now) {
            if !fresh.contains(&entry.source.as_str()) {
                fresh.push(entry.source.as_str());
            }
        } else if !stale.contains(&entry.source.as_str()) {
            stale.push(entry.source.as_str());
        }
    }
    (fresh, stale)
}

fn source_overview(cache: &Cache, now: u64) -> Vec<serde_json::Value> {
    FEEDS
        .iter()
        .map(|(name, _)| {
            let state = source_state(cache, name);
            let last = state.map(|s| s.last_success_at).unwrap_or(0);
            let age = if last > 0 && last <= now {
                Some(now - last)
            } else {
                None
            };
            json!({
                "source": name,
                "last_success_at_unix": last,
                "ttl_seconds": FEED_TTL_SECONDS,
                "age_hours": age.map(|s| s / 3600),
                "stale": !is_fresh(state, now),
                "indicators": cache.entries.iter().filter(|i| i.source == *name).count(),
            })
        })
        .collect()
}

pub fn check(path: &Path, ip: IpAddr) -> Result<()> {
    let cache = read_cache(path)?;
    let now = epoch();
    let (fresh, stale) = effective_matches(&cache, ip, now);
    println!(
        "{}",
        serde_json::to_string(&json!({
            "ip": ip.to_string(),
            "matched": !fresh.is_empty(),
            "sources": fresh,
            "stale_matches_ignored": stale,
            "feeds": source_overview(&cache, now),
            "caution": "Old IP indicators are not considered active. IOC match is not proof of infection.",
        }))?
    );
    Ok(())
}

pub fn status(path: &Path) -> Result<()> {
    let cache = read_cache(path)?;
    let now = epoch();
    let feeds = source_overview(&cache, now);
    let any_stale = FEEDS
        .iter()
        .any(|(name, _)| !is_fresh(source_state(&cache, name), now));
    println!(
        "{}",
        serde_json::to_string(&json!({
            "cache": path.display().to_string(),
            "version": CACHE_VERSION,
            "indicators": cache.entries.len(),
            "saved_at_unix": cache.saved_at,
            "stale": any_stale,
            "feeds": feeds,
        }))?
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn sample_ip() -> IpAddr {
        Ipv4Addr::new(1, 2, 3, 4).into()
    }

    #[test]
    fn ignores_private_ip_and_csv_headers() {
        for s in ["# header", "192.168.1.1", "127.0.0.1", "ip,port"] {
            assert_eq!(parse_indicator(s), None);
        }
    }

    #[test]
    fn parses_and_deduplicates_plain_ip_and_csv() {
        assert_eq!(
            parse_feed("feodo", "1.2.3.4\n1.2.3.4\n5.6.7.8,443\n# comment").unwrap(),
            vec![sample_ip(), Ipv4Addr::new(5, 6, 7, 8).into()]
        );
    }

    #[test]
    fn failed_source_never_inherits_freshness_from_successful_source() {
        let now = 200_000;
        let mut cache = Cache::default();
        assert!(apply_feed(
            &mut cache,
            "feodo",
            "1.2.3.4",
            now - FEED_TTL_SECONDS - 1
        ));
        assert!(apply_feed(
            &mut cache,
            "c2intel_verified",
            "5.6.7.8,IOC",
            now
        ));
        let (active, stale) = effective_matches(&cache, sample_ip(), now);
        assert!(active.is_empty());
        assert_eq!(stale, vec!["feodo"]);
        assert!(!is_fresh(source_state(&cache, "feodo"), now));
        assert!(is_fresh(source_state(&cache, "c2intel_verified"), now));
        assert_eq!(cache.saved_at, now);
    }

    #[test]
    fn malformed_or_empty_update_retains_original_entries_and_time() {
        let mut cache = Cache::default();
        assert!(apply_feed(
            &mut cache,
            "c2intel_verified",
            "1.2.3.4,IOC",
            1_000
        ));
        assert!(!apply_feed(
            &mut cache,
            "c2intel_verified",
            "<html>not a feed</html>",
            2_000
        ));
        assert!(!apply_feed(&mut cache, "c2intel_verified", "", 2_000));
        assert_eq!(
            source_state(&cache, "c2intel_verified")
                .unwrap()
                .last_success_at,
            1_000
        );
        assert_eq!(cache.entries.len(), 1);
    }

    #[test]
    fn legitimate_feodo_empty_list_records_freshness_without_entries() {
        let mut cache = Cache::default();
        assert!(apply_feed(&mut cache, "feodo", "1.2.3.4", 1_000));
        assert!(apply_feed(
            &mut cache,
            "feodo",
            "# No active IPs\n# End\n",
            2_000
        ));
        assert!(cache.entries.is_empty());
        assert_eq!(
            source_state(&cache, "feodo").unwrap().last_success_at,
            2_000
        );
        assert!(is_fresh(source_state(&cache, "feodo"), 2_000));
    }

    #[test]
    fn future_timestamp_is_stale() {
        let mut cache = Cache::default();
        assert!(apply_feed(&mut cache, "feodo", "1.2.3.4", 1000));
        assert!(!is_fresh(source_state(&cache, "feodo"), 999));
    }

    #[test]
    fn legacy_cache_preserves_oldest_per_source_timestamp() {
        let old = LegacyCache {
            version: 1,
            saved_at: 100_000,
            entries: vec![
                Indicator {
                    ip: sample_ip(),
                    source: "feodo".into(),
                    collected_at: 10,
                },
                Indicator {
                    ip: Ipv4Addr::new(5, 6, 7, 8).into(),
                    source: "feodo".into(),
                    collected_at: 50_000,
                },
                Indicator {
                    ip: Ipv4Addr::new(7, 8, 9, 10).into(),
                    source: "c2intel_verified".into(),
                    collected_at: 99_000,
                },
            ],
        };
        let migrated = migrate_legacy(old).unwrap();
        assert_eq!(
            source_state(&migrated, "feodo").unwrap().last_success_at,
            10
        );
        assert_eq!(
            source_state(&migrated, "c2intel_verified")
                .unwrap()
                .last_success_at,
            99_000
        );
        assert!(!is_fresh(source_state(&migrated, "feodo"), 200_000));
    }

    #[test]
    fn default_cache_has_no_fresh_sources() {
        let cache = Cache::default();
        assert!(!is_fresh(source_state(&cache, "feodo"), 10_000));
        assert!(!is_fresh(source_state(&cache, "c2intel_verified"), 10_000));
    }
}
