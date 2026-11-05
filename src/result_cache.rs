//! Bounded cache of YARA results (P5-05), keyed by
//! (file SHA-256, ruleset SHA-256) and tied to one engine identity.
//!
//! A cached result is reused only when the file bytes, the compiled rule set
//! and the engine (YARA-X version + built-in deobfuscation version, which
//! decides the decoded layers) are all identical; changing any of them can
//! never reuse an old result. Only complete analyses are stored, so a
//! timeout or partial scan is never replayed as "scanned". The cache is an
//! optimization: if it cannot be read, scanning proceeds without it.
use crate::model::YaraSummary;
use crate::{store, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

pub const SCHEMA: u32 = 1;
/// Default entry cap; the least recently used entries are evicted.
pub const DEFAULT_MAX_ENTRIES: usize = 50_000;
/// Cache files larger than this are not loaded.
const MAX_FILE_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Entry {
    summary: YaraSummary,
    last_used: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ResultCache {
    schema: u32,
    /// Engine identity the entries were produced with.
    engine: String,
    entries: BTreeMap<String, Entry>,
    clock: u64,
    #[serde(skip)]
    max_entries: usize,
    #[serde(skip)]
    pub hits: u64,
    #[serde(skip)]
    pub misses: u64,
    #[serde(skip)]
    pub discarded_reason: Option<String>,
}

fn key(file_sha256: &str, ruleset_sha256: &str) -> String {
    format!("{file_sha256}:{ruleset_sha256}")
}

impl ResultCache {
    pub fn new(engine: &str, max_entries: usize) -> Self {
        Self {
            schema: SCHEMA,
            engine: engine.to_string(),
            entries: BTreeMap::new(),
            clock: 0,
            max_entries: max_entries.max(1),
            hits: 0,
            misses: 0,
            discarded_reason: None,
        }
    }

    /// Load a cache file. A missing file, another engine identity, another
    /// schema or a corrupt file all give an empty cache (with the reason).
    pub fn load(path: &Path, engine: &str, max_entries: usize) -> Self {
        let parse = |b: &[u8]| -> Result<ResultCache> { Ok(serde_json::from_slice(b)?) };
        let mut fresh = Self::new(engine, max_entries);
        match store::load(path, MAX_FILE_BYTES, parse) {
            Ok(None) => fresh,
            Ok(Some((mut cache, _))) => {
                if cache.schema != SCHEMA {
                    fresh.discarded_reason =
                        Some(format!("cache schema {} != {SCHEMA}", cache.schema));
                    fresh
                } else if cache.engine != engine {
                    fresh.discarded_reason = Some(format!(
                        "engine changed ({} -> {engine}); all entries invalidated",
                        cache.engine
                    ));
                    fresh
                } else {
                    cache.max_entries = max_entries.max(1);
                    cache.evict();
                    cache
                }
            }
            Err(e) => {
                fresh.discarded_reason = Some(format!("cache unreadable, starting empty: {e}"));
                fresh
            }
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        let bytes = serde_json::to_vec(self)?;
        store::store(path, &bytes, |b| {
            serde_json::from_slice::<ResultCache>(b)
                .map(|_| ())
                .map_err(Into::into)
        })
    }

    /// A cached summary for exactly this file and rule set, if any.
    pub fn get(&mut self, file_sha256: &str, ruleset_sha256: &str) -> Option<YaraSummary> {
        self.clock += 1;
        let clock = self.clock;
        match self.entries.get_mut(&key(file_sha256, ruleset_sha256)) {
            // Defense in depth: the summary must name the same rule set.
            Some(e) if e.summary.ruleset_sha256 == ruleset_sha256 => {
                e.last_used = clock;
                self.hits += 1;
                Some(e.summary.clone())
            }
            _ => {
                self.misses += 1;
                None
            }
        }
    }

    /// Store the result of a *complete* analysis.
    pub fn insert(&mut self, file_sha256: &str, summary: &YaraSummary) {
        self.clock += 1;
        self.entries.insert(
            key(file_sha256, &summary.ruleset_sha256),
            Entry {
                summary: summary.clone(),
                last_used: self.clock,
            },
        );
        self.evict();
    }

    fn evict(&mut self) {
        while self.entries.len() > self.max_entries {
            let oldest = self
                .entries
                .iter()
                .min_by_key(|(_, e)| e.last_used)
                .map(|(k, _)| k.clone());
            match oldest {
                Some(k) => {
                    self.entries.remove(&k);
                }
                None => break,
            }
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::YaraMatch;

    fn summary(ruleset: &str, rule: &str) -> YaraSummary {
        YaraSummary {
            ruleset_sha256: ruleset.into(),
            layers_scanned: 2,
            matches: vec![YaraMatch {
                rule: rule.into(),
                namespace: "default".into(),
                rule_id: "AG-T-1".into(),
                severity: 40,
                layer: "raw".into(),
                layer_sha256: "ab".into(),
                offsets: vec![(0, 4)],
                omitted_offsets: 0,
                in_comment_only: false,
            }],
        }
    }

    fn temp(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("aegis-cache-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d.join("yara-cache.json")
    }

    #[test]
    fn hit_only_for_the_same_file_and_rule_set() {
        let mut c = ResultCache::new("e1", 10);
        c.insert("f1", &summary("r1", "a"));
        assert!(c.get("f1", "r1").is_some());
        // A rule update (new rule set hash) or a changed file never hits.
        assert!(c.get("f1", "r2").is_none());
        assert!(c.get("f2", "r1").is_none());
        assert_eq!((c.hits, c.misses), (1, 2));
    }

    #[test]
    fn engine_change_invalidates_everything_on_load() {
        let path = temp("engine");
        let mut c = ResultCache::new("yara-x 1 / builtin-static-3", 10);
        c.insert("f1", &summary("r1", "a"));
        c.save(&path).unwrap();
        let same = ResultCache::load(&path, "yara-x 1 / builtin-static-3", 10);
        assert_eq!(same.len(), 1);
        let other = ResultCache::load(&path, "yara-x 2 / builtin-static-3", 10);
        assert!(other.is_empty());
        assert!(other.discarded_reason.unwrap().contains("engine changed"));
    }

    #[test]
    fn corrupt_or_missing_cache_starts_empty() {
        let path = temp("corrupt");
        assert!(ResultCache::load(&path, "e", 10).is_empty());
        std::fs::write(&path, b"{not json").unwrap();
        let c = ResultCache::load(&path, "e", 10);
        assert!(c.is_empty());
        assert!(c.discarded_reason.is_some());
    }

    #[test]
    fn least_recently_used_entries_are_evicted() {
        let mut c = ResultCache::new("e", 2);
        c.insert("a", &summary("r", "x"));
        c.insert("b", &summary("r", "x"));
        assert!(c.get("a", "r").is_some());
        c.insert("c", &summary("r", "x"));
        assert_eq!(c.len(), 2);
        assert!(c.get("b", "r").is_none());
        assert!(c.get("a", "r").is_some());
    }

    #[test]
    fn mismatched_ruleset_inside_entry_is_not_returned() {
        let mut c = ResultCache::new("e", 10);
        c.entries.insert(
            key("f", "r1"),
            Entry {
                summary: summary("r-other", "x"),
                last_used: 0,
            },
        );
        assert!(c.get("f", "r1").is_none());
    }
}
