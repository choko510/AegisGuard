//! Limited, read-only file integrity monitoring for a few explicitly named
//! paths. A baseline records metadata, handle identity and SHA-256; a check
//! rescans and reports created / modified / renamed / deleted / unreadable
//! entries individually. Browser credential stores are excluded by name and
//! never hashed or read. FIM sees changes, not reads: data copied out of a
//! file without modifying it is invisible here.
use crate::{fsafe, model, store, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

pub const BASELINE_SCHEMA: u32 = 1;
const MAX_ENTRIES: usize = 10_000;
const MAX_HASH_BYTES: u64 = 256 * 1024 * 1024;
const MAX_BASELINE_BYTES: u64 = 32 * 1024 * 1024;
const MAX_DEPTH: usize = 8;
/// File names that hold credentials or cookies; never opened by FIM.
const SENSITIVE_NAMES: &[&str] = &[
    "login data",
    "login data for account",
    "cookies",
    "web data",
    "local state",
    "key3.db",
    "key4.db",
    "logins.json",
    "cert9.db",
    "ntuser.dat",
    "sam",
    "security",
    "system",
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub size: u64,
    pub modified_unix_ms: Option<u64>,
    pub device_id: u64,
    pub file_id: u64,
    /// None when the file was larger than the hashing limit.
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Baseline {
    pub schema: u32,
    pub created_at_unix_ms: u64,
    pub roots: Vec<PathBuf>,
    pub entries: BTreeMap<String, Entry>,
    /// Paths that could not be recorded and why; they are not monitored.
    pub not_monitored: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Change {
    /// created, modified, renamed, deleted, unreadable, now_excluded
    pub kind: &'static str,
    pub path: String,
    pub previous_path: Option<String>,
    pub detail: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CheckResult {
    pub baseline_created_at_unix_ms: u64,
    pub checked_at_unix_ms: u64,
    pub changes: Vec<Change>,
    pub unchanged: usize,
    pub not_monitored: BTreeMap<String, String>,
    /// Changes that happened and were reverted between baseline and check are
    /// invisible to a rescan; this is stated rather than implied.
    pub limitation: &'static str,
}

fn is_sensitive(path: &Path) -> bool {
    path.file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .is_some_and(|n| SENSITIVE_NAMES.contains(&n.as_str()))
}

fn record(path: &Path) -> std::result::Result<Entry, String> {
    let (mut file, meta) = match fsafe::open_regular(path) {
        Ok(opened) => opened,
        Err(fsafe::OpenFailure::Link) => return Err("symlink_not_followed".into()),
        Err(fsafe::OpenFailure::NotRegular) => return Err("not_regular_file".into()),
        Err(fsafe::OpenFailure::Io(e)) => return Err(format!("open_failed: {e}")),
    };
    let id = fsafe::handle_id(&file).map_err(|e| format!("identity_unavailable: {e}"))?;
    let identity = model::FileIdentity::from_metadata(&meta, "handle_metadata");
    let sha256 = if meta.len() <= MAX_HASH_BYTES {
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 64 * 1024];
        let mut total = 0u64;
        loop {
            let n = file
                .read(&mut buf)
                .map_err(|e| format!("read_failed: {e}"))?;
            if n == 0 {
                break;
            }
            total += n as u64;
            if total > MAX_HASH_BYTES {
                return Err("file_grew_during_read".into());
            }
            hasher.update(&buf[..n]);
        }
        let after = file.metadata().map_err(|e| format!("read_failed: {e}"))?;
        if !fsafe::unchanged(&meta, &after) || total != meta.len() {
            return Err("file_changed_during_read".into());
        }
        Some(hex::encode(hasher.finalize()))
    } else {
        None
    };
    Ok(Entry {
        size: meta.len(),
        modified_unix_ms: identity.modified_unix_ms,
        device_id: id.device,
        file_id: id.file,
        sha256,
    })
}

/// Enumerate and record `roots` (files, or directories up to a fixed depth).
fn scan_roots(roots: &[PathBuf]) -> (BTreeMap<String, Entry>, BTreeMap<String, String>) {
    let mut entries = BTreeMap::new();
    let mut not_monitored = BTreeMap::new();
    for root in roots {
        for item in WalkDir::new(root).follow_links(false).max_depth(MAX_DEPTH) {
            let item = match item {
                Ok(i) => i,
                Err(e) => {
                    let path = e.path().unwrap_or(root).display().to_string();
                    not_monitored.insert(path, format!("walk_failed: {e}"));
                    continue;
                }
            };
            if item.file_type().is_dir() {
                continue;
            }
            let key = item.path().display().to_string();
            if is_sensitive(item.path()) {
                not_monitored.insert(key, "excluded_sensitive".into());
                continue;
            }
            if entries.len() >= MAX_ENTRIES {
                not_monitored.insert(key, "entry_limit".into());
                continue;
            }
            match record(item.path()) {
                Ok(entry) => {
                    entries.insert(key, entry);
                }
                Err(reason) => {
                    not_monitored.insert(key, reason);
                }
            }
        }
    }
    (entries, not_monitored)
}

pub fn baseline(roots: &[PathBuf], db: &Path) -> Result<Baseline> {
    if roots.is_empty() {
        return Err("name at least one path to monitor".into());
    }
    for root in roots {
        if is_sensitive(root) {
            return Err(format!(
                "{} is a credential store and is never monitored",
                root.display()
            )
            .into());
        }
    }
    let (entries, not_monitored) = scan_roots(roots);
    let baseline = Baseline {
        schema: BASELINE_SCHEMA,
        created_at_unix_ms: model::now_unix_ms(),
        roots: roots.to_vec(),
        entries,
        not_monitored,
    };
    let bytes = serde_json::to_vec(&baseline)?;
    store::store(db, &bytes, |b| parse_baseline(b).map(|_| ()))?;
    Ok(baseline)
}

fn parse_baseline(bytes: &[u8]) -> Result<Baseline> {
    let baseline: Baseline = serde_json::from_slice(bytes)?;
    if baseline.schema != BASELINE_SCHEMA || baseline.entries.len() > MAX_ENTRIES {
        return Err("unsupported or oversized FIM baseline".into());
    }
    Ok(baseline)
}

pub fn load(db: &Path) -> Result<Baseline> {
    match store::load(db, MAX_BASELINE_BYTES, parse_baseline)? {
        Some((baseline, _)) => Ok(baseline),
        None => Err(format!(
            "no FIM baseline at {}; run `fim baseline` first",
            db.display()
        )
        .into()),
    }
}

/// Compare the current state of the baseline roots against the baseline.
pub fn check(baseline: &Baseline) -> CheckResult {
    let (current, not_monitored) = scan_roots(&baseline.roots);
    let mut changes = Vec::new();
    let mut unchanged = 0usize;
    let mut renamed_from = BTreeSet::new();
    let mut renamed_to = BTreeSet::new();
    // Renames: same file identity and content at a new path.
    for (old_path, old) in &baseline.entries {
        if current.contains_key(old_path) {
            continue;
        }
        if let Some((new_path, _)) = current.iter().find(|(p, e)| {
            !baseline.entries.contains_key(*p)
                && !renamed_to.contains(*p)
                && e.device_id == old.device_id
                && e.file_id == old.file_id
                && e.sha256 == old.sha256
        }) {
            changes.push(Change {
                kind: "renamed",
                path: new_path.clone(),
                previous_path: Some(old_path.clone()),
                detail: None,
            });
            renamed_from.insert(old_path.clone());
            renamed_to.insert(new_path.clone());
        }
    }
    for (path, old) in &baseline.entries {
        if renamed_from.contains(path) {
            continue;
        }
        match current.get(path) {
            None => {
                let (kind, detail) = match not_monitored.get(path) {
                    Some(reason) if reason == "excluded_sensitive" => {
                        ("now_excluded", Some(reason.clone()))
                    }
                    Some(reason) => ("unreadable", Some(reason.clone())),
                    None => ("deleted", None),
                };
                changes.push(Change {
                    kind,
                    path: path.clone(),
                    previous_path: None,
                    detail,
                });
            }
            Some(now) if now == old => unchanged += 1,
            Some(now) => {
                let detail = if now.file_id != old.file_id || now.device_id != old.device_id {
                    "replaced (different file identity)"
                } else if now.sha256 != old.sha256 || now.size != old.size {
                    "content changed"
                } else {
                    "metadata changed"
                };
                changes.push(Change {
                    kind: "modified",
                    path: path.clone(),
                    previous_path: None,
                    detail: Some(detail.into()),
                });
            }
        }
    }
    for path in current.keys() {
        if !baseline.entries.contains_key(path) && !renamed_to.contains(path) {
            changes.push(Change {
                kind: "created",
                path: path.clone(),
                previous_path: None,
                detail: None,
            });
        }
    }
    changes.sort_by(|a, b| (a.kind, &a.path).cmp(&(b.kind, &b.path)));
    CheckResult {
        baseline_created_at_unix_ms: baseline.created_at_unix_ms,
        checked_at_unix_ms: model::now_unix_ms(),
        changes,
        unchanged,
        not_monitored,
        limitation: "A rescan only sees the current state; changes reverted before the check and read-only access are not visible.",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("aegisguard-fim-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn each_change_kind_is_reported_individually() {
        let dir = temp_dir("kinds");
        let watched = dir.join("watched");
        fs::create_dir_all(&watched).unwrap();
        for name in ["keep.txt", "edit.txt", "gone.txt", "move.txt"] {
            fs::write(watched.join(name), name).unwrap();
        }
        let db = dir.join("baseline.json");
        let base = baseline(std::slice::from_ref(&watched), &db).unwrap();
        assert_eq!(base.entries.len(), 4);

        fs::write(watched.join("edit.txt"), "edited content").unwrap();
        fs::remove_file(watched.join("gone.txt")).unwrap();
        fs::rename(watched.join("move.txt"), watched.join("moved.txt")).unwrap();
        fs::write(watched.join("new.txt"), "new").unwrap();

        let result = check(&load(&db).unwrap());
        let kinds: Vec<_> = result
            .changes
            .iter()
            .map(|c| {
                (
                    c.kind,
                    Path::new(&c.path)
                        .file_name()
                        .unwrap()
                        .to_string_lossy()
                        .into_owned(),
                )
            })
            .collect();
        assert_eq!(
            kinds,
            vec![
                ("created", "new.txt".into()),
                ("deleted", "gone.txt".into()),
                ("modified", "edit.txt".into()),
                ("renamed", "moved.txt".into()),
            ]
        );
        assert_eq!(result.unchanged, 1);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn credential_stores_are_never_read() {
        let dir = temp_dir("sensitive");
        fs::write(dir.join("Login Data"), "not really").unwrap();
        fs::write(dir.join("notes.txt"), "x").unwrap();
        let db = dir.join("db.json");
        let base = baseline(std::slice::from_ref(&dir), &db).unwrap();
        let key = dir.join("Login Data").display().to_string();
        assert_eq!(
            base.not_monitored.get(&key).map(String::as_str),
            Some("excluded_sensitive")
        );
        assert!(!base.entries.contains_key(&key));
        assert!(baseline(&[dir.join("Login Data")], &db).is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn replaced_file_is_reported_with_identity_change() {
        let dir = temp_dir("replace");
        let target = dir.join("a.cfg");
        fs::write(&target, "same").unwrap();
        let db = dir.join("db.json");
        let base = baseline(std::slice::from_ref(&target), &db).unwrap();
        let tmp = dir.join("a.tmp");
        fs::write(&tmp, "same").unwrap();
        fs::rename(&tmp, &target).unwrap();
        let result = check(&base);
        assert_eq!(result.changes.len(), 1);
        assert_eq!(result.changes[0].kind, "modified");
        assert_eq!(
            result.changes[0].detail.as_deref(),
            Some("replaced (different file identity)")
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn missing_baseline_is_an_error() {
        let dir = temp_dir("nobaseline");
        assert!(load(&dir.join("none.json")).is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn unreadable_file_is_reported_not_deleted() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("unreadable");
        let target = dir.join("secret.conf");
        fs::write(&target, "x").unwrap();
        let db = dir.join("db.json");
        let base = baseline(std::slice::from_ref(&dir), &db).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o000)).unwrap();
        let enforced = fs::File::open(&target).is_err();
        let result = check(&base);
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        if enforced {
            assert!(result.changes.iter().any(|c| c.kind == "unreadable"));
            assert!(result.changes.iter().all(|c| c.kind != "deleted"));
        }
        fs::remove_dir_all(dir).unwrap();
    }
}
