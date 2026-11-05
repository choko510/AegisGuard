//! Rule provenance ledger. Every rule file must have an entry naming its origin
//! and license before it can be compiled or packed, so third-party rules cannot
//! slip in without an explicit rights decision.
use crate::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

pub const LEDGER_FILE: &str = "ledger.json";
const MAX_LEDGER_BYTES: u64 = 256 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LedgerEntry {
    pub file: String,
    pub origin: String,
    pub license: String,
}

/// `*.yar` / `*.yara` regular files directly in `dir`, sorted.
pub fn rule_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .map(str::to_ascii_lowercase);
        if matches!(ext.as_deref(), Some("yar" | "yara")) {
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}

/// Read `ledger.json` and require exactly one entry per rule file.
pub fn read_ledger(dir: &Path) -> Result<Vec<LedgerEntry>> {
    let path = dir.join(LEDGER_FILE);
    let meta = fs::symlink_metadata(&path).map_err(|e| {
        format!(
            "{}: {e} (every rule directory needs a ledger)",
            path.display()
        )
    })?;
    if !meta.is_file() || meta.len() > MAX_LEDGER_BYTES {
        return Err(format!(
            "{} is not a regular file within the size limit",
            path.display()
        )
        .into());
    }
    let ledger: Vec<LedgerEntry> = serde_json::from_slice(&fs::read(&path)?)?;
    let mut problems = Vec::new();
    for entry in &ledger {
        if entry.origin.trim().is_empty() || entry.license.trim().is_empty() {
            problems.push(format!("{}: origin and license must be stated", entry.file));
        }
        if ledger.iter().filter(|e| e.file == entry.file).count() > 1 {
            problems.push(format!("{}: duplicate ledger entry", entry.file));
        }
    }
    for file in rule_files(dir)? {
        let name = file.file_name().unwrap_or_default().to_string_lossy();
        if !ledger.iter().any(|e| e.file == name) {
            problems.push(format!("{name}: no ledger entry (origin/license unknown)"));
        }
    }
    if problems.is_empty() {
        Ok(ledger)
    } else {
        problems.dedup();
        Err(problems.join("; ").into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("aegisguard-ledger-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn repository_rules_are_fully_ledgered() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("rules/aegisguard");
        let ledger = read_ledger(&dir).unwrap();
        assert_eq!(ledger.len(), rule_files(&dir).unwrap().len());
        assert!(ledger.iter().all(|e| e.origin == "self-authored"));
    }

    #[test]
    fn unledgered_or_incomplete_entries_are_rejected() {
        let dir = temp_dir("missing");
        fs::write(dir.join("a.yar"), "rule a { condition: false }").unwrap();
        assert!(read_ledger(&dir).is_err());
        fs::write(
            dir.join(LEDGER_FILE),
            r#"[{"file":"a.yar","origin":"","license":"x"}]"#,
        )
        .unwrap();
        assert!(read_ledger(&dir).is_err());
        fs::write(
            dir.join(LEDGER_FILE),
            r#"[{"file":"a.yar","origin":"self-authored","license":"x"}]"#,
        )
        .unwrap();
        assert!(read_ledger(&dir).is_ok());
        fs::write(dir.join("b.yar"), "rule b { condition: false }").unwrap();
        assert!(read_ledger(&dir).is_err());
        fs::remove_dir_all(dir).unwrap();
    }
}
