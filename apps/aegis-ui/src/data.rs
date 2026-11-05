//! Loading saved engine outputs (P7-02).
//!
//! Files are read on a worker thread with byte/record limits and a cancel
//! flag, through the library's typed API (`aegisguard::api`), so the UI
//! thread never blocks and never parses CLI stdout. What could not be read
//! is kept and shown; nothing unreadable becomes "nothing found".
use aegisguard::api::{self, DocumentKind, ReadLimits, ScanReportV2};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{SystemTime, UNIX_EPOCH};

/// Largest JSON (non-JSONL) document read.
const MAX_JSON_BYTES: u64 = 32 * 1024 * 1024;
/// Records kept for display across all scan files.
pub const MAX_SCAN_RECORDS: usize = 200_000;
/// Older than this is shown as stale.
pub const STALE_AFTER_SECS: u64 = 7 * 24 * 3600;

/// One loaded JSON document (Defender audit, correlation, C2 status, ...).
#[derive(Debug, Clone)]
pub struct Document {
    pub path: PathBuf,
    pub kind: DocumentKind,
    pub value: Value,
    /// File modification time; the time the result was saved.
    pub saved_at_unix: Option<u64>,
}

/// A file that could not be used, and why.
#[derive(Debug, Clone)]
pub struct LoadError {
    pub path: PathBuf,
    pub reason: String,
}

/// Everything loaded so far.
#[derive(Debug, Clone, Default)]
pub struct Dataset {
    pub scans: Vec<ScanReportV2>,
    pub scan_files: Vec<ScanFileSummary>,
    pub documents: Vec<Document>,
    pub errors: Vec<LoadError>,
}

#[derive(Debug, Clone)]
pub struct ScanFileSummary {
    pub path: PathBuf,
    pub records: usize,
    pub problems: usize,
    pub newer_schema: u64,
    pub truncated: Option<api::Truncation>,
    pub saved_at_unix: Option<u64>,
}

impl ScanFileSummary {
    pub fn complete(&self) -> bool {
        self.problems == 0 && self.newer_schema == 0 && self.truncated.is_none()
    }
}

impl Dataset {
    pub fn is_empty(&self) -> bool {
        self.scans.is_empty() && self.documents.is_empty()
    }

    pub fn latest(&self, kind: DocumentKind) -> Option<&Document> {
        self.documents
            .iter()
            .filter(|d| d.kind == kind)
            .max_by_key(|d| d.saved_at_unix)
    }

    /// Newest time any loaded result was saved.
    pub fn last_saved(&self) -> Option<u64> {
        self.documents
            .iter()
            .filter_map(|d| d.saved_at_unix)
            .chain(self.scan_files.iter().filter_map(|f| f.saved_at_unix))
            .max()
    }

    fn merge(&mut self, other: Dataset) {
        let room = MAX_SCAN_RECORDS.saturating_sub(self.scans.len());
        let dropped = other.scans.len().saturating_sub(room);
        self.scans.extend(other.scans.into_iter().take(room));
        self.scan_files.extend(other.scan_files);
        if dropped > 0 {
            self.errors.push(LoadError {
                path: PathBuf::new(),
                reason: format!(
                    "表示上限 {MAX_SCAN_RECORDS} 件を超えたため {dropped} 件を読み込んでいません"
                ),
            });
        }
        // Re-loading the same file replaces the older copy.
        for doc in other.documents {
            self.documents.retain(|d| d.path != doc.path);
            self.documents.push(doc);
        }
        self.errors.extend(other.errors);
    }
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn modified_unix(path: &Path) -> Option<u64> {
    std::fs::metadata(path)
        .ok()?
        .modified()
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

/// Read the first line to tell JSONL scan output from a JSON document.
fn first_line(path: &Path) -> std::io::Result<String> {
    use std::io::{BufRead, Read};
    let file = std::fs::File::open(path)?;
    let mut line = String::new();
    std::io::BufReader::new(file.take(4 * 1024 * 1024)).read_line(&mut line)?;
    Ok(line)
}

/// Load one file. Never panics; every failure becomes a `LoadError`.
pub fn load_file(path: &Path, cancel: &AtomicBool) -> Dataset {
    let mut out = Dataset::default();
    let fail = |out: &mut Dataset, reason: String| {
        out.errors.push(LoadError {
            path: path.to_path_buf(),
            reason,
        })
    };
    let first = match first_line(path) {
        Ok(l) => l,
        Err(e) => {
            fail(&mut out, format!("読み取れません: {e}"));
            return out;
        }
    };
    let saved_at_unix = modified_unix(path);
    let first_value: Option<Value> = serde_json::from_str(first.trim()).ok();
    let is_scan = first_value
        .as_ref()
        .is_some_and(|v| api::classify(v) == DocumentKind::ScanReport);
    if is_scan {
        match api::read_scan_jsonl(path, ReadLimits::default(), cancel) {
            Ok(r) => {
                out.scan_files.push(ScanFileSummary {
                    path: path.to_path_buf(),
                    records: r.records.len(),
                    problems: r.problems.len() + r.problems_omitted as usize,
                    newer_schema: r.newer_schema_records,
                    truncated: r.truncated,
                    saved_at_unix,
                });
                out.scans = r.records;
            }
            Err(e) => fail(&mut out, format!("読み取れません: {e}")),
        }
        return out;
    }
    match std::fs::metadata(path) {
        Ok(m) if m.len() > MAX_JSON_BYTES => {
            fail(
                &mut out,
                format!("{} バイトを超えるため読み込みません", MAX_JSON_BYTES),
            );
            return out;
        }
        Err(e) => {
            fail(&mut out, format!("読み取れません: {e}"));
            return out;
        }
        Ok(_) => {}
    }
    let value: Value = match std::fs::read(path)
        .map_err(|e| e.to_string())
        .and_then(|b| serde_json::from_slice(&b).map_err(|e| e.to_string()))
    {
        Ok(v) => v,
        Err(e) => {
            fail(
                &mut out,
                format!("AegisGuardの出力として解釈できません: {e}"),
            );
            return out;
        }
    };
    match api::classify(&value) {
        DocumentKind::Unknown => fail(&mut out, "どのコマンドの出力か判別できません".into()),
        kind => out.documents.push(Document {
            path: path.to_path_buf(),
            kind,
            value,
            saved_at_unix,
        }),
    }
    out
}

/// Messages from the worker.
pub enum Update {
    Progress {
        done: usize,
        total: usize,
        current: PathBuf,
    },
    Finished(Dataset, bool),
}

/// A single background load job. Only one runs at a time.
pub struct Job {
    pub rx: mpsc::Receiver<Update>,
    pub cancel: Arc<AtomicBool>,
    pub done: usize,
    pub total: usize,
    pub current: Option<PathBuf>,
}

pub fn start(paths: Vec<PathBuf>, repaint: impl Fn() + Send + 'static) -> Job {
    let (tx, rx) = mpsc::channel();
    let cancel = Arc::new(AtomicBool::new(false));
    let flag = cancel.clone();
    let total = paths.len();
    std::thread::spawn(move || {
        let mut all = Dataset::default();
        for (i, path) in paths.into_iter().enumerate() {
            if flag.load(Ordering::Relaxed) {
                break;
            }
            let _ = tx.send(Update::Progress {
                done: i,
                total,
                current: path.clone(),
            });
            repaint();
            all.merge(load_file(&path, &flag));
        }
        let cancelled = flag.load(Ordering::Relaxed);
        let _ = tx.send(Update::Finished(all, cancelled));
        repaint();
    });
    Job {
        rx,
        cancel,
        done: 0,
        total,
        current: None,
    }
}

impl Dataset {
    pub fn absorb(&mut self, other: Dataset) {
        self.merge(other);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("aegis-ui-data-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    const SCAN: &str = r#"{"path":"a.ps1","kind":"script","status":"analyzed","risk":"review","score":45,"analysis_complete":true,"schema_version":2,"assessment":"analyzed","signal_level":"review"}"#;

    #[test]
    fn scan_jsonl_with_bad_lines_is_loaded_and_flagged() {
        let d = dir("scan");
        let p = d.join("scan.jsonl");
        fs::write(&p, format!("{SCAN}\n{{broken\n{SCAN}\n")).unwrap();
        let out = load_file(&p, &AtomicBool::new(false));
        assert_eq!(out.scans.len(), 2);
        assert_eq!(out.scan_files[0].problems, 1);
        assert!(!out.scan_files[0].complete());
    }

    #[test]
    fn unknown_empty_missing_and_huge_files_become_errors() {
        let d = dir("bad");
        let unknown = d.join("x.json");
        fs::write(&unknown, r#"{"hello":1}"#).unwrap();
        let empty = d.join("empty.json");
        fs::write(&empty, "").unwrap();
        for p in [unknown, empty, d.join("missing.json")] {
            let out = load_file(&p, &AtomicBool::new(false));
            assert!(out.is_empty());
            assert_eq!(out.errors.len(), 1, "{p:?}");
        }
    }

    #[test]
    fn documents_are_classified_and_reloading_replaces() {
        let d = dir("docs");
        let p = d.join("defender.json");
        fs::write(
            &p,
            r#"{"available":false,"controls":[],"errors":["denied"]}"#,
        )
        .unwrap();
        let mut set = Dataset::default();
        set.absorb(load_file(&p, &AtomicBool::new(false)));
        set.absorb(load_file(&p, &AtomicBool::new(false)));
        assert_eq!(set.documents.len(), 1);
        assert_eq!(set.documents[0].kind, DocumentKind::DefenderAudit);
    }

    #[test]
    fn long_names_and_cancel_do_not_break_loading() {
        let d = dir("long");
        let p = d.join(format!("{}.jsonl", "n".repeat(180)));
        fs::write(&p, format!("{SCAN}\n")).unwrap();
        assert_eq!(load_file(&p, &AtomicBool::new(false)).scans.len(), 1);
        let cancelled = load_file(&p, &AtomicBool::new(true));
        assert_eq!(
            cancelled.scan_files[0].truncated,
            Some(api::Truncation::Cancelled)
        );
    }

    #[test]
    fn worker_reports_progress_and_finishes() {
        let d = dir("worker");
        let p = d.join("scan.jsonl");
        fs::write(&p, format!("{SCAN}\n")).unwrap();
        let job = start(vec![p.clone(), p], || {});
        let mut finished = None;
        while let Ok(u) = job.rx.recv() {
            if let Update::Finished(set, cancelled) = u {
                finished = Some((set, cancelled));
            }
        }
        let (set, cancelled) = finished.unwrap();
        assert!(!cancelled);
        assert_eq!(set.scans.len(), 2);
    }
}
