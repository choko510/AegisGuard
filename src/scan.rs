use crate::budget::{self, Budget};
use crate::jsonl::JsonlLog;
use crate::model::{Assessment, FileIdentity, Report};
use crate::{fsafe, pe, script, Result};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::path::Path;
use std::time::Duration;
use walkdir::WalkDir;

const MAX_PE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_SCRIPT_BYTES: u64 = 4 * 1024 * 1024;

fn classify(path: &Path) -> Option<&'static str> {
    let ext = path.extension()?.to_str()?.to_ascii_lowercase();
    match ext.as_str() {
        "exe" | "dll" | "sys" | "scr" | "ocx" | "cpl" => Some("pe"),
        "py" | "pyw" | "js" | "jse" | "mjs" | "cjs" | "ps1" | "psm1" | "psd1" | "bat" | "cmd"
        | "vbs" | "vbe" | "wsf" | "hta" => Some("script"),
        _ => None,
    }
}

/// Optional engines configured for a run. Empty unless built with `--features yara`
/// and `--yara-rules` was given.
#[derive(Default, Clone, Copy)]
pub struct Engines<'a> {
    #[cfg(feature = "yara")]
    pub yara: Option<&'a crate::yara::RuleSet>,
    /// Reuse YARA results of unchanged files with the same rule set (P5-05).
    #[cfg(feature = "yara")]
    pub yara_cache: Option<&'a std::cell::RefCell<crate::result_cache::ResultCache>>,
    #[cfg(not(feature = "yara"))]
    pub _none: std::marker::PhantomData<&'a ()>,
}

pub fn scan_file(path: &Path, time_limit: Duration, engines: Engines) -> Report {
    let kind = classify(path).unwrap_or("unsupported");
    let mut report = Report::new(path.display().to_string(), kind);
    if kind == "unsupported" {
        report.unavailable(
            "unsupported",
            "unsupported_file_type",
            "File type is not a configured scan target",
        );
        return report;
    }

    // Do not scan a symlink observed at initial metadata inspection.
    // This is not an atomic no-follow open; production Windows service must
    // additionally defend against path swaps/reparse points.
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) => {
            report.unavailable("unreadable", "metadata_failed", e.to_string());
            return report;
        }
    };
    if meta.file_type().is_symlink() {
        report.unavailable(
            "unreadable",
            "symlink_not_followed",
            "Not a regular file or is a symlink",
        );
        return report;
    }
    if !meta.is_file() {
        report.unavailable(
            "unreadable",
            "not_regular_file",
            "Not a regular file or is a symlink",
        );
        return report;
    }
    report.file_identity = Some(FileIdentity::from_metadata(&meta, "path_metadata"));
    let limit = if kind == "pe" {
        MAX_PE_BYTES
    } else {
        MAX_SCRIPT_BYTES
    };
    report.coverage.size_limit_bytes = Some(limit);
    if meta.len() > limit {
        report.unavailable(
            "oversized_no_deep_scan",
            "size_limit_exceeded",
            "Size exceeds the configured deep-scan limit",
        );
        return report;
    }

    // Resolve the parent once; the handle's final path must match it, so a
    // directory swapped for a junction/symlink after this point is detected.
    let expected = match fsafe::expected_path(path) {
        Ok(p) => p,
        Err(e) => {
            report.unavailable("unreadable", "metadata_failed", e.to_string());
            return report;
        }
    };
    let (file, before) = match fsafe::open_regular(path) {
        Ok(opened) => opened,
        Err(fsafe::OpenFailure::Link) => {
            report.unavailable(
                "unreadable",
                "symlink_not_followed",
                "The file was replaced by a link or reparse point",
            );
            return report;
        }
        Err(fsafe::OpenFailure::NotRegular) => {
            report.unavailable(
                "unreadable",
                "not_regular_file",
                "Not a regular file or is a symlink",
            );
            return report;
        }
        Err(fsafe::OpenFailure::Io(e)) => {
            report.unavailable("unreadable", "open_failed", e.to_string());
            return report;
        }
    };
    let mut identity = FileIdentity::from_metadata(&before, "handle_metadata");
    let id = match fsafe::handle_id(&file) {
        Ok(id) => id,
        Err(e) => {
            report.file_identity = Some(identity);
            report.unavailable("unreadable", "identity_unavailable", e.to_string());
            return report;
        }
    };
    identity.device_id = Some(id.device);
    identity.file_id = Some(id.file);
    identity.link_count = Some(id.links);
    report.file_identity = Some(identity);
    if fsafe::final_path(&file).is_some_and(|actual| !fsafe::same_path(&actual, &expected)) {
        report.unavailable(
            "unreadable",
            "path_identity_mismatch",
            "The opened file does not resolve to the requested path",
        );
        return report;
    }
    if before.len() > limit {
        report.unavailable(
            "oversized_no_deep_scan",
            "size_limit_exceeded",
            "Size exceeds the configured deep-scan limit",
        );
        return report;
    }

    let mut data = Vec::new();
    let read = (&file).take(limit + 1).read_to_end(&mut data);
    report.coverage.bytes_read = data.len() as u64;
    if let Err(e) = read {
        report.unavailable("unreadable", "read_failed", e.to_string());
        return report;
    }
    if data.len() as u64 > limit {
        report.unavailable(
            "oversized_no_deep_scan",
            "file_grew_during_read",
            "File grew past the scan limit",
        );
        return report;
    }
    // The bytes are only attributed to `path` if the file did not change while
    // being read and the path still names the same file afterwards.
    let stable = file
        .metadata()
        .is_ok_and(|after| fsafe::unchanged(&before, &after))
        && data.len() as u64 == before.len();
    if !stable || !fsafe::path_refers_to(path, &id) {
        report.unavailable(
            "unreadable",
            "file_changed_during_scan",
            "The file was modified, replaced or removed while it was being read",
        );
        return report;
    }

    report.sha256 = Some(hex::encode(Sha256::digest(&data)));
    let budget = Budget::new(time_limit);
    #[cfg(not(feature = "yara"))]
    let _ = engines;
    #[cfg(feature = "yara")]
    let cached = match (engines.yara, engines.yara_cache, report.sha256.as_deref()) {
        (Some(rules), Some(cache), Some(sha)) => cache.borrow_mut().get(sha, &rules.sha256),
        _ => None,
    };
    #[cfg(feature = "yara")]
    let mut yara = if cached.is_some() {
        None
    } else {
        engines.yara.map(crate::yara::Run::new)
    };
    #[cfg(feature = "yara")]
    if let Some(run) = yara.as_mut() {
        // Comment ranges are only meaningful when the raw bytes are the text
        // itself (UTF-8); other encodings are scanned without them.
        let spans = (kind != "pe")
            .then(|| std::str::from_utf8(&data).ok())
            .flatten()
            .and_then(|text| script::comment_spans(text, &path.display().to_string()));
        run.scan_with_comments(&mut report, "raw", &data, &budget, spans.as_deref());
    }
    if kind == "pe" {
        pe::inspect(&data, &mut report, &budget);
        if report.pe.is_some() {
            // Verified through the same handle, so the checked bytes are the
            // scanned bytes.
            let a = crate::authenticode::verify(&file, path);
            if a.status == crate::authenticode::SignatureStatus::Invalid {
                report.add(
                    "invalid_signature",
                    35,
                    "authenticode",
                    "The file carries an Authenticode signature that does not verify (modified or revoked)",
                );
            }
            if let Some(summary) = report.pe.as_mut() {
                summary.authenticode = Some(a);
            }
        }
    } else {
        script::inspect_layers(&data, &mut report, &budget, &mut |_r, _layer, _text| {
            #[cfg(feature = "yara")]
            if let Some(run) = yara.as_mut() {
                run.scan(_r, _layer, _text.as_bytes(), &budget);
            }
        });
    }
    #[cfg(feature = "yara")]
    if let Some(summary) = cached {
        // Same file bytes, rule set and engine: replay the stored evidence.
        report.analyzer("yara_cache");
        for m in &summary.matches {
            let id = if m.rule_id.is_empty() {
                &m.rule
            } else {
                &m.rule_id
            };
            if m.in_comment_only {
                report.add(
                    "yara_rule_match_in_comment",
                    5,
                    format!("yara:{id}@{}", m.layer),
                    "A YARA rule matched only text inside comments, which is not executed",
                );
            } else {
                report.add(
                    "yara_rule_match",
                    m.severity,
                    format!("yara:{id}@{}", m.layer),
                    "A YARA rule matched; see yara.matches for evidence",
                );
            }
        }
        report.yara = Some(summary);
    } else if let Some(run) = yara {
        let summary = run.finish();
        // Only complete analyses are cached; a timeout is never replayed.
        if report.analysis_complete {
            if let (Some(cache), Some(sha)) = (engines.yara_cache, report.sha256.as_deref()) {
                cache.borrow_mut().insert(sha, &summary);
            }
        }
        report.yara = Some(summary);
    }
    report.finish();
    report
}

/// A directory entry that could not be enumerated. Emitted as a report so the
/// unreached part of the tree is visible in JSONL instead of only on stderr.
fn walk_error_report(root: &Path, error: &walkdir::Error) -> Report {
    let path = error.path().unwrap_or(root);
    let mut report = Report::new(
        path.display().to_string(),
        classify(path).unwrap_or("unknown"),
    );
    report.unavailable("unreadable", "walk_failed", error.to_string());
    report
}

/// Upper bounds for one `scan` invocation. Every limit is finite by default;
/// reaching one stops the scan with an explicit record instead of a silent cut.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub per_file: Duration,
    pub max_files: u64,
    pub max_total_bytes: u64,
    pub max_duration: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            per_file: Duration::from_secs(10),
            max_files: 200_000,
            max_total_bytes: 32 * 1024 * 1024 * 1024,
            max_duration: Duration::from_secs(4 * 3600),
        }
    }
}

#[derive(Default)]
struct Summary {
    analyzed: u64,
    incomplete: u64,
    not_assessed: u64,
    bytes_read: u64,
}

impl Summary {
    fn count(&mut self, report: &Report) {
        match report.assessment {
            Assessment::Analyzed => self.analyzed += 1,
            Assessment::Incomplete => self.incomplete += 1,
            Assessment::NotAssessed => self.not_assessed += 1,
        }
        self.bytes_read = self.bytes_read.saturating_add(report.coverage.bytes_read);
    }

    fn files(&self) -> u64 {
        self.analyzed + self.incomplete + self.not_assessed
    }

    /// Why the scan must stop before the next file, if it must.
    fn stop_reason(&self, limits: &Limits, run: &Budget) -> Option<&'static str> {
        if budget::cancelled() {
            Some("scan_cancelled")
        } else if run.exceeded().is_some() {
            Some("scan_time_limit")
        } else if self.files() >= limits.max_files {
            Some("scan_file_limit")
        } else if self.bytes_read >= limits.max_total_bytes {
            Some("scan_byte_limit")
        } else {
            None
        }
    }
}

/// Stands for every entry under `root` that was not reached.
fn stopped_report(root: &Path, reason: &'static str) -> Report {
    let mut report = Report::new(root.display().to_string(), "unknown");
    report.unavailable(
        "scan_stopped",
        reason,
        "The scan stopped early; remaining entries under this path were not assessed",
    );
    report
}

pub fn run(
    path: &Path,
    recursive: bool,
    mut log: Option<JsonlLog>,
    limits: Limits,
    engines: Engines,
) -> Result<()> {
    // Ctrl-C finishes the current bounded unit, records the stop and exits.
    let _ = ctrlc::set_handler(budget::cancel);
    let mut summary = Summary::default();
    if path.is_file() || path.is_symlink() {
        emit(
            scan_file(path, limits.per_file, engines),
            &mut log,
            &mut summary,
        )?;
        print_summary(&summary);
        return Ok(());
    }
    if !path.is_dir() {
        return Err(format!("Path does not exist or is not readable: {}", path.display()).into());
    }

    let run_budget = Budget::new(limits.max_duration);
    let max_depth = if recursive { usize::MAX } else { 1 };
    let mut stopped = None;
    for entry in WalkDir::new(path).follow_links(false).max_depth(max_depth) {
        // Symlinks with a target extension are reported as not assessed
        // rather than silently dropped.
        let relevant = entry.as_ref().map_or(true, |e| {
            (e.file_type().is_file() || e.path_is_symlink()) && classify(e.path()).is_some()
        });
        if !relevant {
            continue;
        }
        if let Some(reason) = summary.stop_reason(&limits, &run_budget) {
            stopped = Some(reason);
            break;
        }
        match entry {
            Ok(e) => emit(
                scan_file(e.path(), limits.per_file, engines),
                &mut log,
                &mut summary,
            )?,
            Err(e) => {
                eprintln!("walk error: {e}");
                emit(walk_error_report(path, &e), &mut log, &mut summary)?;
            }
        }
    }
    if let Some(reason) = stopped {
        emit(stopped_report(path, reason), &mut log, &mut summary)?;
    }
    print_summary(&summary);
    match stopped {
        Some(reason) => {
            Err(format!("scan stopped early ({reason}); see the scan_stopped record").into())
        }
        None => Ok(()),
    }
}

fn print_summary(summary: &Summary) {
    eprintln!(
        "summary: analyzed={} incomplete={} not_assessed={} bytes_read={} (no signals is not proof of safety)",
        summary.analyzed, summary.incomplete, summary.not_assessed, summary.bytes_read
    );
}

fn emit(report: Report, log: &mut Option<JsonlLog>, summary: &mut Summary) -> Result<()> {
    summary.count(&report);
    let line = serde_json::to_string(&report)?;
    println!("{line}");
    if let Some(log) = log.as_mut() {
        log.write_line(&line)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::SignalLevel;

    #[test]
    fn supported_extensions_case_insensitive() {
        assert_eq!(classify(Path::new("TEST.PS1")), Some("script"));
        assert_eq!(classify(Path::new("test.DLL")), Some("pe"));
        assert_eq!(classify(Path::new("image.png")), None);
    }

    #[test]
    fn missing_file_cannot_be_called_clean() {
        let report = scan_file(
            Path::new("aegisguard_missing_1234.ps1"),
            Limits::default().per_file,
            Engines::default(),
        );
        assert_eq!(report.risk, "not_assessed");
        assert_eq!(report.assessment, Assessment::NotAssessed);
        assert_eq!(report.signal_level, SignalLevel::NotEvaluated);
        assert_eq!(report.not_assessed_reason, Some("metadata_failed"));
        assert!(report.file_identity.is_none());
    }

    #[test]
    fn unsupported_type_is_not_assessed() {
        let report = scan_file(
            Path::new("notes.txt"),
            Limits::default().per_file,
            Engines::default(),
        );
        assert_eq!(report.status, "unsupported");
        assert_eq!(report.not_assessed_reason, Some("unsupported_file_type"));
        assert!(report.coverage.analyzers.is_empty());
    }
}
