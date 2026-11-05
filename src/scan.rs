use crate::model::{Assessment, FileIdentity, Report};
use crate::{pe, script, Result};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
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

pub fn scan_file(path: &Path) -> Report {
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

    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            report.unavailable("unreadable", "open_failed", e.to_string());
            return report;
        }
    };
    if let Ok(handle_meta) = file.metadata() {
        report.file_identity = Some(FileIdentity::from_metadata(&handle_meta, "handle_metadata"));
    }
    let mut data = Vec::new();
    let read = file.take(limit + 1).read_to_end(&mut data);
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

    report.sha256 = Some(hex::encode(Sha256::digest(&data)));
    if kind == "pe" {
        pe::inspect(&data, &mut report);
    } else {
        script::inspect(&data, &mut report);
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

#[derive(Default)]
struct Summary {
    analyzed: usize,
    incomplete: usize,
    not_assessed: usize,
}

impl Summary {
    fn count(&mut self, report: &Report) {
        match report.assessment {
            Assessment::Analyzed => self.analyzed += 1,
            Assessment::Incomplete => self.incomplete += 1,
            Assessment::NotAssessed => self.not_assessed += 1,
        }
    }
}

pub fn run(path: &Path, recursive: bool, output: Option<&Path>) -> Result<()> {
    let mut log: Option<File> = if let Some(destination) = output {
        if let Some(parent) = destination.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        Some(
            OpenOptions::new()
                .append(true)
                .create(true)
                .open(destination)?,
        )
    } else {
        None
    };
    let mut summary = Summary::default();
    if path.is_file() || path.is_symlink() {
        emit(scan_file(path), &mut log, &mut summary)?;
        print_summary(&summary);
        return Ok(());
    }
    if !path.is_dir() {
        return Err(format!("Path does not exist or is not readable: {}", path.display()).into());
    }

    let max_depth = if recursive { usize::MAX } else { 1 };
    for entry in WalkDir::new(path).follow_links(false).max_depth(max_depth) {
        match entry {
            Ok(e) => {
                // Symlinks with a target extension are reported as not assessed
                // rather than silently dropped.
                let candidate = e.file_type().is_file() || e.path_is_symlink();
                if candidate && classify(e.path()).is_some() {
                    emit(scan_file(e.path()), &mut log, &mut summary)?;
                }
            }
            Err(e) => {
                eprintln!("walk error: {e}");
                emit(walk_error_report(path, &e), &mut log, &mut summary)?;
            }
        }
    }
    print_summary(&summary);
    Ok(())
}

fn print_summary(summary: &Summary) {
    eprintln!(
        "summary: analyzed={} incomplete={} not_assessed={} (no signals is not proof of safety)",
        summary.analyzed, summary.incomplete, summary.not_assessed
    );
}

fn emit(report: Report, log: &mut Option<File>, summary: &mut Summary) -> Result<()> {
    summary.count(&report);
    let line = serde_json::to_string(&report)?;
    println!("{line}");
    if let Some(file) = log.as_mut() {
        writeln!(file, "{line}")?;
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
        let report = scan_file(Path::new("aegisguard_missing_1234.ps1"));
        assert_eq!(report.risk, "not_assessed");
        assert_eq!(report.assessment, Assessment::NotAssessed);
        assert_eq!(report.signal_level, SignalLevel::NotEvaluated);
        assert_eq!(report.not_assessed_reason, Some("metadata_failed"));
        assert!(report.file_identity.is_none());
    }

    #[test]
    fn unsupported_type_is_not_assessed() {
        let report = scan_file(Path::new("notes.txt"));
        assert_eq!(report.status, "unsupported");
        assert_eq!(report.not_assessed_reason, Some("unsupported_file_type"));
        assert!(report.coverage.analyzers.is_empty());
    }
}
