use crate::model::Report;
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
        report.unavailable("unsupported", "File type is not a configured scan target");
        return report;
    }

    // Do not scan a symlink observed at initial metadata inspection.
    // This is not an atomic no-follow open; production Windows service must
    // additionally defend against path swaps/reparse points.
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) => {
            report.unavailable("unreadable", e.to_string());
            return report;
        }
    };
    if meta.file_type().is_symlink() || !meta.is_file() {
        report.unavailable("unreadable", "Not a regular file or is a symlink");
        return report;
    }
    let limit = if kind == "pe" {
        MAX_PE_BYTES
    } else {
        MAX_SCRIPT_BYTES
    };
    if meta.len() > limit {
        report.unavailable(
            "oversized_no_deep_scan",
            "Size exceeds the configured deep-scan limit",
        );
        return report;
    }

    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            report.unavailable("unreadable", e.to_string());
            return report;
        }
    };
    let mut data = Vec::new();
    if let Err(e) = file.take(limit + 1).read_to_end(&mut data) {
        report.unavailable("unreadable", e.to_string());
        return report;
    }
    if data.len() as u64 > limit {
        report.unavailable("oversized_no_deep_scan", "File grew past the scan limit");
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
    if path.is_file() || path.is_symlink() {
        emit(scan_file(path), &mut log)?;
        return Ok(());
    }
    if !path.is_dir() {
        return Err(format!("Path does not exist or is not readable: {}", path.display()).into());
    }

    let max_depth = if recursive { usize::MAX } else { 1 };
    for entry in WalkDir::new(path).follow_links(false).max_depth(max_depth) {
        match entry {
            Ok(e) => {
                if e.file_type().is_file() && classify(e.path()).is_some() {
                    emit(scan_file(e.path()), &mut log)?;
                }
            }
            Err(e) => eprintln!("walk error: {e}"),
        }
    }
    Ok(())
}

fn emit(report: Report, log: &mut Option<File>) -> Result<()> {
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
    }
}
