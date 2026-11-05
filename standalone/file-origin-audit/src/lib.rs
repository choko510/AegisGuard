//! Standalone, no-network, read-only file origin evidence module.
mod parser;
#[cfg(windows)]
mod windows;

use std::fs::{self, File};
use std::io::Read;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub use parser::MAX_STREAM_BYTES;

/// A non-privileged abstraction that permits safe tests without Windows or ADS.
#[derive(Debug)]
pub enum Evidence {
    Stream(Vec<u8>),
    Absent,
    NotSupported,
    PermissionDenied,
    Error(&'static str),
}

pub struct Report {
    pub status: &'static str,
    pub coverage: &'static str,
    pub zone_id: Option<u8>,
    pub zone_name: Option<&'static str>,
    pub motw_present: Option<bool>,
    pub source_url_recorded: bool,
    pub referrer_url_recorded: bool,
    pub warnings: Vec<&'static str>,
    pub probe: &'static str,
    pub generated_at_unix_ms: u128,
}

pub fn assess(evidence: Evidence, probe: &'static str) -> Report {
    let mut report = Report {
        status: "error",
        coverage: "error",
        zone_id: None,
        zone_name: None,
        motw_present: None,
        source_url_recorded: false,
        referrer_url_recorded: false,
        warnings: vec![],
        probe,
        generated_at_unix_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_millis()),
    };
    match evidence {
        Evidence::Stream(bytes) => {
            report.status = "present";
            report.motw_present = Some(true);
            let parsed = parser::parse(&bytes);
            report.zone_id = parsed.zone_id;
            report.zone_name = parsed.zone_id.map(parser::zone_name);
            report.source_url_recorded = parsed.source_url_recorded;
            report.referrer_url_recorded = parsed.referrer_url_recorded;
            report.warnings = parsed.warnings;
            report.coverage = if parsed.complete && parsed.zone_id.is_some() {
                "complete"
            } else {
                "partial"
            };
            report.warnings.push("metadata_is_untrusted");
        }
        Evidence::Absent => {
            report.status = "absent";
            report.coverage = "complete";
            report.motw_present = Some(false);
            report.warnings.push("absence_does_not_imply_safety");
        }
        Evidence::NotSupported => {
            report.status = "not_supported";
            report.coverage = "unavailable";
            report.warnings.push("named_streams_unavailable");
        }
        Evidence::PermissionDenied => {
            report.status = "permission_denied";
            report.coverage = "permission_denied";
            report.warnings.push("access_denied");
        }
        Evidence::Error(code) => {
            report.status = "error";
            report.coverage = "error";
            report.warnings.push(code);
        }
    }
    report
}

fn json_string(value: &str) -> String {
    let mut escaped = String::from("\"");
    for c in value.chars() {
        match c {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            c if c <= '\u{001f}' => escaped.push_str(&format!("\\u{:04x}", c as u32)),
            c => escaped.push(c),
        }
    }
    escaped.push('"');
    escaped
}

impl Report {
    pub fn to_json(&self) -> String {
        let zone_id = self.zone_id.map_or("null".to_owned(), |id| id.to_string());
        let zone_name = self.zone_name.map_or("null".to_owned(), json_string);
        let present = self
            .motw_present
            .map_or("null", |p| if p { "true" } else { "false" });
        let warnings = self
            .warnings
            .iter()
            .map(|s| json_string(s))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            concat!(
                "{{\"schema_version\":\"1.0.0\",\"module\":\"file-origin-audit\",",
                "\"generated_at_unix_ms\":{},\"status\":{},",
                "\"entries\":[{{\"status\":{},\"motw_present\":{},",
                "\"zone_id\":{},\"zone_name\":{},",
                "\"source_url_recorded\":{},\"referrer_url_recorded\":{},",
                "\"origin_confidence\":\"unverified\",\"probe\":{}}}],",
                "\"warnings\":[{}],\"coverage\":{}}}"
            ),
            self.generated_at_unix_ms,
            json_string(self.status),
            json_string(self.status),
            present,
            zone_id,
            zone_name,
            self.source_url_recorded,
            self.referrer_url_recorded,
            json_string(self.probe),
            warnings,
            json_string(self.coverage),
        )
    }
}

/// Fixture input is harmless stream bytes, NOT a Windows path or an executable.
/// Refuses symlinks and cannot read more than 64 KiB + 1 byte.
pub fn inspect_fixture(path: &Path) -> Report {
    let before = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(e) => return assess(map_fixture_error(e), "fixture"),
    };
    if before.file_type().is_symlink() || !before.is_file() {
        return assess(Evidence::Error("fixture_not_regular_file"), "fixture");
    }
    if before.len() > MAX_STREAM_BYTES as u64 {
        return assess(
            Evidence::Error("stream_size_limit_exceeded"),
            "fixture",
        );
    }
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(e) => return assess(map_fixture_error(e), "fixture"),
    };
    let mut bytes = Vec::new();
    if file
        .by_ref()
        .take((MAX_STREAM_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .is_err()
    {
        return assess(Evidence::Error("fixture_read_failed"), "fixture");
    }
    if bytes.len() > MAX_STREAM_BYTES {
        return assess(Evidence::Error("stream_size_limit_exceeded"), "fixture");
    }
    let after = match file.metadata() {
        Ok(m) => m,
        Err(_) => return assess(Evidence::Error("fixture_stat_failed"), "fixture"),
    };
    let path_after = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(_) => return assess(Evidence::Error("file_changed_during_read"), "fixture"),
    };
    if after.len() != before.len()
        || after.modified().ok() != before.modified().ok()
        || path_after.len() != before.len()
        || path_after.modified().ok() != before.modified().ok()
        || path_after.file_type().is_symlink()
    {
        return assess(Evidence::Error("file_changed_during_read"), "fixture");
    }
    assess(Evidence::Stream(bytes), "fixture")
}

fn map_fixture_error(error: std::io::Error) -> Evidence {
    match error.kind() {
        std::io::ErrorKind::PermissionDenied => Evidence::PermissionDenied,
        _ => Evidence::Error("fixture_unavailable"),
    }
}

#[cfg(windows)]
pub fn inspect(path: &Path) -> Report {
    assess(windows::probe(path), "windows_ads")
}

#[cfg(not(windows))]
pub fn inspect(_path: &Path) -> Report {
    assess(Evidence::NotSupported, "windows_ads")
}
