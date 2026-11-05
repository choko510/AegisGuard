use serde_json::Value;
#[cfg(not(windows))]
use serde_json::json;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use windows_posture::{error_report, evaluate, MAX_FIXTURE_BYTES};

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn read_fixture(path: &OsStr) -> Result<Value, &'static str> {
    let path = Path::new(path);
    let metadata = fs::symlink_metadata(path).map_err(|_| "fixture_unreadable")?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("fixture_not_regular_file");
    }
    if metadata.len() > MAX_FIXTURE_BYTES {
        return Err("fixture_too_large");
    }
    let file = File::open(path).map_err(|_| "fixture_unreadable")?;
    let mut bytes = Vec::new();
    file.take(MAX_FIXTURE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "fixture_read_failed")?;
    if bytes.len() as u64 > MAX_FIXTURE_BYTES {
        return Err("fixture_too_large");
    }
    serde_json::from_slice(&bytes).map_err(|_| "fixture_invalid_json")
}

fn audit_raw() -> Value {
    #[cfg(windows)]
    {
        windows_posture::windows::collect()
    }
    #[cfg(not(windows))]
    {
        json!({})
    }
}

fn emit(report: &Value) {
    // Only strictly allowlisted fields reach the JSON report. No raw OS errors,
    // identifiers, volume paths, key protectors, or arbitrary fixture text.
    println!("{report}");
}

fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    let timestamp = now_ms();

    let result = if args.len() == 4
        && args[1].to_str() == Some("audit")
        && args[2].to_str() == Some("--format")
        && args[3].to_str() == Some("json")
    {
        let result = evaluate(&audit_raw(), timestamp);
        #[cfg(not(windows))]
        let result = result.map(|mut report| {
            report["warnings"] = json!(["windows_only"]);
            report
        });
        result
    } else if args.len() == 3 && args[1].to_str() == Some("inspect-fixture") {
        read_fixture(&args[2]).and_then(|fixture| evaluate(&fixture, timestamp))
    } else {
        eprintln!("Usage: windows-posture audit --format json | windows-posture inspect-fixture <file>");
        std::process::exit(2);
    };

    match result {
        Ok(report) => {
            let code = if report["status"] == "complete" { 0 } else { 1 };
            emit(&report);
            std::process::exit(code);
        }
        Err(error_code) => {
            eprintln!("Inspection failed: {error_code}");
            emit(&error_report(timestamp, "invalid_fixture_or_probe"));
            std::process::exit(2);
        }
    }
}
