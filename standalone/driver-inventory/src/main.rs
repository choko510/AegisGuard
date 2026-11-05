#[cfg(not(windows))]
use driver_inventory::Collection;
use driver_inventory::{error_report, fixture, report, MAX_FIXTURE_BYTES};
use serde_json::Value;
use std::io::Read;

#[cfg(windows)]
mod windows;

fn usage() {
    eprintln!(
        "Usage:\n  driver-inventory list [--drivers-only] --format json [--verify-signatures] [--show-paths]\n  driver-inventory inspect-fixture <file> [--drivers-only] [--show-paths]"
    );
}

#[cfg(windows)]
fn live(drivers_only: bool, verify_signatures: bool, show_paths: bool) -> Value {
    let windows_dir = match windows::windows_directory() {
        Ok(value) => value,
        Err(code) => return error_report(code),
    };
    let started = std::time::Instant::now();
    let mut items = windows::collect(drivers_only, started);
    windows::enrich(&mut items, &windows_dir, verify_signatures, started);
    report(items, drivers_only, show_paths, &windows_dir)
}
#[cfg(not(windows))]
fn live(drivers_only: bool, _verify_signatures: bool, show_paths: bool) -> Value {
    let _ = show_paths;
    report(
        Collection {
            services: Vec::new(),
            enumeration_status: "unavailable",
            error_code: Some("windows_required"),
            pages: 0,
        },
        drivers_only,
        false,
        r"C:\Windows",
    )
}

fn execute(args: &[String]) -> Result<Value, &'static str> {
    let Some(command) = args.first().map(String::as_str) else {
        return Err("missing_command");
    };
    match command {
        "list" => {
            let mut drivers_only = false;
            let mut verify_signatures = false;
            let mut show_paths = false;
            let mut format_seen = false;
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--drivers-only" if !drivers_only => drivers_only = true,
                    "--verify-signatures" if !verify_signatures => verify_signatures = true,
                    "--show-paths" if !show_paths => show_paths = true,
                    "--format" if !format_seen => {
                        if args.get(i + 1).map(String::as_str) != Some("json") {
                            return Err("unsupported_format");
                        }
                        format_seen = true;
                        i += 1;
                    }
                    _ => return Err("invalid_argument"),
                }
                i += 1;
            }
            if !format_seen {
                return Err("format_required");
            }
            Ok(live(drivers_only, verify_signatures, show_paths))
        }
        "inspect-fixture" => {
            if args.len() < 2 {
                return Err("fixture_required");
            }
            let path = &args[1];
            if path.starts_with('-') {
                return Err("invalid_fixture_path");
            }
            let mut drivers_only = false;
            let mut show_paths = false;
            for arg in &args[2..] {
                match arg.as_str() {
                    "--drivers-only" if !drivers_only => drivers_only = true,
                    "--show-paths" if !show_paths => show_paths = true,
                    _ => return Err("invalid_argument"),
                }
            }
            // Read input without executing or probing any fixture path.
            let file = std::fs::File::open(path).map_err(|_| "fixture_open_failed")?;
            let mut bytes = Vec::new();
            file.take(MAX_FIXTURE_BYTES as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| "fixture_read_failed")?;
            if bytes.len() > MAX_FIXTURE_BYTES {
                return Err("fixture_size_limit");
            }
            let collection = fixture(&bytes)?;
            Ok(report(collection, drivers_only, show_paths, r"C:\Windows"))
        }
        _ => Err("unknown_command"),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match execute(&args) {
        Ok(v) => v,
        Err(code) => {
            usage();
            error_report(code)
        }
    };
    let status = result["status"].as_str().unwrap_or("error");
    println!(
        "{}",
        serde_json::to_string_pretty(&result).unwrap_or_else(|_| "{}".into())
    );
    if status != "complete" {
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn list_requires_explicit_json() {
        assert_eq!(execute(&["list".into()]).unwrap_err(), "format_required");
        assert_eq!(
            execute(&["list".into(), "--format".into(), "xml".into()]).unwrap_err(),
            "unsupported_format"
        );
        assert_eq!(
            execute(&[
                "list".into(),
                "--format".into(),
                "json".into(),
                "--unknown".into()
            ])
            .unwrap_err(),
            "invalid_argument"
        );
    }
    #[test]
    fn missing_fixture_fails_without_path_leak() {
        let err =
            execute(&["inspect-fixture".into(), "this/path/does/not/exist".into()]).unwrap_err();
        let x = error_report(err);
        assert_eq!(x["status"], "error");
        assert!(!x.to_string().contains("this/path"));
    }
}
