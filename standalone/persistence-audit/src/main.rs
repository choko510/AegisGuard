use persistence_audit::{
    failure_report, inspect_records, DEFAULT_LIMIT, MAX_CAPTURE_BYTES, MAX_LIMIT,
};
#[cfg(windows)]
use persistence_audit::mark_partial;
use serde_json::Value;
use std::env;
use std::fs::File;
use std::io::{self, Read};
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let (report, argument_error) = match run(&args) {
        Ok(value) => (value, false),
        Err(_) => (
            failure_report(false, "error", "invalid_arguments_or_fixture"),
            true,
        ),
    };
    // Output is always a versioned JSON object. No raw OS error text or input.
    match serde_json::to_string_pretty(&report) {
        Ok(text) => println!("{text}"),
        Err(_) => return ExitCode::from(2),
    }
    if argument_error || report["status"] == "error" {
        ExitCode::from(2)
    } else if report["status"] == "complete" {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

fn run(args: &[String]) -> Result<Value, ()> {
    match args.first().map(String::as_str) {
        Some("scan") => {
            let mut limit = DEFAULT_LIMIT;
            let mut include_wmi = false;
            let mut i = 1usize;
            while i < args.len() {
                match args[i].as_str() {
                    "--include-wmi" if !include_wmi => include_wmi = true,
                    "--format" if i + 1 < args.len() && args[i + 1] == "json" => i += 1,
                    "--limit" if i + 1 < args.len() => {
                        i += 1;
                        limit = parse_limit(&args[i])?;
                    }
                    _ => return Err(()),
                }
                i += 1;
            }
            #[cfg(windows)]
            {
                match persistence_audit::windows::collect(limit, include_wmi) {
                    Ok(capture) => {
                        let mut report = inspect_records(&capture.bytes, include_wmi, limit);
                        if let Some(code) = capture.failure {
                            mark_partial(&mut report, code);
                        }
                        Ok(report)
                    }
                    Err(code) => Ok(failure_report(include_wmi, "unavailable", code)),
                }
            }
            #[cfg(not(windows))]
            {
                let _ = (limit, include_wmi);
                Ok(failure_report(include_wmi, "unavailable", "windows_only"))
            }
        }
        Some("inspect-fixture") if args.len() >= 2 => {
            let mut limit = DEFAULT_LIMIT;
            let mut include_wmi = false;
            let mut i = 2usize;
            while i < args.len() {
                match args[i].as_str() {
                    "--include-wmi" if !include_wmi => include_wmi = true,
                    "--limit" if i + 1 < args.len() => {
                        i += 1;
                        limit = parse_limit(&args[i])?;
                    }
                    _ => return Err(()),
                }
                i += 1;
            }
            let data = read_bounded(&args[1]).map_err(|_| ())?;
            Ok(inspect_records(&data, include_wmi, limit))
        }
        _ => Err(()),
    }
}

fn parse_limit(s: &str) -> Result<usize, ()> {
    let n = s.parse::<usize>().map_err(|_| ())?;
    if (1..=MAX_LIMIT).contains(&n) {
        Ok(n)
    } else {
        Err(())
    }
}

fn read_bounded(path: &str) -> io::Result<Vec<u8>> {
    let file = File::open(path)?;
    let mut reader = file.take((MAX_CAPTURE_BYTES + 1) as u64);
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes)?;
    if bytes.len() > MAX_CAPTURE_BYTES {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "fixture_too_large"));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_limits() {
        assert!(parse_limit("0").is_err());
        assert!(parse_limit("2001").is_err());
        assert!(parse_limit("1").is_ok());
        assert!(parse_limit("2000").is_ok());
        assert!(parse_limit("2x").is_err());
    }

    #[test]
    fn rejects_unsupported_commands() {
        assert!(run(&["delete".into()]).is_err());
        assert!(run(&["scan".into(), "--format".into(), "yaml".into()]).is_err());
        assert!(run(&["scan".into(), "--limit".into(), "0".into()]).is_err());
    }
}
