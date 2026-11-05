use privacy_audit::{audit_path, exit_code, self_test, Mode};
use serde_json::json;
use std::path::PathBuf;

fn usage() {
    println!("privacy-audit check --input <jsonl-or-log> --format json [--mode auto|jsonl|log]");
    println!("privacy-audit self-test");
}

fn invalid_arguments() -> ! {
    let output = json!({
        "schema_version": 1,
        "module": "privacy-audit",
        "generated_at_unix_ms": 0,
        "status": "error",
        "entries": [],
        "warnings": ["invalid_arguments"],
        "coverage": {"complete": false}
    });
    println!("{output}");
    std::process::exit(3)
}

fn main() {
    let mut args = std::env::args_os().skip(1);
    let Some(command) = args.next().and_then(|v| v.into_string().ok()) else {
        invalid_arguments();
    };
    match command.as_str() {
        "--help" | "-h" | "help" => {
            usage();
        }
        "self-test" => {
            if args.next().is_some() {
                invalid_arguments();
            }
            let output = self_test();
            let code = exit_code(&output);
            println!("{output}");
            std::process::exit(code);
        }
        "check" => {
            let mut input: Option<PathBuf> = None;
            let mut mode = Mode::Auto;
            let mut format_set = false;
            while let Some(raw_key) = args.next() {
                let Ok(key) = raw_key.into_string() else {
                    invalid_arguments();
                };
                match key.as_str() {
                    "--input" if input.is_none() => {
                        input = Some(PathBuf::from(
                            args.next().unwrap_or_else(|| invalid_arguments()),
                        ));
                    }
                    "--format" if !format_set => {
                        let Some(value) = args.next().and_then(|v| v.into_string().ok()) else {
                            invalid_arguments();
                        };
                        if value != "json" {
                            invalid_arguments();
                        }
                        format_set = true;
                    }
                    "--mode" => {
                        let Some(value) = args.next().and_then(|v| v.into_string().ok()) else {
                            invalid_arguments();
                        };
                        mode = Mode::parse(&value).unwrap_or_else(|| invalid_arguments());
                    }
                    _ => invalid_arguments(),
                }
            }
            let Some(path) = input else {
                invalid_arguments();
            };
            let output = audit_path(&path, mode);
            let code = exit_code(&output);
            println!("{output}");
            std::process::exit(code);
        }
        _ => invalid_arguments(),
    }
}
