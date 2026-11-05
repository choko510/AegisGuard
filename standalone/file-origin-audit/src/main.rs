use std::ffi::OsString;
use std::path::Path;
use std::process::ExitCode;

fn usage() -> ExitCode {
    eprintln!("usage: file-origin-audit inspect <path> --format json | inspect-fixture <fixture> [--format json]");
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    if args.len() != 2 && args.len() != 4 {
        return usage();
    }
    let Some(command) = args[0].to_str() else {
        return usage();
    };
    if command != "inspect" && command != "inspect-fixture" {
        return usage();
    }
    if args.len() == 4 && (args[2] != "--format" || args[3] != "json") {
        return usage();
    }
    if args[1].is_empty() {
        return usage();
    }
    let report = if command == "inspect-fixture" {
        file_origin_audit::inspect_fixture(Path::new(&args[1]))
    } else {
        file_origin_audit::inspect(Path::new(&args[1]))
    };
    println!("{}", report.to_json());
    if matches!(report.coverage, "complete" | "partial") {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(3)
    }
}
