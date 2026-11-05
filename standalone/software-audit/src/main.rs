use software_audit::{inspect_fixture_bytes, inventory, match_bytes, model, read_bounded};
use std::path::Path;

fn usage() -> String {
    "usage: software-audit inventory --format json | match --inventory <json> --advisories <local.json> | inspect-fixture <file>".into()
}
fn run(args: &[String]) -> Result<(serde_json::Value, bool), String> {
    match args {
        [command, flag, format]
            if command == "inventory" && flag == "--format" && format == "json" =>
        {
            let report = inventory::inventory();
            let ok = report.status == "complete";
            Ok((
                serde_json::to_value(report).map_err(|_| "serialization error")?,
                ok,
            ))
        }
        [command, inv, inv_path, adv, adv_path]
            if command == "match" && inv == "--inventory" && adv == "--advisories" =>
        {
            let inventory = read_bounded(Path::new(inv_path), 1024 * 1024)?;
            let advisories = read_bounded(Path::new(adv_path), 2 * 1024 * 1024)?;
            let report = match_bytes(&inventory, &advisories, model::now_ms())?;
            let ok = report.status == "complete";
            Ok((
                serde_json::to_value(report).map_err(|_| "serialization error")?,
                ok,
            ))
        }
        [command, path] if command == "inspect-fixture" => {
            let file = read_bounded(Path::new(path), 1024 * 1024)?;
            let report = inspect_fixture_bytes(&file)?;
            let ok = report.status == "complete";
            Ok((
                serde_json::to_value(report).map_err(|_| "serialization error")?,
                ok,
            ))
        }
        _ => Err(usage()),
    }
}
fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let (report, ok) = match run(&args) {
        Ok(value) => value,
        Err(reason) => {
            eprintln!("software-audit: {reason}");
            (
                serde_json::json!({
                    "schema_version": model::SCHEMA_VERSION,
                    "module": "software-audit",
                    "generated_at_unix_ms": model::now_ms(),
                    "status": "error",
                    "entries": [],
                    "warnings": [reason],
                    "coverage": {"scope":"none", "sources":[], "skipped":0, "truncated":false, "evaluated":0}
                }),
                false,
            )
        }
    };
    match serde_json::to_string_pretty(&report) {
        Ok(text) => println!("{text}"),
        Err(_) => {
            eprintln!("software-audit: output serialization failed");
            std::process::exit(2);
        }
    }
    if !ok {
        std::process::exit(3);
    }
}
