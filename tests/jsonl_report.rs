//! End-to-end checks of the `scan` JSONL contract using harmless fixtures only.
//! Nothing here executes a fixture; the CLI reads them as bytes.
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const FIXTURES: &str = "tests/fixtures/scan";
const GOLDEN: &str = "tests/golden/scan_fixtures_v2.json";
const V1_RISKS: [&str; 5] = ["low_signal", "incomplete", "review", "high", "not_assessed"];
const V1_STATUSES: [&str; 6] = [
    "analyzed",
    "incomplete",
    "unsupported",
    "unreadable",
    "oversized_no_deep_scan",
    "invalid_pe",
];

struct Run {
    reports: Vec<Value>,
    stdout: String,
    stderr: String,
}

fn scan(args: &[&str]) -> Run {
    let out = Command::new(env!("CARGO_BIN_EXE_aegisguard"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .arg("scan")
        .args(args)
        .output()
        .expect("run aegisguard");
    assert!(out.status.success(), "scan failed: {out:?}");
    let stdout = String::from_utf8(out.stdout).unwrap();
    let reports = stdout
        .lines()
        .map(|line| serde_json::from_str(line).expect("each stdout line is one JSON report"))
        .collect();
    Run {
        reports,
        stdout,
        stderr: String::from_utf8(out.stderr).unwrap(),
    }
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("aegisguard-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Replace values that legitimately differ between runs and platforms.
fn normalize(mut report: Value) -> Value {
    let path = report["path"].as_str().unwrap().replace('\\', "/");
    report["path"] = path.into();
    report["started_at_unix_ms"] = "<volatile>".into();
    report["completed_at_unix_ms"] = "<volatile>".into();
    if let Some(identity) = report["file_identity"].as_object_mut() {
        identity.insert("modified_unix_ms".into(), "<volatile>".into());
    }
    report
}

fn assert_v1_compatible(report: &Value) {
    let r = report.as_object().expect("report is an object");
    for key in ["path", "kind", "status", "risk"] {
        assert!(r[key].is_string(), "{key} must stay a string: {report}");
    }
    assert!(r["sha256"].is_string() || r["sha256"].is_null());
    assert!(r["warning"].is_string() || r["warning"].is_null());
    assert!(r["score"].as_u64().is_some_and(|s| s <= 100));
    assert!(r["decoded_layers"].is_u64());
    assert!(r["analysis_complete"].is_boolean());
    assert!(r["incomplete_reasons"]
        .as_array()
        .unwrap()
        .iter()
        .all(Value::is_string));
    for signal in r["signals"].as_array().unwrap() {
        assert!(signal["code"].is_string() && signal["source"].is_string());
        assert!(signal["severity"].is_u64() && signal["reason"].is_string());
    }
    assert!(V1_RISKS.contains(&r["risk"].as_str().unwrap()));
    assert!(V1_STATUSES.contains(&r["status"].as_str().unwrap()));
}

/// The safety contract: a partial or failed analysis never reads as a negative result.
fn assert_completeness_contract(report: &Value) {
    let assessment = report["assessment"].as_str().unwrap();
    let complete = report["analysis_complete"].as_bool().unwrap();
    assert_eq!(complete, assessment == "analyzed", "{report}");
    if report["risk"] == "low_signal" {
        assert_eq!(assessment, "analyzed", "{report}");
    }
    match assessment {
        "analyzed" => assert!(report["not_assessed_reason"].is_null()),
        "incomplete" => {
            assert!(!report["incomplete_reasons"].as_array().unwrap().is_empty());
            assert_ne!(report["risk"], "low_signal");
        }
        "not_assessed" => {
            assert!(report["not_assessed_reason"].is_string(), "{report}");
            assert_eq!(report["risk"], "not_assessed");
        }
        other => panic!("unknown assessment {other}"),
    }
}

#[test]
fn fixture_reports_match_golden() {
    let mut actual: Vec<Value> = scan(&[FIXTURES])
        .reports
        .into_iter()
        .map(normalize)
        .collect();
    actual.sort_by(|a, b| a["path"].as_str().cmp(&b["path"].as_str()));
    let actual = Value::Array(actual);
    let golden = Path::new(env!("CARGO_MANIFEST_DIR")).join(GOLDEN);
    if std::env::var_os("AEGISGUARD_UPDATE_GOLDEN").is_some() {
        fs::write(
            &golden,
            serde_json::to_string_pretty(&actual).unwrap() + "\n",
        )
        .unwrap();
    }
    let expected: Value = serde_json::from_str(&fs::read_to_string(&golden).unwrap()).unwrap();
    assert_eq!(
        actual,
        expected,
        "golden mismatch; actual:\n{}",
        serde_json::to_string_pretty(&actual).unwrap()
    );
}

#[test]
fn every_report_stays_readable_by_v1_consumers() {
    let run = scan(&[FIXTURES]);
    assert_eq!(run.reports.len(), 4);
    for report in &run.reports {
        assert_v1_compatible(report);
        assert_completeness_contract(report);
    }
}

#[test]
fn report_never_contains_sample_content() {
    let run = scan(&[FIXTURES]);
    for needle in [
        "AEGIS-SYNTHETIC-SECRET",
        "collector.example.invalid",
        "Login Data",
        "requests.post",
        "VAL0=test",
    ] {
        assert!(!run.stdout.contains(needle), "stdout leaked {needle}");
        assert!(!run.stderr.contains(needle), "stderr leaked {needle}");
    }
}

#[test]
fn output_file_matches_stdout_and_appends() {
    let dir = temp_dir("output");
    let log = dir.join("reports").join("scan.jsonl");
    let log_arg = log.to_str().unwrap();
    let first = scan(&[FIXTURES, "--output", log_arg]);
    let second = scan(&[FIXTURES, "--output", log_arg]);
    let written = fs::read_to_string(&log).unwrap();
    assert_eq!(written.lines().count(), 8);
    assert!(written.starts_with(first.stdout.lines().next().unwrap()));
    assert!(written.ends_with(&second.stdout));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn unsupported_single_file_is_not_assessed() {
    let run = scan(&[&format!("{FIXTURES}/notes.txt")]);
    let report = &run.reports[0];
    assert_v1_compatible(report);
    assert_completeness_contract(report);
    assert_eq!(report["not_assessed_reason"], "unsupported_file_type");
    assert!(report["file_identity"].is_null());
}

#[test]
fn oversized_script_is_not_assessed_without_reading_it() {
    let dir = temp_dir("oversized");
    let path = dir.join("large.ps1");
    fs::write(&path, vec![b' '; 4 * 1024 * 1024 + 1]).unwrap();
    let run = scan(&[path.to_str().unwrap()]);
    let report = &run.reports[0];
    assert_completeness_contract(report);
    assert_eq!(report["status"], "oversized_no_deep_scan");
    assert_eq!(report["not_assessed_reason"], "size_limit_exceeded");
    assert_eq!(report["coverage"]["bytes_read"], 0);
    assert_eq!(report["file_identity"]["size_bytes"], 4 * 1024 * 1024 + 1);
    assert!(report["sha256"].is_null());
    assert!(run.stderr.contains("not_assessed=1"));
    fs::remove_dir_all(dir).unwrap();
}

#[cfg(unix)]
#[test]
fn symlinks_and_unreadable_directories_are_reported_not_dropped() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let dir = temp_dir("walk");
    fs::write(dir.join("real.py"), "print('x')\n").unwrap();
    symlink(dir.join("real.py"), dir.join("link.py")).unwrap();
    let locked = dir.join("locked");
    fs::create_dir(&locked).unwrap();
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
    // Root can read a 0o000 directory; only assert the walk error when it applies.
    let enforced = fs::read_dir(&locked).is_err();

    let run = scan(&[dir.to_str().unwrap(), "--recursive"]);
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
    fs::remove_dir_all(&dir).unwrap();

    let reason = |r: &Value| r["not_assessed_reason"].as_str().map(str::to_owned);
    let reasons: Vec<_> = run.reports.iter().filter_map(reason).collect();
    assert!(reasons.contains(&"symlink_not_followed".to_owned()));
    if enforced {
        assert!(reasons.contains(&"walk_failed".to_owned()));
    }
    for report in &run.reports {
        assert_v1_compatible(report);
        assert_completeness_contract(report);
    }
}
