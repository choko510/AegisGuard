//! End-to-end checks of the `scan` JSONL contract using harmless fixtures only.
//! Nothing here executes a fixture; the CLI reads them as bytes.
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const FIXTURES: &str = "tests/fixtures/scan";
const GOLDEN: &str = "tests/golden/scan_fixtures_v2.json";
const V1_RISKS: [&str; 5] = ["low_signal", "incomplete", "review", "high", "not_assessed"];
// v1 statuses plus `scan_stopped`, added with run-level budgets.
const V1_STATUSES: [&str; 7] = [
    "scan_stopped",
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
    let (run, success) = scan_allowing_failure(args);
    assert!(success, "scan failed: {}", run.stderr);
    run
}

fn scan_allowing_failure(args: &[&str]) -> (Run, bool) {
    let out = Command::new(env!("CARGO_BIN_EXE_aegisguard"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .arg("scan")
        .args(args)
        .output()
        .expect("run aegisguard");
    let stdout = String::from_utf8(out.stdout).unwrap();
    let reports = stdout
        .lines()
        .map(|line| serde_json::from_str(line).expect("each stdout line is one JSON report"))
        .collect();
    let run = Run {
        reports,
        stdout,
        stderr: String::from_utf8(out.stderr).unwrap(),
    };
    (run, out.status.success())
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
        for key in ["modified_unix_ms", "device_id", "file_id"] {
            identity.insert(key.into(), "<volatile>".into());
        }
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

#[test]
fn handle_identity_is_recorded_and_stable_across_scans() {
    let target = format!("{FIXTURES}/benign.py");
    let first = &scan(&[&target]).reports[0];
    let second = &scan(&[&target]).reports[0];
    let identity = &first["file_identity"];
    assert_eq!(identity["observed_via"], "handle_metadata");
    assert!(identity["device_id"].is_u64() && identity["file_id"].is_u64());
    assert!(identity["link_count"].as_u64().is_some_and(|n| n >= 1));
    assert_eq!(identity["device_id"], second["file_identity"]["device_id"]);
    assert_eq!(identity["file_id"], second["file_identity"]["file_id"]);
}

#[cfg(unix)]
#[test]
fn unreadable_file_is_not_assessed() {
    use std::os::unix::fs::PermissionsExt;
    let dir = temp_dir("denied");
    let path = dir.join("denied.py");
    fs::write(&path, "print(1)\n").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
    let enforced = fs::File::open(&path).is_err();
    let run = scan(&[path.to_str().unwrap()]);
    fs::remove_dir_all(&dir).unwrap();
    let report = &run.reports[0];
    assert_completeness_contract(report);
    if enforced {
        assert_eq!(report["not_assessed_reason"], "open_failed");
    }
}

#[test]
fn file_limit_stops_with_explicit_record_and_failure_exit() {
    let (run, success) = scan_allowing_failure(&[FIXTURES, "--max-files", "2"]);
    assert!(!success, "a stopped scan must not exit successfully");
    assert_eq!(run.reports.len(), 3);
    let stop = run.reports.last().unwrap();
    assert_eq!(stop["status"], "scan_stopped");
    assert_eq!(stop["not_assessed_reason"], "scan_file_limit");
    for report in &run.reports {
        assert_v1_compatible(report);
        assert_completeness_contract(report);
    }
}

#[test]
fn byte_limit_stops_the_scan() {
    let (run, success) = scan_allowing_failure(&[FIXTURES, "--max-total-bytes", "1"]);
    assert!(!success);
    let stop = run.reports.last().unwrap();
    assert_eq!(stop["not_assessed_reason"], "scan_byte_limit");
}

#[test]
fn zero_time_budget_never_reads_as_clean() {
    let run = scan(&[FIXTURES, "--file-time-limit-ms", "0"]);
    for report in &run.reports {
        assert_completeness_contract(report);
        assert_ne!(report["assessment"], "analyzed", "{report}");
    }
    assert!(run.reports.iter().any(|r| r["incomplete_reasons"]
        .as_array()
        .unwrap()
        .contains(&"analysis_time_limit".into())));
}

#[test]
fn limits_not_reached_exit_successfully_without_stop_record() {
    let run = scan(&[FIXTURES, "--max-files", "4"]);
    assert!(run.reports.iter().all(|r| r["status"] != "scan_stopped"));
}

#[test]
fn output_refuses_unrelated_files_and_rotates_its_own() {
    let dir = temp_dir("rotation");
    let foreign = dir.join("notes.txt");
    fs::write(&foreign, "keep\n").unwrap();
    let (_, success) = scan_allowing_failure(&[FIXTURES, "--output", foreign.to_str().unwrap()]);
    assert!(!success);
    assert_eq!(fs::read_to_string(&foreign).unwrap(), "keep\n");

    let log = dir.join("scan.jsonl");
    let log_arg = log.to_str().unwrap();
    for _ in 0..3 {
        scan(&[
            FIXTURES,
            "--output",
            log_arg,
            "--output-max-bytes",
            "4096",
            "--output-generations",
            "2",
        ]);
    }
    let rotated = dir.join("scan.jsonl.1");
    assert!(rotated.exists());
    assert!(!dir.join("scan.jsonl.3").exists());
    for file in [&log, &rotated] {
        for line in fs::read_to_string(file).unwrap().lines() {
            let report: Value = serde_json::from_str(line).unwrap();
            assert_v1_compatible(&report);
        }
    }
    fs::remove_dir_all(dir).unwrap();
}

#[cfg(feature = "yara")]
#[test]
fn yara_rules_add_evidence_without_leaking_content() {
    let run = scan(&[FIXTURES, "--yara-rules", "rules/aegisguard"]);
    let by_name = |name: &str| {
        run.reports
            .iter()
            .find(|r| r["path"].as_str().unwrap().ends_with(name))
            .unwrap()
            .clone()
    };
    let hit = by_name("credential_reference.py");
    let matches = hit["yara"]["matches"].as_array().unwrap();
    assert!(matches
        .iter()
        .any(|m| m["rule_id"] == "AG-0002" && m["layer"] == "raw"));
    assert_eq!(hit["yara"]["ruleset_sha256"].as_str().unwrap().len(), 64);
    let benign = by_name("benign.py");
    assert_eq!(benign["yara"]["layers_scanned"], 1);
    assert!(benign["yara"]["matches"].as_array().unwrap().is_empty());
    assert_eq!(benign["risk"], "low_signal");
    for report in &run.reports {
        assert_v1_compatible(report);
        assert_completeness_contract(report);
    }
    assert!(!run.stdout.contains("Login Data") && !run.stdout.contains("collector.example"));
}

#[cfg(not(feature = "yara"))]
#[test]
fn yara_request_without_the_feature_fails_closed() {
    let (run, success) = scan_allowing_failure(&[FIXTURES, "--yara-rules", "rules/aegisguard"]);
    assert!(!success);
    assert!(run.reports.is_empty());
}

fn aegisguard(args: &[&str]) -> (String, bool) {
    let out = Command::new(env!("CARGO_BIN_EXE_aegisguard"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(args)
        .output()
        .expect("run aegisguard");
    (String::from_utf8(out.stdout).unwrap(), out.status.success())
}

#[cfg(feature = "yara")]
#[test]
fn signed_rule_pack_lifecycle_through_the_cli() {
    let dir = temp_dir("rulepack-cli");
    let key = dir.join("maintainer");
    let store = dir.join("store");
    let (store_s, pub_s) = (
        store.to_str().unwrap().to_owned(),
        key.with_extension("pub").to_str().unwrap().to_owned(),
    );
    assert!(aegisguard(&["rules", "keygen", key.to_str().unwrap()]).1);
    for sequence in ["1", "2"] {
        let out = dir.join(format!("pack{sequence}"));
        let (_, ok) = aegisguard(&[
            "rules",
            "pack",
            "rules/aegisguard",
            "--key",
            key.with_extension("key").to_str().unwrap(),
            "--sequence",
            sequence,
            "--out",
            out.to_str().unwrap(),
        ]);
        assert!(ok);
        let (stdout, ok) = aegisguard(&[
            "rules",
            "install",
            out.to_str().unwrap(),
            "--trusted-key",
            &pub_s,
            "--store",
            &store_s,
        ]);
        assert!(ok, "{stdout}");
    }
    // Replaying sequence 1 is refused.
    let (_, ok) = aegisguard(&[
        "rules",
        "install",
        dir.join("pack1").to_str().unwrap(),
        "--trusted-key",
        &pub_s,
        "--store",
        &store_s,
    ]);
    assert!(!ok);
    let run = scan(&[FIXTURES, "--rule-store", &store_s, "--trusted-key", &pub_s]);
    assert!(run.reports.iter().any(|r| r["yara"]["matches"]
        .as_array()
        .is_some_and(|m| !m.is_empty())));
    let (stdout, ok) = aegisguard(&[
        "rules",
        "rollback",
        "--trusted-key",
        &pub_s,
        "--store",
        &store_s,
    ]);
    assert!(ok);
    assert!(stdout.contains("\"sequence\":1"));
    // A different key is not trusted.
    let other = dir.join("other");
    assert!(aegisguard(&["rules", "keygen", other.to_str().unwrap()]).1);
    let (run, ok) = scan_allowing_failure(&[
        FIXTURES,
        "--rule-store",
        &store_s,
        "--trusted-key",
        other.with_extension("pub").to_str().unwrap(),
    ]);
    assert!(!ok && run.reports.is_empty());
    fs::remove_dir_all(dir).unwrap();
}

#[cfg(not(feature = "yara"))]
#[test]
fn rule_pack_cannot_be_installed_without_an_engine_to_validate_it() {
    let dir = temp_dir("rulepack-noyara");
    let key = dir.join("k");
    assert!(aegisguard(&["rules", "keygen", key.to_str().unwrap()]).1);
    // Keys are never overwritten.
    assert!(!aegisguard(&["rules", "keygen", key.to_str().unwrap()]).1);
    let out = dir.join("pack");
    assert!(
        aegisguard(&[
            "rules",
            "pack",
            "rules/aegisguard",
            "--key",
            key.with_extension("key").to_str().unwrap(),
            "--sequence",
            "1",
            "--out",
            out.to_str().unwrap(),
        ])
        .1
    );
    let (_, ok) = aegisguard(&[
        "rules",
        "install",
        out.to_str().unwrap(),
        "--trusted-key",
        key.with_extension("pub").to_str().unwrap(),
        "--store",
        dir.join("store").to_str().unwrap(),
    ]);
    assert!(
        !ok,
        "a pack whose rules cannot be compiled must not be installed"
    );
    assert!(!dir.join("store").join("rulepack.json").exists());
    fs::remove_dir_all(dir).unwrap();
}

/// Front ends read CLI output through the library API (P5-01). Every record
/// the CLI writes must come back complete, with the same axes.
#[test]
fn cli_output_reads_back_through_the_typed_api() {
    use aegisguard::api;
    let run = scan(&[FIXTURES, "--recursive"]);
    let out = api::read_scan_jsonl_from(
        run.stdout.as_bytes(),
        api::ReadLimits::default(),
        &std::sync::atomic::AtomicBool::new(false),
    )
    .unwrap();
    assert!(out.complete(), "{:?}", out.problems);
    assert_eq!(out.records.len(), run.reports.len());
    for (typed, raw) in out.records.iter().zip(&run.reports) {
        assert_eq!(typed.path, raw["path"].as_str().unwrap());
        let assessment = serde_json::to_value(typed.assessment()).unwrap();
        assert_eq!(assessment, raw["assessment"]);
        let level = serde_json::to_value(typed.signal_level()).unwrap();
        assert_eq!(level, raw["signal_level"]);
        assert!(
            typed.unknown_fields.is_empty(),
            "{:?}",
            typed.unknown_fields
        );
        if typed.nothing_found() {
            assert_eq!(raw["risk"], "low_signal");
        }
    }
}
