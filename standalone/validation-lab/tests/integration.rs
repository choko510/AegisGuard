use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use validation_lab::{generate, summarize, verify};

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct Temporary(PathBuf);
impl Temporary {
    fn new() -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!(
            "validation-lab-test-{}-{}-{}",
            std::process::id(),
            nanos,
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&p).unwrap();
        Self(p)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn snap(root: &Path) -> Vec<(String, Vec<u8>)> {
    fn walk(base: &Path, dir: &Path, files: &mut Vec<(String, Vec<u8>)>) {
        for entry in fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.is_dir() {
                walk(base, &path, files);
            } else {
                let relative = path
                    .strip_prefix(base)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                files.push((relative, fs::read(&path).unwrap()));
            }
        }
    }
    let mut files = Vec::new();
    walk(root, root, &mut files);
    files.sort_by(|a, b| a.0.cmp(&b.0));
    files
}

fn create(temp: &Temporary, name: &str, seed: u64, profile: &str) -> PathBuf {
    let dir = temp.path().join(name);
    let report = generate(&dir, seed, profile).unwrap();
    assert_eq!(report["status"], "complete");
    dir
}

#[test]
fn deterministic_all_files_and_cross_platform_jsonl() {
    let temp = Temporary::new();
    let a = create(&temp, "a", 42, "all");
    let b = create(&temp, "b", 42, "all");
    let c = create(&temp, "c", 43, "all");
    let first = snap(&a);
    assert_eq!(first, snap(&b));
    assert_ne!(first, snap(&c));
    assert_eq!(
        first.len(),
        1 + 10 + 10 + 1 + first.iter().filter(|p| p.0.ends_with(".xml")).count()
    );
    assert_eq!(verify(&a).unwrap()["status"], "complete");
    let xml = fs::read_to_string(a.join("k2f-analog-chain/event-000.xml")).unwrap();
    assert!(xml.contains("Microsoft-Windows-Sysmon"));
    assert!(xml.contains("EventRecordID"));
    let jsonl = fs::read(a.join("k2f-analog-chain/events.jsonl")).unwrap();
    assert!(jsonl.iter().all(|b| *b != b'\r'));
    assert!(String::from_utf8(jsonl)
        .unwrap()
        .contains("C:\\\\Users\\\\Lab"));
}

#[test]
fn only_new_directory_and_no_commands_are_executed() {
    let temp = Temporary::new();
    let a = create(&temp, "case", 7, "admin-script");
    assert!(generate(&a, 7, "all").is_err());
    assert!(generate(&temp.path().join("bad"), 7, "unrecognized").is_err());
    assert!(!temp.path().join("bad").exists());
    assert_eq!(verify(&a).unwrap()["status"], "complete");
    let s = fs::read_to_string(a.join("admin-script/events.jsonl")).unwrap();
    assert!(s.contains("CommandLine_sha256"));
    assert!(!s.contains("powershell.exe -NoProfile"));
    assert_eq!(fs::read_dir(a.join("admin-script")).unwrap().count(), 3);
}

#[test]
fn tamper_and_truncated_event_detected() {
    let temp = Temporary::new();
    let a = create(&temp, "case", 42, "pid-reuse");
    let path = a.join("pid-reuse/events.jsonl");
    let mut text = fs::read(&path).unwrap();
    text.extend_from_slice(b"{broken");
    fs::write(&path, text).unwrap();
    let report = verify(&a).unwrap();
    assert_eq!(report["status"], "partial");
    assert!(report["warnings"].to_string().contains("mismatch"));
}

#[test]
fn unknown_manifest_version_rejected() {
    let temp = Temporary::new();
    let a = create(&temp, "case", 42, "benign-com");
    let path = a.join("manifest.json");
    let mut manifest: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    manifest["schema_version"] = json!(999);
    fs::write(&path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    assert!(verify(&a).is_err());
}

#[test]
fn incomplete_report_is_not_success() {
    let temp = Temporary::new();
    let a = create(&temp, "case", 42, "benign-com");
    let actual = temp.path().join("actual.jsonl");
    fs::write(&actual, b"").unwrap();
    let summary = summarize(&a.join("manifest.json"), &actual).unwrap();
    assert_eq!(summary["status"], "partial");
    assert_eq!(summary["coverage"]["unknown"], 1);
    let report = json!({"case_id":"benign-com","rules":[{"rule_id":"AG-B002","evaluable":false}],"findings":[]});
    fs::write(&actual, format!("{report}\n")).unwrap();
    assert_eq!(
        summarize(&a.join("manifest.json"), &actual).unwrap()["status"],
        "partial"
    );
    fs::write(&actual, b"bad json\n").unwrap();
    assert!(summarize(&a.join("manifest.json"), &actual).is_err());
}

#[test]
fn completed_and_unexpected_finding_are_distinguished() {
    let temp = Temporary::new();
    let a = create(&temp, "case", 42, "benign-com");
    let actual = temp.path().join("actual.jsonl");
    let ok = json!({"case_id":"benign-com","rules":[{"rule_id":"AG-B002","evaluable":true}],"findings":[]});
    fs::write(&actual, format!("{ok}\n")).unwrap();
    let report = summarize(&a.join("manifest.json"), &actual).unwrap();
    assert_eq!(report["status"], "complete");
    assert_eq!(report["coverage"]["passed"], 1);
    let unexpected = json!({"case_id":"benign-com","rules":[{"rule_id":"AG-B002","evaluable":true}],
        "findings":[{"rule_id":"AG-B002","event_refs":[]}]});
    fs::write(&actual, format!("{unexpected}\n")).unwrap();
    let report = summarize(&a.join("manifest.json"), &actual).unwrap();
    assert_eq!(report["status"], "partial");
    assert_eq!(report["coverage"]["failed"], 1);
}

#[test]
fn untrusted_finding_without_expected_evidence_is_not_a_pass() {
    let temp = Temporary::new();
    let a = create(&temp, "case", 42, "k2f-analog-chain");
    let actual = temp.path().join("actual.jsonl");
    let rules = ["AG-B001", "AG-B002", "AG-B003", "AG-B005"]
        .iter()
        .map(|id| json!({"rule_id":id,"evaluable":true}))
        .collect::<Vec<_>>();
    let report = json!({"case_id":"k2f-analog-chain","rules":rules,
        "findings":[{"rule_id":"AG-B001","event_refs":["nonexistent"]},
                    {"rule_id":"AG-B002","event_refs":["nonexistent"]},
                    {"rule_id":"AG-B003","event_refs":["nonexistent"]}]});
    fs::write(&actual, format!("{report}\n")).unwrap();
    let result = summarize(&a.join("manifest.json"), &actual).unwrap();
    assert_eq!(result["coverage"]["failed"], 3);
    assert_eq!(result["coverage"]["planned"], 1);
}

#[test]
fn bounded_actual_input_and_duplicate_case_id() {
    let temp = Temporary::new();
    let a = create(&temp, "case", 42, "benign-com");
    let actual = temp.path().join("actual.jsonl");
    fs::write(&actual, vec![b'a'; 8 * 1024 * 1024 + 1]).unwrap();
    assert!(summarize(&a.join("manifest.json"), &actual).is_err());
    let report = json!({"case_id":"benign-com","rules":[],"findings":[]});
    fs::write(&actual, format!("{report}\n{report}\n")).unwrap();
    assert!(summarize(&a.join("manifest.json"), &actual).is_err());
}

#[cfg(unix)]
#[test]
fn symlink_artifact_is_rejected() {
    use std::os::unix::fs::symlink;
    let temp = Temporary::new();
    let a = create(&temp, "case", 42, "benign-com");
    let target = a.join("benign-com/events.jsonl");
    let other = a.join("benign-com/event-copy.txt");
    fs::rename(&target, &other).unwrap();
    symlink(&other, &target).unwrap();
    let report = verify(&a).unwrap();
    assert_eq!(report["status"], "partial");
}

#[test]
fn malformed_incomplete_and_unknown_schema_reports_do_not_pass() {
    let temp = Temporary::new();
    let a = create(&temp, "case", 42, "benign-com");
    let actual = temp.path().join("actual.jsonl");
    // Missing findings array must not be interpreted as no detection.
    let truncated =
        json!({"case_id":"benign-com","rules":[{"rule_id":"AG-B002","evaluable":true}]});
    fs::write(&actual, format!("{truncated}\n")).unwrap();
    assert_eq!(
        summarize(&a.join("manifest.json"), &actual).unwrap()["status"],
        "partial"
    );
    let partial = json!({"case_id":"benign-com","status":"partial",
        "rules":[{"rule_id":"AG-B002","evaluable":true}],"findings":[]});
    fs::write(&actual, format!("{partial}\n")).unwrap();
    assert_eq!(
        summarize(&a.join("manifest.json"), &actual).unwrap()["coverage"]["unknown"],
        1
    );
    let newer = json!({"schema_version":999,"case_id":"benign-com","rules":[],"findings":[]});
    fs::write(&actual, format!("{newer}\n")).unwrap();
    assert!(summarize(&a.join("manifest.json"), &actual).is_err());
}

#[test]
fn stale_ioc_is_explicitly_expired_and_future_rules_remain_planned() {
    let temp = Temporary::new();
    let a = create(&temp, "case", 42, "stale-ioc");
    let ioc: Value =
        serde_json::from_slice(&fs::read(a.join("stale-ioc/expired-ioc.json")).unwrap()).unwrap();
    assert!(ioc["expires_at_unix_ms"].as_u64().unwrap() < 1_793_872_800_000);
    assert_eq!(ioc["compatible_with_aegisguard_c2_cache"], false);
    assert_eq!(verify(&a).unwrap()["status"], "complete");
    let actual = temp.path().join("actual.jsonl");
    fs::write(&actual, b"{\"rules\":[],\"findings\":[]}\n").unwrap();
    assert_eq!(
        summarize(&a.join("manifest.json"), &actual).unwrap()["status"],
        "partial"
    );
}

#[test]
fn a_valid_json_object_without_final_newline_is_incomplete() {
    let temp = Temporary::new();
    let a = create(&temp, "case", 42, "benign-com");
    let actual = temp.path().join("actual.jsonl");
    fs::write(
        &actual,
        b"{\"case_id\":\"benign-com\",\"rules\":[],\"findings\":[]}",
    )
    .unwrap();
    assert!(summarize(&a.join("manifest.json"), &actual).is_err());
    fs::write(
        &actual,
        b"{\"case_id\":\"benign-com\",\"rules\":[],\"findings\":[]}\n\n",
    )
    .unwrap();
    assert!(summarize(&a.join("manifest.json"), &actual).is_err());
    fs::write(
        &actual,
        b"{\"ruleset_version\":999,\"case_id\":\"benign-com\",\"rules\":[],\"findings\":[]}\n",
    )
    .unwrap();
    assert!(summarize(&a.join("manifest.json"), &actual).is_err());
}

#[test]
fn complete_synthetic_chain_with_expected_refs_is_compared_not_called_malware() {
    let temp = Temporary::new();
    let a = create(&temp, "case", 42, "k2f-analog-chain");
    let expected: Value =
        serde_json::from_slice(&fs::read(a.join("manifest.json")).unwrap()).unwrap();
    let checks = expected["cases"][0]["expected"].as_array().unwrap();
    let rules = checks
        .iter()
        .filter(|e| e["outcome"] != "planned")
        .map(|e| json!({"rule_id":e["rule_id"],"evaluable":true}))
        .collect::<Vec<_>>();
    let findings = checks
        .iter()
        .filter(|e| e["outcome"] == "present")
        .map(|e| json!({"rule_id":e["rule_id"],"event_refs":e["event_refs"]}))
        .collect::<Vec<_>>();
    let actual = temp.path().join("actual.jsonl");
    let report = json!({"case_id":"k2f-analog-chain","ruleset_version":2,
        "rules":rules,"findings":findings});
    fs::write(&actual, format!("{report}\n")).unwrap();
    let result = summarize(&a.join("manifest.json"), &actual).unwrap();
    assert_eq!(result["coverage"]["passed"], 4);
    assert_eq!(result["coverage"]["failed"], 0);
    assert_eq!(result["coverage"]["planned"], 1);
    assert_eq!(result["status"], "partial"); // planned means not fully implemented
}

#[test]
fn unexpected_finding_in_benign_case_must_fail() {
    let tmp = Temporary::new();
    let dir = create(&tmp, "unexpected", 42, "benign-com");
    let report = tmp.path().join("unexpected-findings.jsonl");
    let actual = json!({
        "case_id":"benign-com",
        "rules":[{"rule_id":"AG-B002","evaluable":true}],
        "findings":[{"rule_id":"AG-C010","event_refs":["unexpected-id"],"confidence":"high"}]
    });
    fs::write(&report, format!("{actual}\n")).unwrap();
    let result = summarize(&dir.join("manifest.json"), &report).unwrap();
    assert_eq!(result["status"], "partial");
    assert!(result["coverage"]["failed"].as_u64().unwrap() >= 1);
    assert!(result.to_string().contains("no_unexpected_finding"));
}

#[test]
fn unknown_rule_must_not_be_evaluable_or_report_a_finding() {
    let tmp = Temporary::new();
    let dir = create(&tmp, "unknown", 42, "stale-ioc");
    let report = tmp.path().join("unexpected-unknown.jsonl");
    for actual in [
        json!({"case_id":"stale-ioc","rules":[{"rule_id":"AG-C002","evaluable":true}],
             "findings":[]}),
        json!({"case_id":"stale-ioc","rules":[{"rule_id":"AG-C002","evaluable":false}],
             "findings":[{"rule_id":"AG-C002","confidence":"high","event_refs":["some-event"]}]}),
    ] {
        fs::write(&report, format!("{actual}\n")).unwrap();
        let result = summarize(&dir.join("manifest.json"), &report).unwrap();
        assert_eq!(result["status"], "partial");
        assert!(result["coverage"]["failed"].as_u64().unwrap() > 0);
    }
}

#[test]
fn xml_and_jsonl_must_match_even_after_rehashing_the_manifest() {
    use sha2::{Digest, Sha256};
    let tmp = Temporary::new();
    let dir = create(&tmp, "semantic", 42, "benign-com");
    let mut manifest: Value =
        serde_json::from_slice(&fs::read(dir.join("manifest.json")).unwrap()).unwrap();
    let xml_rel = manifest["cases"][0]["xml"][0]["path"].as_str().unwrap();
    let file = dir.join(xml_rel);
    let source = String::from_utf8(fs::read(&file).unwrap()).unwrap();
    let altered = source.replacen("<EventID>1</EventID>", "<EventID>7</EventID>", 1);
    assert_ne!(source, altered);
    fs::write(&file, altered.as_bytes()).unwrap();
    manifest["cases"][0]["xml"][0]["sha256"] =
        json!(format!("{:x}", Sha256::digest(altered.as_bytes())));
    manifest["cases"][0]["xml"][0]["bytes"] = json!(altered.len());
    fs::write(
        dir.join("manifest.json"),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();
    let result = verify(&dir).unwrap();
    assert_eq!(result["status"], "partial");
    assert!(result.to_string().contains("XML/JSONL event mismatch"));
}
