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
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let p = std::env::temp_dir().join(format!(
            "validation-lab-test-{}-{}-{}",
            std::process::id(), nanos, COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&p).unwrap();
        Self(p)
    }
    fn path(&self) -> &Path { &self.0 }
}
impl Drop for Temporary {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
}

fn snap(root: &Path) -> Vec<(String, Vec<u8>)> {
    fn walk(base: &Path, dir: &Path, files: &mut Vec<(String, Vec<u8>)>) {
        for entry in fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.is_dir() { walk(base, &path, files); }
            else {
                let relative = path.strip_prefix(base).unwrap().to_string_lossy().replace('\\', "/");
                files.push((relative, fs::read(&path).unwrap()));
            }
        }
    }
    let mut files = Vec::new();
    walk(root, root, &mut files);
    files.sort_by(|a,b| a.0.cmp(&b.0));
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
    assert_eq!(first.len(), 1 + 10 + 10 + 1 + first.iter().filter(|p| p.0.ends_with(".xml")).count());
    assert_eq!(verify(&a).unwrap()["status"], "complete");
    let xml = fs::read_to_string(a.join("k2f-analog-chain/event-000.xml")).unwrap();
    assert!(xml.contains("Microsoft-Windows-Sysmon"));
    assert!(xml.contains("EventRecordID"));
    let jsonl = fs::read(a.join("k2f-analog-chain/events.jsonl")).unwrap();
    assert!(jsonl.iter().all(|b| *b != b'\r'));
    assert!(String::from_utf8(jsonl).unwrap().contains("C:\\\\Users\\\\Lab"));
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
    assert_eq!(summarize(&a.join("manifest.json"), &actual).unwrap()["status"], "partial");
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
    let rules = ["AG-B001","AG-B002","AG-B003","AG-B005"].iter()
        .map(|id| json!({"rule_id":id,"evaluable":true})).collect::<Vec<_>>();
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
