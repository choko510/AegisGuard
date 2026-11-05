use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn temporary_fixture(data: &[u8]) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "windows-posture-test-{}-{stamp}.json",
        std::process::id()
    ));
    fs::write(&path, data).unwrap();
    path
}

fn inspect(path: &PathBuf) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_windows-posture"))
        .arg("inspect-fixture")
        .arg(path)
        .output()
        .unwrap()
}

#[test]
fn fixture_cli_emits_only_json_and_no_raw_secrets() {
    let path = temporary_fixture(
        br#"{"bitlocker":{"status":"ok","recovery_key":"DO_NOT_PRINT_ME"}}"#,
    );
    let output = inspect(&path);
    fs::remove_file(path).unwrap();
    assert_eq!(output.status.code(), Some(2));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "error");
    assert!(!String::from_utf8_lossy(&output.stdout).contains("DO_NOT_PRINT_ME"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("DO_NOT_PRINT_ME"));
}

#[test]
fn fixture_cli_rejects_oversized_input_before_parse() {
    let path = temporary_fixture(&vec![b' '; 65_537]);
    let output = inspect(&path);
    fs::remove_file(path).unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap()["status"],
        "error"
    );
}

#[test]
fn fixture_cli_handles_empty_and_corrupt_input() {
    for input in [&b""[..], &b"{broken"[..]] {
        let path = temporary_fixture(input);
        let output = inspect(&path);
        fs::remove_file(path).unwrap();
        assert_eq!(output.status.code(), Some(2));
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["status"], "error");
    }
}

#[test]
fn fixture_cli_reports_partial_without_failing_to_parse() {
    let path = temporary_fixture(br#"{"secure_boot":{"status":"ok","enabled":true}}"#);
    let output = inspect(&path);
    fs::remove_file(path).unwrap();
    assert_eq!(output.status.code(), Some(1));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "partial");
    assert_eq!(report["coverage"]["assessed"], 1);
}

#[cfg(not(windows))]
#[test]
fn non_windows_audit_does_not_pretend_it_checked_windows() {
    let output = Command::new(env!("CARGO_BIN_EXE_windows-posture"))
        .args(["audit", "--format", "json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "unavailable");
    assert_eq!(report["warnings"][0], "windows_only");
}

#[cfg(unix)]
#[test]
fn symlink_fixture_is_rejected_without_following_it() {
    let original = temporary_fixture(br#"{"secure_boot":{"status":"ok","enabled":true}}"#);
    let link = original.with_extension("link");
    std::os::unix::fs::symlink(&original, &link).unwrap();
    let output = inspect(&link);
    fs::remove_file(link).unwrap();
    fs::remove_file(original).unwrap();
    assert_eq!(output.status.code(), Some(2));
}
