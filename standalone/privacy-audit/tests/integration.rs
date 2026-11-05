use privacy_audit::{audit_path, audit_reader, exit_code, Mode, MAX_FILE_BYTES, MAX_LINES};
use serde_json::Value;
use std::fs;
use std::io::{self, BufRead, Read};
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn synthetic_file(name: &str, bytes: &[u8]) -> PathBuf {
    let serial = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "privacy-audit-test-{}-{serial}-{name}",
        std::process::id()
    ));
    fs::write(&path, bytes).unwrap();
    path
}

#[test]
fn cli_does_not_echo_secrets_in_stdout_stderr_or_errors() {
    let secret = "syntheticTEST_ONLY_ABC12345";
    let input = synthetic_file(
        "jsonl.txt",
        format!("{{\"password\":\"{secret}\"}}\n").as_bytes(),
    );
    let run = Command::new(env!("CARGO_BIN_EXE_privacy-audit"))
        .args(["check", "--input"])
        .arg(&input)
        .args(["--format", "json", "--mode", "jsonl"])
        .output()
        .unwrap();
    fs::remove_file(input).unwrap();
    assert_eq!(run.status.code(), Some(2));
    assert!(run.stderr.is_empty());
    let stdout = String::from_utf8(run.stdout).unwrap();
    let json: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(json["status"], "complete");
    assert_eq!(json["entries"][0]["redacted_excerpt_or_hash"], "[REDACTED]");
    assert!(!stdout.contains(secret));
    assert!(!stdout.contains("jsonl.txt"));
}

#[test]
fn jsonl_mode_rejects_malformed_records_not_fallback_to_log() {
    let input = synthetic_file("broken.log", b"{\"token\":\"syntheticABC123\"");
    let run = Command::new(env!("CARGO_BIN_EXE_privacy-audit"))
        .args(["check", "--input"])
        .arg(&input)
        .args(["--format", "json", "--mode", "jsonl"])
        .output()
        .unwrap();
    fs::remove_file(input).unwrap();
    assert_eq!(run.status.code(), Some(3));
    let text = String::from_utf8(run.stdout).unwrap();
    assert!(text.contains("malformed_json"));
    assert!(!text.contains("syntheticABC123"));
}

#[test]
fn caps_and_null_coverage_are_explicit() {
    let big = vec![b'z'; (MAX_FILE_BYTES + 1) as usize];
    let file = synthetic_file("too-large.log", &big);
    let result = audit_path(&file, Mode::Log);
    fs::remove_file(file).unwrap();
    assert_eq!(exit_code(&result), 3);
    assert_eq!(result["warnings"][0], "file_limit_exceeded");
    let line = "{\"event\":\"ok\"}\n".repeat(MAX_LINES + 1);
    let result = audit_reader(line.as_bytes(), Mode::Log);
    assert_eq!(exit_code(&result), 3);
    assert_eq!(result["warnings"][0], "line_count_limit_exceeded");
}

#[test]
fn duplicate_rule_one_line_is_not_repeated() {
    let result = audit_reader(
        &b"token=syntheticFIRST12345 token=syntheticSECOND12345"[..],
        Mode::Log,
    );
    assert_eq!(result["entries"].as_array().unwrap().len(), 1);
}

#[test]
fn normal_and_encoded_html_queries_are_distinguished() {
    let text = concat!(
        "https://example.invalid/?page=1&amp;token=syntheticURLTOKEN12345\n",
        "https://example.invalid/?page=1&amp;sort=asc\n"
    );
    let result = audit_reader(text.as_bytes(), Mode::Log);
    let entries = result["entries"].as_array().unwrap();
    assert!(!entries.is_empty());
    assert!(entries.iter().all(|entry| entry["line_no"] == 1));
    assert_eq!(exit_code(&result), 2);
}

#[test]
fn permission_denied_is_not_reported_as_clean() {
    struct Denied;
    impl Read for Denied {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::PermissionDenied, "test only"))
        }
    }
    impl BufRead for Denied {
        fn fill_buf(&mut self) -> io::Result<&[u8]> {
            Err(io::Error::new(io::ErrorKind::PermissionDenied, "test only"))
        }
        fn consume(&mut self, _amt: usize) {}
    }
    let result = audit_reader(Denied, Mode::Auto);
    assert_eq!(result["status"], "permission_denied");
    assert_eq!(exit_code(&result), 3);
    assert!(!result.to_string().contains("test only"));
}

#[test]
fn report_has_generated_time_and_no_input_path() {
    let result = audit_reader(&b"normal log line\n"[..], Mode::Log);
    assert!(result["generated_at_unix_ms"].as_u64().unwrap() > 1_700_000_000_000);
    assert_eq!(result["schema_version"], 1);
    assert_eq!(result["module"], "privacy-audit");
    assert_eq!(result["coverage"]["complete"], true);
}

#[cfg(unix)]
#[test]
fn symlink_is_not_followed() {
    use std::os::unix::fs::symlink;
    let target = synthetic_file("target.log", b"normal\n");
    let link = target.with_extension("link");
    symlink(&target, &link).unwrap();
    let result = audit_path(&link, Mode::Log);
    assert_eq!(result["warnings"][0], "symlink_not_followed");
    assert_eq!(exit_code(&result), 3);
    fs::remove_file(link).unwrap();
    fs::remove_file(target).unwrap();
}

#[test]
fn secret_arrays_and_nested_objects_inherit_sensitive_parent() {
    for input in [
        r#"{"access_token":["synthetic$ABC12345"]}"#,
        r#"[{"access_token":["synthetic$ABC12345"]}]"#,
        r#"{"password":{"nested":{"values":["synthetic$ABC12345"]}}}"#,
        r#"{"Cookie":[{"payload":"synthetic$ABC12345"}]}"#,
    ] {
        let result = audit_reader(input.as_bytes(), Mode::Auto);
        assert_eq!(result["status"], "complete", "{input}");
        assert!(
            result["entries"].as_array().is_some_and(|v| !v.is_empty()),
            "secret not detected in {input}"
        );
        assert_eq!(exit_code(&result), 2);
        assert!(!result.to_string().contains("synthetic$ABC12345"));
    }
}

#[test]
fn duplicate_json_keys_fail_closed_even_with_unicode_escapes() {
    for input in [
        r#"{"password":"synthetic$ABC12345","password":"[REDACTED]"}"#,
        r#"{"password":"synthetic$ABC12345","pass\u0077ord":"[REDACTED]"}"#,
        r#"{"outer":{"token":"synthetic$ABC12345","token":null}}"#,
        r#"[{"key":"a","key":"b"}]"#,
    ] {
        let result = audit_reader(input.as_bytes(), Mode::Auto);
        assert_ne!(result["status"], "complete", "{input}");
        assert_eq!(result["warnings"][0], "duplicate_json_key");
        assert_eq!(exit_code(&result), 3);
        assert!(!result.to_string().contains("synthetic$ABC12345"));
    }
}

#[test]
fn ordinary_json_arrays_remain_clean_when_no_secrets_exist() {
    let output = audit_reader(&br#"[{"items":["hello","world"]},{"ok":true}]"#[..], Mode::Auto);
    assert_eq!(output["status"], "complete");
    assert_eq!(output["coverage"]["json_lines"], 1);
    assert_eq!(exit_code(&output), 0);
}
