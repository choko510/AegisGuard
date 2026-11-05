use file_origin_audit::{assess, inspect_fixture, Evidence, MAX_STREAM_BYTES};
use std::path::Path;

fn parsed(input: &[u8]) -> file_origin_audit::Report {
    assess(Evidence::Stream(input.to_vec()), "fixture")
}

#[test]
fn zones_zero_through_four() {
    for (id, name) in [
        (0, "local_machine"),
        (1, "local_intranet"),
        (2, "trusted_sites"),
        (3, "internet"),
        (4, "restricted_sites"),
    ] {
        let input = format!("[ZoneTransfer]\r\nZoneId={id}\r\n");
        let report = parsed(input.as_bytes());
        assert_eq!(report.status, "present");
        assert_eq!(report.zone_id, Some(id));
        assert_eq!(report.zone_name, Some(name));
        assert_eq!(report.coverage, "complete");
    }
}

#[test]
fn utf8_bom_crlf_unicode_and_unknown_key() {
    let bytes = "\u{feff}[ZoneTransfer]\r\n説明=テスト\r\nZoneId=3\r\n";
    let report = parsed(bytes.as_bytes());
    assert_eq!(report.zone_id, Some(3));
    assert_eq!(report.coverage, "complete");
    assert!(report.warnings.contains(&"unknown_keys_ignored"));
}

#[test]
fn utf16_both_endian_variants() {
    let data = "[ZoneTransfer]\r\nZoneId=4\r\n";
    for little in [true, false] {
        let mut bytes = if little { vec![0xff, 0xfe] } else { vec![0xfe, 0xff] };
        for unit in data.encode_utf16() {
            let encoded = if little {
                unit.to_le_bytes()
            } else {
                unit.to_be_bytes()
            };
            bytes.extend_from_slice(&encoded);
        }
        let report = parsed(&bytes);
        assert_eq!(report.zone_id, Some(4));
        assert_eq!(report.coverage, "complete");
    }
}

#[test]
fn malformed_utf16_is_partial() {
    let report = parsed(&[0xff, 0xfe, 0x41]);
    assert_eq!(report.coverage, "partial");
    assert_eq!(report.zone_id, None);
}

#[test]
fn duplicate_zone_is_ambiguous_even_if_identical() {
    for input in [
        "[ZoneTransfer]\nZoneId=3\nZoneId=3\n",
        "[ZoneTransfer]\nZoneId=3\nZoneId=0\n",
        "[ZoneTransfer]\nZoneId=3\n[ZoneTransfer]\nZoneId=3\n",
    ] {
        let report = parsed(input.as_bytes());
        assert_eq!(report.zone_id, None);
        assert_eq!(report.coverage, "partial");
    }
}

#[test]
fn malformed_values_do_not_become_trusted() {
    for value in ["5", "-1", "03", "3;comment", "３", ""] {
        let input = format!("[ZoneTransfer]\nZoneId={value}\n");
        let report = parsed(input.as_bytes());
        assert_eq!(report.zone_id, None);
        assert_eq!(report.coverage, "partial");
    }
}

#[test]
fn missing_section_and_missing_zone_are_not_success() {
    assert_eq!(parsed(b"ZoneId=3\n").coverage, "partial");
    assert_eq!(parsed(b"[ZoneTransfer]\nHostUrl=https://example.test\n").coverage, "partial");
    assert_eq!(parsed(b"").coverage, "partial");
}

#[test]
fn injected_newline_and_control_are_rejected() {
    let duplicate = parsed(b"[ZoneTransfer]\nZoneId=3\nZoneId=0\n");
    assert_eq!(duplicate.zone_id, None);
    let control = parsed(b"[ZoneTransfer]\nZoneId=3\rZoneId=0\n");
    assert_eq!(control.zone_id, None);
    assert!(control.warnings.contains(&"invalid_control_character"));
    let nul = parsed(b"[ZoneTransfer]\nZoneId=3\0\n");
    assert_eq!(nul.zone_id, None);
}

#[test]
fn input_limits_are_bounded() {
    let bytes = vec![b'A'; MAX_STREAM_BYTES + 1];
    let report = parsed(&bytes);
    assert_eq!(report.coverage, "partial");
    assert!(report.warnings.contains(&"stream_size_limit_exceeded"));

    let lines = format!("[ZoneTransfer]\nZoneId=3\n{}", "ignored=1\n".repeat(1025));
    assert_eq!(parsed(lines.as_bytes()).zone_id, None);
    let long_line = format!("[ZoneTransfer]\nZoneId=3\nX={}\n", "a".repeat(8193));
    assert_eq!(parsed(long_line.as_bytes()).coverage, "partial");
}

#[test]
fn urls_never_leave_the_parser() {
    let secret = "FAKE_TOKEN_DO_NOT_LEAK_1234567890";
    let input = format!(
        "[ZoneTransfer]\nZoneId=3\nHostUrl=https://a.invalid/download?token={secret}\nReferrerUrl=https://b.invalid/?key={secret}\n"
    );
    let result = parsed(input.as_bytes());
    let json = result.to_json();
    assert!(result.source_url_recorded);
    assert!(result.referrer_url_recorded);
    assert!(!json.contains(secret));
    assert!(!json.contains("https"));
    assert!(!json.contains("a.invalid"));
    assert!(json.contains("\"schema_version\":\"1.0.0\""));
}

#[test]
fn missing_ads_does_not_prove_safety() {
    let report = assess(Evidence::Absent, "windows_ads");
    assert_eq!(report.status, "absent");
    assert_eq!(report.coverage, "complete");
    assert_eq!(report.motw_present, Some(false));
    assert!(report.warnings.contains(&"absence_does_not_imply_safety"));
}

#[test]
fn unavailable_denied_and_failed_are_distinct() {
    for (evidence, status, coverage) in [
        (Evidence::NotSupported, "not_supported", "unavailable"),
        (Evidence::PermissionDenied, "permission_denied", "permission_denied"),
        (Evidence::Error("file_changed_during_read"), "error", "error"),
    ] {
        let report = assess(evidence, "mock");
        assert_eq!(report.status, status);
        assert_eq!(report.coverage, coverage);
        assert_eq!(report.motw_present, None);
    }
}

#[test]
fn failure_injection_for_replacement_and_permission() {
    let replaced = assess(Evidence::Error("file_changed_during_read"), "mock");
    let denied = assess(Evidence::PermissionDenied, "mock");
    assert!(replaced.to_json().contains("file_changed_during_read"));
    assert!(denied.to_json().contains("permission_denied"));
}

#[test]
fn output_has_timestamp_and_entries() {
    let report = parsed(b"[ZoneTransfer]\nZoneId=2\n");
    assert!(report.generated_at_unix_ms > 1_000_000_000_000);
    assert!(report.to_json().contains("\"entries\":[{"));
    assert!(!report.to_json().contains("\"trusted\":true"));
}

#[test]
fn fixture_on_disk_is_read_only() {
    let file = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/zone3.ini");
    let report = inspect_fixture(&file);
    assert_eq!(report.zone_id, Some(3));
    assert_eq!(report.coverage, "complete");
    assert!(!report.to_json().contains("FAKE_DO_NOT_LEAK"));
}

#[test]
fn nonexistent_fixture_is_not_absent_motw() {
    let file = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/does_not_exist.ini");
    let report = inspect_fixture(&file);
    assert_eq!(report.status, "error");
    assert_eq!(report.motw_present, None);
}

#[cfg(unix)]
#[test]
fn fixture_symlink_is_rejected() {
    use std::os::unix::fs::symlink;
    let target = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/zone3.ini");
    let link = std::env::temp_dir().join(format!(
        "file-origin-audit-link-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("valid clock")
            .as_nanos()
    ));
    symlink(&target, &link).expect("create benign symlink fixture");
    let report = inspect_fixture(&link);
    std::fs::remove_file(&link).expect("remove fixture symlink");
    assert_eq!(report.status, "error");
}
