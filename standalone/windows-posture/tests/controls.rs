use serde_json::{json, Value};
use windows_posture::evaluate;

fn enabled_fixture() -> Value {
    json!({
        "edition": "pro",
        "secure_boot": {"status": "ok", "enabled": true},
        "tpm": {"status": "ok", "present": true, "ready": true, "spec_2_0": true},
        "device_guard": {
            "status": "ok",
            "vbs_status": 2,
            "running_services": [2],
            "configured_services": [2]
        },
        "bitlocker": {
            "status": "ok", "os_volume_count": 1,
            "protection": 1, "conversion": 1
        }
    })
}

fn entry<'a>(report: &'a Value, id: &str) -> &'a Value {
    report["entries"]
        .as_array()
        .expect("entries must be an array")
        .iter()
        .find(|value| value["id"] == id)
        .expect("control must exist")
}

#[test]
fn all_enabled_is_complete_and_versioned() {
    let report = evaluate(&enabled_fixture(), 42).unwrap();
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["module"], "windows-posture");
    assert_eq!(report["generated_at_unix_ms"], 42);
    assert_eq!(report["status"], "complete");
    assert_eq!(report["coverage"]["assessed"], 5);
    for control in report["entries"].as_array().unwrap() {
        assert_eq!(control["availability"], "supported");
        assert_eq!(control["state"], "enabled");
        assert_eq!(control["checked_at"], 42);
    }
}

#[test]
fn disabled_is_distinct_from_unknown() {
    let mut fixture = enabled_fixture();
    fixture["secure_boot"]["enabled"] = json!(false);
    fixture["tpm"]["ready"] = json!(false);
    fixture["device_guard"]["vbs_status"] = json!(0);
    fixture["device_guard"]["running_services"] = json!([]);
    fixture["device_guard"]["configured_services"] = json!([]);
    fixture["bitlocker"]["protection"] = json!(0);
    fixture["bitlocker"]["conversion"] = json!(0);
    let report = evaluate(&fixture, 42).unwrap();
    assert_eq!(report["status"], "complete");
    for control in report["entries"].as_array().unwrap() {
        assert_eq!(control["state"], "disabled");
    }
}

#[test]
fn unsupported_tpm_and_legacy_boot_not_enabled() {
    let fixture = json!({
        "secure_boot": {"status": "unsupported"},
        "tpm": {"status": "ok", "present": false, "ready": false}
    });
    let report = evaluate(&fixture, 1).unwrap();
    for id in ["secure_boot", "tpm_2_0"] {
        assert_eq!(entry(&report, id)["state"], "not_applicable");
    }
    assert_eq!(report["status"], "partial");
}

#[test]
fn inaccessible_probes_are_not_mislabeled_disabled() {
    let fixture = json!({
        "secure_boot": {"status": "permission_denied"},
        "tpm": {"status": "permission_denied"},
        "device_guard": {"status": "permission_denied"},
        "bitlocker": {"status": "permission_denied"}
    });
    let report = evaluate(&fixture, 1).unwrap();
    assert_eq!(report["status"], "permission_denied");
    assert_eq!(report["coverage"]["permission_denied"], 5);
    for control in report["entries"].as_array().unwrap() {
        assert_eq!(control["state"], "permission_denied");
    }
}

#[test]
fn timeout_cannot_be_reported_as_secure() {
    let report = evaluate(&json!({"secure_boot":{"status":"timeout"}}), 5).unwrap();
    assert_eq!(entry(&report, "secure_boot")["state"], "unknown");
    assert_eq!(
        entry(&report, "secure_boot")["warnings"][0],
        "probe_timeout"
    );
    assert_eq!(report["status"], "unavailable");
}

#[test]
fn missing_values_are_unknown() {
    let fixture = json!({
        "tpm": {"status": "ok", "present": true, "ready": true, "spec_2_0": null},
        "device_guard": {"status": "ok", "vbs_status": null, "running_services": null},
        "bitlocker": {
            "status": "ok", "os_volume_count": 1, "protection": null,
            "conversion": 1
        }
    });
    let report = evaluate(&fixture, 5).unwrap();
    for id in ["tpm_2_0", "vbs", "hvci", "bitlocker_os_volume"] {
        assert_eq!(entry(&report, id)["state"], "unknown");
    }
}

#[test]
fn contradictions_are_unknown_not_successful() {
    let fixture = json!({
        "tpm": {"status": "ok", "present": false, "ready": true, "spec_2_0": true},
        "device_guard": {"status": "ok", "vbs_status": 0, "running_services": [2]},
        "bitlocker": {"status": "ok", "os_volume_count": 1, "protection": 1, "conversion": 0}
    });
    let report = evaluate(&fixture, 5).unwrap();
    for id in ["tpm_2_0", "vbs", "hvci", "bitlocker_os_volume"] {
        assert_eq!(entry(&report, id)["state"], "unknown");
        assert_eq!(entry(&report, id)["warnings"][0], "conflicting_evidence");
    }
}

#[test]
fn duplicate_vbs_codes_are_inconsistent() {
    let fixture = json!({
        "device_guard": {
            "status": "ok", "vbs_status": 2,
            "running_services": [2,2], "configured_services": [2]
        }
    });
    let report = evaluate(&fixture, 5).unwrap();
    assert_eq!(entry(&report, "hvci")["state"], "unknown");
}

#[test]
fn configured_hvci_is_not_the_same_as_running_hvci() {
    let fixture = json!({
        "device_guard": {
            "status": "ok", "vbs_status": 1,
            "running_services": [], "configured_services": [2]
        }
    });
    let report = evaluate(&fixture, 5).unwrap();
    assert_eq!(entry(&report, "vbs")["state"], "disabled");
    assert_eq!(entry(&report, "hvci")["state"], "disabled");
    assert_eq!(
        entry(&report, "hvci")["warnings"][0],
        "configured_but_not_running"
    );
}

#[test]
fn bitlocker_encrypted_but_unprotected_is_not_enabled() {
    let fixture = json!({
        "bitlocker": {
            "status": "ok", "os_volume_count": 1,
            "protection": 0, "conversion": 1
        }
    });
    let report = evaluate(&fixture, 10).unwrap();
    assert_eq!(entry(&report, "bitlocker_os_volume")["state"], "disabled");
    assert_eq!(
        entry(&report, "bitlocker_os_volume")["warnings"][0],
        "encrypted_but_protection_off"
    );
}

#[test]
fn unknown_os_volume_count_never_claims_unencrypted() {
    for count in [0, 2] {
        let fixture = json!({
            "bitlocker": {
                "status": "ok", "os_volume_count": count,
                "protection": 0, "conversion": 0
            }
        });
        assert_eq!(
            entry(&evaluate(&fixture, 9).unwrap(), "bitlocker_os_volume")["state"],
            "unknown"
        );
    }
}

#[test]
fn editions_do_not_override_observed_states() {
    let mut home = enabled_fixture();
    home["edition"] = json!("home");
    let a = evaluate(&home, 99).unwrap();
    let mut pro = home;
    pro["edition"] = json!("pro");
    let b = evaluate(&pro, 99).unwrap();
    assert_eq!(a, b);
}

#[test]
fn malformed_fields_and_excessive_arrays_are_rejected() {
    for fixture in [
        json!({"secure_boot":{"status":"ok","enabled":"yes"}}),
        json!({"device_guard":{"status":"ok","running_services":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17]}}),
        json!({"bitlocker":{"status":"ok","os_volume_count":-1}}),
        json!({"tpm":{"status":"surprise"}}),
        json!({"unexpected":"field"}),
        json!([]),
    ] {
        assert!(evaluate(&fixture, 1).is_err());
    }
}

#[test]
fn empty_and_unknown_fields_are_not_trusted() {
    assert_eq!(evaluate(&json!({}), 3).unwrap()["status"], "unavailable");
    assert!(evaluate(&json!({"tpm":{"status":"ok","owner_auth":"secret"}}), 1).is_err());
}

#[test]
fn varying_timestamps_are_not_cached() {
    let fixture = enabled_fixture();
    let a = evaluate(&fixture, 100).unwrap();
    let b = evaluate(&fixture, 200).unwrap();
    assert_eq!(a["entries"][0]["checked_at"], 100);
    assert_eq!(b["entries"][0]["checked_at"], 200);
}

#[test]
fn failed_bitlocker_read_methods_never_imply_protection() {
    for status in ["error", "timeout", "permission_denied"] {
        let fixture = json!({
            "bitlocker": {"status": status}
        });
        let report = evaluate(&fixture, 11).unwrap();
        let control = entry(&report, "bitlocker_os_volume");
        assert_ne!(control["state"], "enabled");
        assert_ne!(control["state"], "disabled");
        if status == "permission_denied" {
            assert_eq!(control["state"], "permission_denied");
            assert_eq!(report["status"], "permission_denied");
        } else {
            assert_eq!(control["state"], "unknown");
            assert_eq!(report["status"], "unavailable");
        }
    }
}

#[test]
fn conflicting_or_incomplete_fresh_bitlocker_values_are_unknown() {
    for (protection, conversion) in [
        (json!(1), json!(0)),
        (json!(1), json!(null)),
        (json!(2), json!(1)),
        (json!(1), json!(2)),
    ] {
        let fixture = json!({
            "bitlocker": {
                "status": "ok",
                "os_volume_count": 1,
                "protection": protection,
                "conversion": conversion
            }
        });
        let report = evaluate(&fixture, 11).unwrap();
        assert_eq!(entry(&report, "bitlocker_os_volume")["state"], "unknown");
    }
}
