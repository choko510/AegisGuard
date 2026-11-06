use driver_inventory::{fixture, normalize_image_path, report, MAX_ENTRIES, MAX_FIXTURE_BYTES};
use serde_json::json;

fn data() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schema_version":1,"enumeration_status":"complete",
        "services":[
            {"name":"SecureSvc", "service_type":16, "state":4, "start_type":2,
             "delayed_auto_start":true,"dependency_count":2,
             "image_path":"\"C:\\Program Files\\Acme\\svc.exe\" --password secret",
             "file_state":"exists", "signature":"not_checked"},
            {"name":"FSFilter", "service_type":2, "state":1, "start_type":0,
             "image_path":"\\SystemRoot\\System32\\drivers\\filter.sys",
             "file_state":"exists", "signature":"verified_embedded"},
            {"name":"VirtualOne", "service_type":1, "state":4, "start_type":3,
             "file_state":"virtual", "signature":"unknown"},
            {"name":"HiddenSvc", "service_type":32, "state":1,
             "config_error":"permission_denied"},
            {"name":"MissingDriver", "service_type":1, "state":1, "start_type":4,
             "image_path":"C:\\Windows\\System32\\drivers\\gone.sys",
             "file_state":"missing","signature":"invalid"}
        ]
    }))
    .unwrap()
}
#[test]
fn mixed_types_statuses_and_minimal_paths() {
    let collection = fixture(&data()).unwrap();
    let result = report(collection, false, false, r"C:\Windows");
    assert_eq!(result["status"], "partial"); // one unreadable configuration
    assert_eq!(result["coverage"]["enumerated"], 5);
    assert_eq!(result["entries"][0]["kind"], "win32_own_process");
    assert_eq!(result["entries"][0]["start_type"], "automatic");
    assert_eq!(result["entries"][0]["delayed_auto_start"], true);
    assert_eq!(result["entries"][0]["dependency_count"], 2);
    assert_eq!(
        result["entries"][0]["binary"]["normalized_path"],
        "[redacted_non_system_path]"
    );
    assert_eq!(result["entries"][1]["kind"], "file_system_driver");
    assert_eq!(result["entries"][1]["state"], "stopped");
    assert_eq!(
        result["entries"][1]["binary"]["signature"],
        "verified_embedded"
    );
    assert_eq!(result["entries"][2]["binary"]["file_state"], "virtual");
    assert_eq!(result["entries"][3]["config_error"], "permission_denied");
    assert_eq!(result["entries"][4]["binary"]["file_state"], "missing");
    assert!(result["entries"][4]["indicators"]
        .to_string()
        .contains("file_missing_review"));
    assert!(!result.to_string().contains("password"));
    assert!(!result.to_string().contains("secret"));
}
#[test]
fn drivers_only_does_not_include_user_services() {
    let result = report(fixture(&data()).unwrap(), true, false, r"C:\Windows");
    assert_eq!(result["coverage"]["reported"], 3);
    assert_eq!(result["status"], "partial"); // virtual driver has no resolvable path
}
#[test]
fn show_paths_is_opt_in_and_never_shows_arguments() {
    let result = report(fixture(&data()).unwrap(), false, true, r"C:\Windows");
    assert_eq!(
        result["entries"][0]["binary"]["normalized_path"],
        r"C:\Program Files\Acme\svc.exe"
    );
    assert!(!result.to_string().contains("password"));
}
#[test]
fn rejects_malformed_or_large_fixtures() {
    assert_eq!(fixture(b"not json").unwrap_err(), "invalid_json");
    assert_eq!(fixture(b"{}").unwrap_err(), "unsupported_fixture_schema");
    assert_eq!(
        fixture(&vec![b' '; MAX_FIXTURE_BYTES + 1]).unwrap_err(),
        "fixture_size_limit"
    );
    let oversized = json!({"schema_version":1, "enumeration_status":"complete",
        "services":vec![json!({"name":"X","service_type":1,"state":1});MAX_ENTRIES+1]});
    assert_eq!(
        fixture(&serde_json::to_vec(&oversized).unwrap()).unwrap_err(),
        "entry_limit"
    );
    let invalid = json!({"schema_version":1,"enumeration_status":"complete",
        "services":[{"name":"Hi","service_type":1,"state":1,
                     "file_state":"signed_and_safe"}]});
    assert_eq!(
        fixture(&serde_json::to_vec(&invalid).unwrap()).unwrap_err(),
        "invalid_file_state"
    );
}
#[test]
fn no_entries_and_unavailable_are_not_safety_claims() {
    for enumeration_status in ["complete", "permission_denied", "error"] {
        let x = json!({"schema_version":1,"enumeration_status":enumeration_status,"services":[]});
        let report = report(
            fixture(&serde_json::to_vec(&x).unwrap()).unwrap(),
            false,
            false,
            r"C:\Windows",
        );
        assert_eq!(report["coverage"]["permission_filtered_possible"], true);
        assert_eq!(report["status"], enumeration_status);
        assert_eq!(report["entries"].as_array().unwrap().len(), 0);
    }
}
#[test]
fn duplicate_names_and_privacy_are_bounded() {
    let fixture_json = json!({"schema_version":1, "enumeration_status":"complete",
    "services":[
        {"name":"X","service_type":1,"state":4,"image_path":"%TOKEN%\\x.sys"},
        {"name":"x","service_type":1,"state":4,"image_path":"secret"},
        {"name":"A B","service_type":1,"state":4}
    ]});
    let result = report(
        fixture(&serde_json::to_vec(&fixture_json).unwrap()).unwrap(),
        false,
        false,
        r"C:\Windows",
    );
    assert_eq!(result["status"], "partial");
    assert_eq!(result["coverage"]["reported"], 2);
    assert!(result.to_string().contains("duplicate_service_name"));
    assert!(!result.to_string().contains("TOKEN"));
    assert_eq!(result["entries"][1]["service_name"], "[redacted]");
}
#[test]
fn unicode_and_untrusted_path_rules() {
    let x = json!({"schema_version":1,"enumeration_status":"complete",
        "services":[{"name":"日本語Svc","service_type":1,"state":4,
            "image_path":"\"C:\\Windows\\System32\\drivers\\日本語.sys\" /q",
            "signature":"untrusted_chain"}]});
    let report = report(
        fixture(&serde_json::to_vec(&x).unwrap()).unwrap(),
        true,
        false,
        r"C:\Windows",
    );
    assert_eq!(report["entries"][0]["service_name"], "日本語Svc");
    assert!(report["entries"][0]["binary"]["normalized_path"]
        .as_str()
        .unwrap()
        .contains("日本語.sys"));
    assert_eq!(
        normalize_image_path(r"C:\Windows\..\oops.sys", r"C:\Windows").1,
        "relative_component"
    );
}

#[test]
fn delayed_start_query_failure_is_visible_and_drivers_are_not_applicable() {
    let raw = json!({
        "schema_version":1,
        "enumeration_status":"complete",
        "services":[
            {"name":"AutoSvc","service_type":16,"state":4,"start_type":2,
             "image_path":"C:\\Windows\\System32\\svc.exe",
             "config_error":"permission_denied"},
            {"name":"BootDriver","service_type":1,"state":4,"start_type":0,
             "image_path":"C:\\Windows\\System32\\drivers\\boot.sys"}
        ]
    });
    let result = report(
        fixture(&serde_json::to_vec(&raw).unwrap()).unwrap(),
        false,
        false,
        r"C:\Windows",
    );
    assert_eq!(result["status"], "partial");
    assert_eq!(
        result["entries"][0]["delayed_auto_start_status"],
        "permission_denied"
    );
    assert_eq!(
        result["entries"][0]["delayed_auto_start"],
        serde_json::Value::Null
    );
    assert_eq!(
        result["entries"][1]["delayed_auto_start_status"],
        "not_applicable"
    );
    assert_ne!(result["entries"][0]["delayed_auto_start"], false);
}
