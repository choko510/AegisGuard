use persistence_audit::{inspect_records, mark_partial, MAX_LINE_BYTES};
use serde_json::{json, Value};

fn fixture() -> &'static [u8] {
    include_bytes!("fixtures/synthetic.jsonl")
}
fn hmac_test_id(seed: u8) -> String {
    format!("h1:{}", format!("{seed:02x}").repeat(32))
}
fn all_done() -> String {
    [
        "registry_hkcu_64_run", "registry_hkcu_64_runonce",
        "registry_hkcu_32_run", "registry_hkcu_32_runonce",
        "registry_hklm_64_run", "registry_hklm_64_runonce",
        "registry_hklm_32_run", "registry_hklm_32_runonce",
        "startup_user", "startup_common", "task_scheduler",
    ]
    .iter()
    .map(|section| json!({"t":"done", "section":section}).to_string())
    .collect::<Vec<_>>()
    .join("\n")
}

#[test]
fn synthetic_fixture_complete_and_private() {
    let report = inspect_records(fixture(), false, 100);
    assert_eq!(report["schema_version"], 2);
    assert_eq!(report["module"], "persistence-audit");
    assert_eq!(report["status"], "complete");
    assert_eq!(report["entry_ids_complete"], true);
    let entries = report["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 5);
    let text = report.to_string();
    for private in ["Alice", "花子", "--quiet", "--check", "raw_target"] {
        assert!(!text.contains(private));
    }
    assert!(text.contains("<redacted>"));
    assert!(entries.iter().all(|e| e["entry_id"].as_str().is_some()));
    assert!(entries.iter().all(|e| !e["location_redacted"].as_str().unwrap().contains('#')));
    assert!(entries.iter().any(|e| e["assessment"]["state"] == "review"));
    assert!(entries.iter().any(|e| e["assessment"]["state"] == "observed"));
    assert!(entries.iter().any(|e| e["assessment"]["state"] == "unknown"));
}

#[test]
fn missing_wmi_sources_are_partial_when_requested() {
    let r = inspect_records(fixture(), true, 100);
    assert_eq!(r["status"], "partial");
    assert_eq!(
        r["coverage"].as_array().unwrap().iter().filter(|c| c["status"] == "not_collected").count(),
        3
    );
}

#[test]
fn cap_never_claims_complete() {
    let r = inspect_records(fixture(), false, 2);
    assert_eq!(r["status"], "partial");
    assert_eq!(r["entries_truncated"], true);
    assert_eq!(r["entries"].as_array().unwrap().len(), 2);
}

#[test]
fn capture_failure_overrides_complete() {
    let mut r = inspect_records(fixture(), false, 100);
    mark_partial(&mut r, "collector_timeout");
    assert_eq!(r["status"], "partial");
    assert!(r["warnings"].as_array().unwrap().iter().any(|v| v["code"] == "collector_timeout"));
}

#[test]
fn unsanitized_legacy_record_is_rejected_no_secret_echo() {
    let mut input = fixture().to_vec();
    input.extend_from_slice(
        b"{\"t\":\"entry\",\"section\":\"startup_user\",\"kind\":\"startup\",\"scope\":\"user\",\"raw_target\":\"C:\\\\safe.exe --token=secretkey\",\"secret\":\"classified\"}\n"
    );
    let report = inspect_records(&input, false, 100);
    let out = report.to_string();
    assert_eq!(report["status"], "partial");
    assert!(!out.contains("secretkey"));
    assert!(!out.contains("classified"));
    assert!(out.contains("unsafe_legacy_record"));
}

#[test]
fn no_raw_command_accepted_even_under_target_path() {
    let mut data = all_done();
    data.push('\n');
    data.push_str(&json!({
        "t":"entry","section":"startup_user","kind":"startup","scope":"user",
        "target_path":"C:\\Tools\\agent.exe --password secret",
        "entry_id":hmac_test_id(9)
    }).to_string());
    let r = inspect_records(data.as_bytes(), false, 10);
    assert_eq!(r["status"], "complete");
    assert_eq!(r["entries"][0]["target_path"], Value::Null);
    assert!(!r.to_string().contains("secret"));
}

#[test]
fn oversize_record_and_invalid_utf8_fail_closed() {
    let too_long = vec![b'x'; MAX_LINE_BYTES + 1];
    assert_ne!(inspect_records(&too_long, false, 100)["status"], "complete");
    assert_eq!(inspect_records(&[0xff, b'\n'], false, 100)["status"], "error");
}

#[test]
fn stable_ids_survive_enumeration_reorder() {
    let a = json!({"t":"entry","section":"registry_hkcu_64_run","kind":"run","scope":"user",
        "target_path":"C:\\Tools\\a.exe","entry_id":hmac_test_id(1)});
    let b = json!({"t":"entry","section":"registry_hkcu_64_run","kind":"run","scope":"user",
        "target_path":"C:\\Tools\\b.exe","entry_id":hmac_test_id(2)});
    let input_a = format!("{}\n{}\n{}\n",a,b,all_done());
    let input_b = format!("{}\n{}\n{}\n",b,a,all_done());
    let r1 = inspect_records(input_a.as_bytes(), false, 10);
    let r2 = inspect_records(input_b.as_bytes(), false, 10);
    assert_eq!(r1["status"], "complete");
    assert_eq!(r2["status"], "complete");
    let mut ids_a: Vec<_> = r1["entries"].as_array().unwrap().iter().map(|e| e["entry_id"].as_str().unwrap()).collect();
    let mut ids_b: Vec<_> = r2["entries"].as_array().unwrap().iter().map(|e| e["entry_id"].as_str().unwrap()).collect();
    ids_a.sort_unstable();
    ids_b.sort_unstable();
    assert_eq!(ids_a, ids_b);
}

#[test]
fn duplicate_identity_is_not_reported_twice() {
    let a = json!({"t":"entry","section":"startup_user","kind":"startup","scope":"user",
        "entry_id":hmac_test_id(3),"target_path":"C:\\Tools\\a.exe"});
    let b = json!({"t":"entry","section":"startup_user","kind":"startup","scope":"user",
        "entry_id":hmac_test_id(3),"target_path":"C:\\Tools\\b.exe"});
    let data = format!("{}\n{}\n{}\n", a, b, all_done());
    let r = inspect_records(data.as_bytes(), false, 10);
    assert_eq!(r["entries"].as_array().unwrap().len(), 1);
    assert!(r["warnings"].as_array().unwrap().iter().any(|e| e["code"] == "duplicate_entry_id"));
    assert_eq!(r["status"], "partial");
}

#[test]
fn missing_id_does_not_forge_stability() {
    let data = format!("{}\n{}\n",
        json!({"t":"entry","section":"startup_user","kind":"startup","scope":"user",
            "entry_id":null,"target_path":null}),all_done());
    let r = inspect_records(data.as_bytes(), false, 10);
    assert_eq!(r["status"], "complete");
    assert_eq!(r["entry_ids_complete"], false);
    assert_eq!(r["entries"][0]["entry_id"], Value::Null);
    assert!(r["warnings"].as_array().unwrap().iter().any(|e| e["code"] == "stable_id_key_unavailable_for_some_entries"));
}

#[test]
fn wmi_template_only_static_and_dynamic_are_distinct() {
    let mut data = fixture().to_vec();
    for (n, source, dynamic, target) in [
        (11u8,"template_static","not_observed",Some("C:\\Windows\\System32\\cmd.exe")),
        (12u8,"template_unresolved","possible",None),
    ] {
        data.extend_from_slice(json!({
            "t":"entry","section":"wmi_consumer","kind":"wmi_consumer","scope":"machine",
            "entry_id":hmac_test_id(n),"target_path":target,
            "template_present":true,"template_dynamic_target":dynamic,"target_source":source
        }).to_string().as_bytes());
        data.push(b'\n');
    }
    for (n, section) in [(13u8,"wmi_filter"),(14u8,"wmi_binding")] {
        data.extend_from_slice(json!({
            "t":"entry","section":section,"kind":section,"scope":"machine",
            "entry_id":hmac_test_id(n),"target_path":null
        }).to_string().as_bytes());
        data.push(b'\n');
    }
    for section in ["wmi_filter","wmi_consumer","wmi_binding"] {
        data.extend_from_slice(json!({"t":"done","section":section}).to_string().as_bytes());
        data.push(b'\n');
    }
    let r = inspect_records(&data,true,100);
    assert_eq!(r["status"], "complete");
    let entries = r["entries"].as_array().unwrap();
    let wmi: Vec<_> = entries.iter().filter(|e| e["kind"] == "wmi_consumer").collect();
    assert_eq!(wmi.len(),2);
    assert_eq!(wmi[0]["assessment"]["priority"],"medium");
    assert_eq!(wmi[0]["wmi_template"]["target_source"],"template_static");
    assert_eq!(wmi[1]["assessment"]["state"],"unknown");
    assert_eq!(wmi[1]["assessment"]["priority"],"medium");
    assert_eq!(wmi[1]["assessment"]["reason"],"wmi_event_variable_may_control_target");
    assert_eq!(wmi[1]["target_path"],Value::Null);
    assert!(entries.iter().filter(|e| e["kind"] == "wmi_binding").all(|e| e["assessment"]["state"] == "unknown"));
}

#[test]
fn unresolved_wmi_executable_is_still_a_review_lead() {
    let data = format!("{}\n{}\n",
        json!({
            "t":"entry","section":"wmi_consumer","kind":"wmi_consumer","scope":"machine",
            "entry_id":hmac_test_id(20),"target_path":null,
            "template_present":false,"template_dynamic_target":"not_applicable",
            "target_source":"executable_path"
        }),
        all_done()
    );
    let r = inspect_records(data.as_bytes(), true, 10);
    assert_eq!(r["entries"][0]["assessment"]["state"], "unknown");
    assert_eq!(r["entries"][0]["assessment"]["priority"], "medium");
    assert_eq!(r["entries"][0]["target_path"], Value::Null);
}

#[test]
fn invalid_id_does_not_pass_through() {
    let data = format!("{}\n{}\n",
        json!({"t":"entry","section":"startup_user","kind":"startup","scope":"user",
            "entry_id":"registry-secret","target_path":"C:\\Tools\\a.exe"}),all_done());
    let r = inspect_records(data.as_bytes(), false, 10);
    assert_eq!(r["status"], "partial");
    assert_eq!(r["entries"].as_array().unwrap().len(), 0);
    assert!(!r.to_string().contains("registry-secret"));
}

#[test]
fn permission_denied_source_not_treated_as_zero_entries() {
    let r = inspect_records(
        b"{\"t\":\"issue\",\"section\":\"registry_hklm_32_run\",\"code\":\"permission_denied\"}\n",
        false,100
    );
    assert_eq!(r["status"], "permission_denied");
}
