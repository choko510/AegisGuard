use serde_json::{json, Value};
use software_audit::{inspect_fixture_bytes, match_bytes, model, read_bounded};

fn entry(name: &str, version: Option<&str>, publisher: Option<&str>) -> Value {
    json!({"name":name,"version":version,"publisher":publisher})
}
fn fixture(entries: Vec<Value>) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schema_version":1,
        "sources":[
            {"id":"hklm64","status":"complete","entries":entries},
            {"id":"hklm32","status":"complete","entries":[]},
            {"id":"hkcu64","status":"complete","entries":[]},
            {"id":"hkcu32","status":"complete","entries":[]}
        ]
    })).unwrap()
}
fn advisory(now: u64) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schema_version":1,"source_checked_at_unix_ms":now,
        "advisories":[{
            "id":"CVE-2026-12345","vendor":"Example Labs","product":"Widget",
            "product_aliases":["Widget Pro"],"publisher_aliases":["Example Labs LLC"],
            "version_ranges":[{"start_inclusive":"1.0","end_exclusive":"1.10"}],
            "unaffected_versions":["1.9.5"],"architectures":["x64"],"editions":["Pro"],
            "source_url":"https://example.org/security/advisory"
        }]
    })).unwrap()
}
fn evaluate(entries: Vec<Value>, now: u64) -> software_audit::model::MatchReport {
    let inv = inspect_fixture_bytes(&fixture(entries)).unwrap();
    let bytes = serde_json::to_vec(&inv).unwrap();
    match_bytes(&bytes, &advisory(now), now).unwrap()
}
#[test]
fn exact_identity_arch_edition_and_version_are_candidates_only() {
    let now = 1_800_000_000_000;
    let report = evaluate(vec![json!({
        "name":"Widget Pro","version":"1.9","publisher":"Example Labs LLC",
        "architecture":"x64","edition":"Pro"
    })], now);
    assert_eq!(report.status, "complete");
    assert_eq!(report.entries.len(), 1);
    assert_eq!(report.entries[0].classification, "candidate");
    assert_eq!(report.entries[0].confidence, "medium");
    assert_eq!(report.entries[0].source_checked_at_unix_ms, now);
}
#[test]
fn similar_product_or_wrong_vendor_do_not_match() {
    let now = 1_800_000_000_000;
    let report = evaluate(vec![
        json!({"name":"Widget Pro Plus","version":"1.9","publisher":"Example Labs","architecture":"x64","edition":"Pro"}),
        json!({"name":"Widget","version":"1.9","publisher":"Other Labs","architecture":"x64","edition":"Pro"}),
    ], now);
    assert!(report.entries.is_empty());
    assert!(report.warnings.iter().any(|s| s.contains("not_proof_of_safety")));
}
#[test]
fn fixed_boundary_backport_and_arch_edition_mismatch_excluded() {
    let now = 1_800_000_000_000;
    let report = evaluate(vec![
        json!({"name":"Widget","version":"1.10","publisher":"Example Labs","architecture":"x64","edition":"Pro"}),
        json!({"name":"Widget","version":"1.9.5","publisher":"Example Labs","architecture":"x64","edition":"Pro"}),
        json!({"name":"Widget","version":"1.9","publisher":"Example Labs","architecture":"x86","edition":"Pro"}),
        json!({"name":"Widget","version":"1.9","publisher":"Example Labs","architecture":"x64","edition":"Home"}),
    ], now);
    assert!(report.entries.is_empty());
}
#[test]
fn unknown_version_arch_and_publisher_not_confirmed() {
    let now = 1_800_000_000_000;
    let report = evaluate(vec![
        entry("Widget", None, Some("Example Labs")),
        entry("Widget Pro", Some("1.9-beta"), Some("Example Labs")),
        entry("Widget", Some("1.9"), None)
    ], now);
    assert_eq!(report.entries.len(), 3);
    assert!(report.entries.iter().all(|m| m.classification == "unknown" && m.confidence == "low"));
}
#[test]
fn stale_or_future_advisory_cannot_produce_normal_candidate() {
    let now = 1_800_000_000_000;
    let app = json!({"name":"Widget","version":"1.9","publisher":"Example Labs","architecture":"x64","edition":"Pro"});
    for checked in [now - 40 * 86_400_000, now + 400_000] {
        let inv = inspect_fixture_bytes(&fixture(vec![app.clone()])).unwrap();
        let mut data: Value = serde_json::from_slice(&advisory(now)).unwrap();
        data["source_checked_at_unix_ms"] = json!(checked);
        let out = match_bytes(&serde_json::to_vec(&inv).unwrap(), &serde_json::to_vec(&data).unwrap(), now).unwrap();
        assert_eq!(out.status, "partial");
        assert_eq!(out.entries[0].classification, "unknown");
    }
}
#[test]
fn duplicate_registry_views_preserve_sources() {
    let input = json!({"schema_version":1,"sources":[
        {"id":"hklm64","status":"complete","entries":[entry("Widget", Some("1.9"), Some("Example Labs"))]},
        {"id":"hklm32","status":"complete","entries":[entry("Widget", Some("1.9"), Some("Example Labs"))]},
        {"id":"hkcu64","status":"complete","entries":[]},
        {"id":"hkcu32","status":"complete","entries":[]}
    ]});
    let report = inspect_fixture_bytes(&serde_json::to_vec(&input).unwrap()).unwrap();
    assert_eq!(report.entries.len(), 1);
    assert_eq!(report.entries[0].sources.len(), 2);
}
#[test]
fn empty_partial_denied_and_invalid_entries_distinguished() {
    let empty = inspect_fixture_bytes(&fixture(vec![])).unwrap();
    assert_eq!(empty.status, "complete");
    assert!(empty.entries.is_empty());
    let partial = json!({"schema_version":1,"sources":[
        {"id":"hklm64","status":"complete","entries":[entry("Bad\nName",Some("1.0"),None)]},
        {"id":"hkcu64","status":"permission_denied","entries":[]}
    ]});
    let report = inspect_fixture_bytes(&serde_json::to_vec(&partial).unwrap()).unwrap();
    assert_eq!(report.status, "partial");
    assert_eq!(report.coverage.skipped, 1);
    let denied = json!({"schema_version":1,"sources":[
        {"id":"hklm64","status":"permission_denied"},
        {"id":"hklm32","status":"permission_denied"},
        {"id":"hkcu64","status":"permission_denied"},
        {"id":"hkcu32","status":"permission_denied"}
    ]});
    let report = inspect_fixture_bytes(&serde_json::to_vec(&denied).unwrap()).unwrap();
    assert_eq!(report.status, "permission_denied");
}
#[test]
fn malformed_duplicate_oversize_and_cpe_only_rejected() {
    assert!(inspect_fixture_bytes(b"{not-json").is_err());
    assert!(inspect_fixture_bytes(&vec![b'x'; 1024 * 1024 + 1]).is_err());
    assert!(inspect_fixture_bytes(&serde_json::to_vec(&json!({"schema_version":1,"sources":[
        {"id":"hklm64","status":"complete"},{"id":"hklm64","status":"complete"}
    ]})).unwrap()).is_err());
    let inv = inspect_fixture_bytes(&fixture(vec![entry("Widget", Some("1.9"), Some("Example Labs"))])).unwrap();
    let inv_json = serde_json::to_vec(&inv).unwrap();
    assert!(match_bytes(&inv_json, &vec![b' '; 2 * 1024 * 1024 + 1], model::now_ms()).is_err());
    assert!(match_bytes(&inv_json, br#"{"schema_version":1,"advisories":[{"cpe":"cpe:2.3:a:*:*:*"}]}"#, model::now_ms()).is_err());
}
#[test]
fn directory_cannot_be_read_as_input_file() {
    assert!(read_bounded(&std::env::temp_dir(), 64).is_err());
}
#[test]
fn synthetic_negative_cases_have_no_false_candidates() {
    let now = 1_800_000_000_000;
    let mut samples = vec![
        json!({"name":"Widget Plus","version":"1.9","publisher":"Example Labs","architecture":"x64","edition":"Pro"}),
        json!({"name":"Widget","version":"1.9","publisher":"Other Labs","architecture":"x64","edition":"Pro"}),
        json!({"name":"Widget","version":"1.10","publisher":"Example Labs","architecture":"x64","edition":"Pro"}),
        json!({"name":"Widget","version":"1.9","publisher":"Example Labs","architecture":"arm64","edition":"Pro"}),
        json!({"name":"Widget","version":"1.9.5","publisher":"Example Labs","architecture":"x64","edition":"Pro"}),
    ];
    samples.push(json!({"name":"Widget","version":"1.9","publisher":"Example Labs","architecture":"x64","edition":"Pro"}));
    let report = evaluate(samples, now);
    let candidates = report.entries.iter().filter(|m| m.classification == "candidate").count();
    assert_eq!(candidates, 1, "five negative cases must not become candidates");
}
