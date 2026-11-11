//! Read-only, versioned persistence inventory and fixture analysis.
//! Command strings are sanitized inside the Windows collector before IPC.

use serde_json::{json, Value};
use std::collections::{BTreeMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(windows)]
pub mod windows;

pub const MAX_CAPTURE_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_LINE_BYTES: usize = 8 * 1024;
pub const DEFAULT_LIMIT: usize = 500;
pub const MAX_LIMIT: usize = 2_000;
const BASE_SECTIONS: &[&str] = &[
    "registry_hkcu_64_run",
    "registry_hkcu_64_runonce",
    "registry_hkcu_32_run",
    "registry_hkcu_32_runonce",
    "registry_hklm_64_run",
    "registry_hklm_64_runonce",
    "registry_hklm_32_run",
    "registry_hklm_32_runonce",
    "startup_user",
    "startup_common",
    "task_scheduler",
];
const WMI_SECTIONS: &[&str] = &["wmi_filter", "wmi_consumer", "wmi_binding"];

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis())
}

fn sections(include_wmi: bool) -> Vec<&'static str> {
    let mut ids = BASE_SECTIONS.to_vec();
    if include_wmi {
        ids.extend_from_slice(WMI_SECTIONS);
    }
    ids
}

fn warning(source: &str, code: &str) -> Value {
    json!({"source": source, "code": code})
}

pub fn failure_report(include_wmi: bool, status: &str, code: &str) -> Value {
    let coverage: Vec<Value> = sections(include_wmi)
        .iter()
        .map(|id| json!({"source": id, "status": "not_collected"}))
        .collect();
    json!({
        "schema_version": 2,
        "module": "persistence-audit",
        "generated_at_unix_ms": now_ms(),
        "status": status,
        "entries": [],
        "warnings": [warning("collector", code)],
        "coverage": coverage,
        "entries_truncated": false,
        "entry_ids_complete": false,
        "meaning": "No findings is not proof of a safe system"
    })
}

/// Add a transport failure after decoding any partial collector output.
pub fn mark_partial(report: &mut Value, code: &str) {
    if let Some(warnings) = report["warnings"].as_array_mut() {
        warnings.push(warning("collector", code));
    }
    if report["status"] == "complete" {
        report["status"] = json!("partial");
    }
}

/// Decode the bounded, one-record-per-line collector contract. This is also the
/// fixture path, so parsing and classification can be tested without Windows.
pub fn inspect_records(input: &[u8], include_wmi: bool, limit: usize) -> Value {
    if input.len() > MAX_CAPTURE_BYTES {
        return failure_report(include_wmi, "error", "input_too_large");
    }
    let limit = limit.clamp(1, MAX_LIMIT);
    let expected = sections(include_wmi);
    let mut coverage: BTreeMap<&str, &'static str> =
        expected.iter().map(|x| (*x, "not_collected")).collect();
    let mut warnings = Vec::<Value>::new();
    let mut entries = Vec::<Value>::new();
    let mut unique = HashSet::<Vec<u8>>::new();
    let mut seen_ids = HashSet::<String>::new();
    let mut ids_missing = false;
    let mut truncated = false;
    let mut rows = 0usize;

    for line in input.split(|c| *c == b'\n').filter(|row| !row.is_empty()) {
        rows += 1;
        if rows > 10_000 {
            warnings.push(warning("input", "record_count_limit"));
            truncated = true;
            break;
        }
        if line.len() > MAX_LINE_BYTES {
            warnings.push(warning("input", "record_too_large"));
            truncated = true;
            continue;
        }
        let record: Value = match serde_json::from_slice(line) {
            Ok(Value::Object(v)) => Value::Object(v),
            _ => {
                warnings.push(warning("input", "invalid_record"));
                continue;
            }
        };
        let Some(section) = record["section"].as_str() else {
            warnings.push(warning("input", "invalid_record"));
            continue;
        };
        if !coverage.contains_key(section) {
            warnings.push(warning("input", "unknown_section"));
            continue;
        }
        match record["t"].as_str() {
            Some("done") => {
                if coverage[section] == "not_collected" {
                    coverage.insert(
                        expected
                            .iter()
                            .copied()
                            .find(|s| *s == section)
                            .unwrap_or(""),
                        "complete",
                    );
                }
            }
            Some("issue") => {
                let code = match record["code"].as_str() {
                    Some("permission_denied") => "permission_denied",
                    Some("limit_reached") => "limit_reached",
                    Some("unavailable") => "unavailable",
                    Some("timeout") => "timeout",
                    _ => "enumeration_error",
                };
                let state = if code == "permission_denied" {
                    "permission_denied"
                } else {
                    "unavailable"
                };
                let id = expected
                    .iter()
                    .copied()
                    .find(|s| *s == section)
                    .unwrap_or("");
                coverage.insert(id, state);
                warnings.push(warning(section, code));
                if code == "limit_reached" {
                    truncated = true;
                }
            }
            Some("entry") => {
                // Reject legacy raw command fields, including in untrusted fixtures.
                if record.get("raw_target").is_some() {
                    warnings.push(warning(section, "unsafe_legacy_record"));
                    continue;
                }
                if !unique.insert(line.to_vec()) {
                    warnings.push(warning(section, "duplicate_record"));
                    continue;
                }
                let kind = match record["kind"].as_str() {
                    Some("run") => "run",
                    Some("run_once") => "run_once",
                    Some("startup") => "startup",
                    Some("scheduled_task") => "scheduled_task",
                    Some("wmi_filter") => "wmi_filter",
                    Some("wmi_consumer") => "wmi_consumer",
                    Some("wmi_binding") => "wmi_binding",
                    _ => {
                        warnings.push(warning(section, "invalid_record"));
                        continue;
                    }
                };
                let scope = match record["scope"].as_str() {
                    Some("user") => "user",
                    Some("machine") => "machine",
                    _ => "unknown",
                };
                let entry_id = match record.get("entry_id") {
                    Some(Value::String(id)) if valid_entry_id(id) => Some(id.as_str()),
                    Some(Value::Null) | None => None,
                    _ => {
                        warnings.push(warning(section, "invalid_entry_id"));
                        continue;
                    }
                };
                if let Some(id) = entry_id {
                    if !seen_ids.insert(format!("{section}/{id}")) {
                        warnings.push(warning(section, "duplicate_entry_id"));
                        continue;
                    }
                } else {
                    ids_missing = true;
                }
                if entries.len() >= limit {
                    truncated = true;
                    continue;
                }
                // This is already a sanitized *executable only*, never a command.
                let target = validate_target(record["target_path"].as_str());
                let mut assessment = assess(kind, target.as_deref());
                let mut wmi_template = None;
                if kind == "wmi_consumer" {
                    let present = record["template_present"].as_bool();
                    let dynamic = match record["template_dynamic_target"].as_str() {
                        Some("possible") => "possible",
                        Some("not_observed") => "not_observed",
                        Some("not_applicable") => "not_applicable",
                        _ => "unknown",
                    };
                    let source = match record["target_source"].as_str() {
                        Some("executable_path") => "executable_path",
                        Some("template_static") => "template_static",
                        Some("template_dynamic") => "template_dynamic",
                        Some("template_unresolved") => "template_unresolved",
                        _ => "unresolved",
                    };
                    if dynamic == "possible" && source != "executable_path" {
                        assessment = ("unknown", "medium", "wmi_event_variable_may_control_target");
                    } else if (present == Some(true) || source == "executable_path")
                        && target.is_none()
                    {
                        assessment = ("unknown", "medium", "wmi_template_target_unresolved");
                    } else if source == "template_static" && target.is_some() {
                        assessment = ("review", "medium", "wmi_template_launch_review");
                    }
                    wmi_template = Some(json!({
                        "present": present,
                        "dynamic_target": dynamic,
                        "target_source": source
                    }));
                }
                let mut entry = json!({
                    "kind": kind,
                    "scope": scope,
                    "location_redacted": section,
                    "entry_id": entry_id,
                    "target_path": target,
                    "signature_status": "not_checked",
                    "evidence": ["read_only_enumeration", "signature_not_verified"],
                    "assessment": {
                        "state": assessment.0,
                        "priority": assessment.1,
                        "reason": assessment.2
                    }
                });
                if let Some(metadata) = wmi_template {
                    entry["wmi_template"] = metadata;
                }
                entries.push(entry);
            }
            _ => warnings.push(warning(section, "invalid_record")),
        }
    }

    if truncated {
        warnings.push(warning("input", "entry_or_record_limit"));
    }
    if ids_missing {
        warnings.push(warning(
            "input",
            "stable_id_key_unavailable_for_some_entries",
        ));
    }
    let complete = coverage.values().filter(|s| **s == "complete").count();
    let denied = coverage
        .values()
        .filter(|s| **s == "permission_denied")
        .count();
    let all_complete = complete == expected.len();
    let bad_input = warnings.iter().any(|v| {
        matches!(
            v["code"].as_str(),
            Some(
                "invalid_record"
                    | "record_too_large"
                    | "record_count_limit"
                    | "unknown_section"
                    | "unsafe_legacy_record"
                    | "invalid_entry_id"
                    | "duplicate_entry_id"
            )
        )
    });
    let status = if all_complete && !truncated && !bad_input {
        "complete"
    } else if complete > 0 || !entries.is_empty() {
        "partial"
    } else if denied > 0 {
        "permission_denied"
    } else if bad_input {
        "error"
    } else {
        "unavailable"
    };
    let coverage: Vec<Value> = coverage
        .into_iter()
        .map(|(source, status)| json!({"source": source, "status": status}))
        .collect();
    json!({
        "schema_version": 2,
        "module": "persistence-audit",
        "generated_at_unix_ms": now_ms(),
        "status": status,
        "entries": entries,
        "warnings": warnings,
        "coverage": coverage,
        "entries_truncated": truncated,
        "entry_ids_complete": !ids_missing && !entries.is_empty(),
        "meaning": "Priority is for human investigation, not a malware verdict"
    })
}

/// Accept only an already-sanitized executable path from the collector.
/// Never reinterpret a command line or carry arbitrary fixture strings forward.
fn validate_target(value: Option<&str>) -> Option<String> {
    let value = value?;
    if value.is_empty() || value.len() > 1024 || value.trim() != value {
        return None;
    }
    if value.chars().any(|c| c.is_control())
        || value.contains('"')
        || value.contains('\'')
        || value.replace("<redacted>", "").contains('<')
        || value.replace("<redacted>", "").contains('>')
        || value.chars().any(|c| matches!(c, ';' | '&' | '|' | '@'))
        || value.contains("://")
        || value.starts_with(r"\\")
    {
        return None;
    }
    let lower = value.to_ascii_lowercase();
    if ![".exe", ".com", ".cmd", ".bat", ".ps1", ".vbs", ".lnk"]
        .iter()
        .any(|suffix| lower.ends_with(suffix))
    {
        return None;
    }
    // C:\Users\<redacted> is allowed. A raw profile username isn't.
    let parts: Vec<&str> = value.split('\\').collect();
    if parts.len() > 2
        && parts[0].ends_with(':')
        && parts[1].eq_ignore_ascii_case("users")
        && parts[2] != "<redacted>"
    {
        return None;
    }
    if value.contains('%') {
        let allowed = [
            "%systemroot%",
            "%windir%",
            "%programfiles%",
            "%programfiles(x86)%",
            "%appdata%",
            "%localappdata%",
            "%userprofile%",
            "%temp%",
            "%tmp%",
        ];
        if !allowed.iter().any(|prefix| lower.starts_with(prefix))
            || lower.matches('%').count() != 2
        {
            return None;
        }
    }
    // No whitespace other than spaces in a static path; no raw command options.
    if value.contains(" --")
        || value.contains(" /")
        || value.contains(" -")
        || value.contains('=')
        || [".exe ", ".cmd ", ".bat ", ".com ", ".ps1 ", ".vbs "]
            .iter()
            .any(|suffix| lower.contains(suffix))
    {
        return None;
    }
    Some(value.to_string())
}

fn valid_entry_id(value: &str) -> bool {
    value.strip_prefix("h1:").is_some_and(|v| {
        v.len() == 64
            && v.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

fn assess(kind: &str, target: Option<&str>) -> (&'static str, &'static str, &'static str) {
    if kind == "wmi_filter" || kind == "wmi_binding" {
        return ("unknown", "unrated", "subscription_metadata_only");
    }
    let Some(target) = target else {
        return ("unknown", "unrated", "target_unresolved");
    };
    let p = target.to_ascii_lowercase();
    let executable = [".exe", ".com", ".cmd", ".bat", ".ps1", ".vbs"]
        .iter()
        .any(|suffix| p.ends_with(suffix));
    if !executable {
        return ("unknown", "unrated", "target_not_executable_or_unresolved");
    }
    if [
        "powershell.exe",
        "pwsh.exe",
        "cmd.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
        "rundll32.exe",
    ]
    .iter()
    .any(|suffix| p.ends_with(suffix))
    {
        return ("review", "medium", "script_or_proxy_host_needs_context");
    }
    if p.contains(r"\appdata\")
        || p.contains(r"\temp\")
        || p.contains(r"\downloads\")
        || p.starts_with(r"%appdata%\")
        || p.starts_with(r"%temp%\")
        || p.starts_with(r"%localappdata%\")
    {
        return ("review", "medium", "user_writable_location_not_proof");
    }
    if p.contains(r"\program files\")
        || p.contains(r"\windows\system32\")
        || p.starts_with(r"%programfiles%\")
        || p.starts_with(r"%systemroot%\")
    {
        return ("observed", "low", "common_install_location_unverified");
    }
    ("unknown", "unrated", "location_not_enough_to_assess")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full_empty() -> Vec<u8> {
        sections(false)
            .iter()
            .map(|s| format!(r#"{{"t":"done","section":"{s}"}}"#))
            .collect::<Vec<_>>()
            .join("\n")
            .into_bytes()
    }

    #[test]
    fn empty_but_collected_is_not_safe() {
        let report = inspect_records(&full_empty(), false, 10);
        assert_eq!(report["status"], "complete");
        assert_eq!(report["entries"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn missing_sections_are_partial_not_complete() {
        let r = inspect_records(br#"{"t":"done","section":"startup_user"}"#, false, 10);
        assert_eq!(r["status"], "partial");
    }

    #[test]
    fn rejects_unsanitized_commands() {
        assert_eq!(
            validate_target(Some(r"C:\Tools\agent.exe --token secret")),
            None
        );
        assert_eq!(
            validate_target(Some(r"C:\Users\Alice\AppData\agent.exe")),
            None
        );
        assert_eq!(validate_target(Some(r"\\server\share\a.exe")), None);
        assert_eq!(validate_target(Some("https://secret.example/a.exe")), None);
        assert_eq!(
            validate_target(Some(r"C:\Users\<redacted>\AppData\Updater.exe")),
            Some(r"C:\Users\<redacted>\AppData\Updater.exe".to_string())
        );
        assert_eq!(assess("run", None).0, "unknown");
    }

    #[test]
    fn stable_id_shape_is_strict() {
        let id = format!("h1:{}", "a".repeat(64));
        assert!(valid_entry_id(&id));
        assert!(!valid_entry_id("h1:abc"));
        assert!(!valid_entry_id(&format!("h1:{}", "G".repeat(64))));
    }

    #[test]
    fn normal_updater_not_declared_clean() {
        assert_eq!(
            assess("run", Some(r"C:\Program Files\Acme\updater.exe")).0,
            "observed"
        );
        assert_eq!(
            assess("run", Some(r"C:\Users\<redacted>\AppData\Local\a.exe")).0,
            "review"
        );
    }

    #[test]
    fn limits_and_malformed_are_not_clean() {
        let huge = vec![b'x'; MAX_CAPTURE_BYTES + 1];
        assert_eq!(inspect_records(&huge, false, 10)["status"], "error");
        assert_eq!(
            inspect_records(b"invalid json", false, 10)["status"],
            "error"
        );
        let bad = format!("{{\"t\":\"entry\",\"section\":\"startup_user\",\"kind\":\"startup\",\"raw_target\":\"{}\"}}", "x".repeat(10_000));
        assert_eq!(
            inspect_records(bad.as_bytes(), false, 10)["status"],
            "error"
        );
    }

    #[test]
    fn respects_cap_and_duplicate() {
        let a = br#"{"t":"entry","section":"startup_user","kind":"startup","scope":"user","target_path":"C:\\Tools\\a.exe"}"#;
        let mut rows = vec![a.to_vec(), a.to_vec()];
        rows.extend(full_empty().split(|b| *b == b'\n').map(|r| r.to_vec()));
        let data = rows.join(&b'\n');
        let r = inspect_records(&data, false, 1);
        assert_eq!(r["entries"].as_array().unwrap().len(), 1);
        assert_eq!(r["status"], "complete");
        assert!(r["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["code"] == "duplicate_record"));
    }

    #[test]
    fn permission_denied_is_not_empty_success() {
        let r = inspect_records(
            br#"{"t":"issue","section":"registry_hklm_64_run","code":"permission_denied"}"#,
            false,
            10,
        );
        assert_eq!(r["status"], "permission_denied");
    }
}
