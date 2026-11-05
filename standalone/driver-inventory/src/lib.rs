//! A bounded, observation-only SCM driver/service inventory. No root-crate imports.
use serde_json::{json, Value};
use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

pub const MAX_ENTRIES: usize = 4096;
pub const MAX_FIXTURE_BYTES: usize = 256 * 1024;
pub const MAX_IMAGE_UNITS: usize = 2048;
pub const MAX_ENUM_PAGES: usize = 32;
pub const MAX_DURATION_MS: u128 = 10_000;
pub const SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug)]
pub struct RawService {
    pub name: String,
    pub evidence_source: &'static str,
    pub service_type: u32,
    pub state: u32,
    pub start_type: Option<u32>,
    pub image_path: Option<String>,
    pub delayed_auto_start: Option<bool>,
    pub dependency_count: Option<usize>,
    pub config_error: Option<&'static str>,
    pub file_state: Option<&'static str>,
    pub signature: Option<&'static str>,
}

#[derive(Debug)]
pub struct Collection {
    pub services: Vec<RawService>,
    pub enumeration_status: &'static str,
    pub error_code: Option<&'static str>,
    pub pages: usize,
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .unwrap_or(0)
}

pub fn is_driver(t: u32) -> bool {
    t & 0x0b != 0
}

pub fn kind(t: u32) -> &'static str {
    if t & 0x01 != 0 { "kernel_driver" }
    else if t & 0x02 != 0 { "file_system_driver" }
    else if t & 0x08 != 0 { "recognizer_driver" }
    else if t & 0x10 != 0 { "win32_own_process" }
    else if t & 0x20 != 0 { "win32_shared_process" }
    else { "unknown" }
}

pub fn state(s: u32) -> &'static str {
    match s {
        1 => "stopped", 2 => "start_pending", 3 => "stop_pending",
        4 => "running", 5 => "continue_pending", 6 => "pause_pending",
        7 => "paused", _ => "unknown",
    }
}

pub fn start_type(s: Option<u32>) -> &'static str {
    match s {
        Some(0) => "boot", Some(1) => "system", Some(2) => "automatic",
        Some(3) => "demand", Some(4) => "disabled",
        _ => "unknown",
    }
}

pub fn sanitized_name(name: &str) -> String {
    // A service key name is useful for correlation, but control characters,
    // private command text and very long names must never reach the report.
    if name.is_empty() || name.chars().count() > 128
        || !name.chars().all(|c| c.is_alphanumeric() || matches!(c, '_' | '-' | '.'))
    {
        "[redacted]".to_string()
    } else {
        name.to_string()
    }
}

/// Resolve only trustworthy Windows-system aliases; never run or expand
/// an arbitrary environment variable. Discard command-line arguments.
pub fn normalize_image_path(raw: &str, windows_dir: &str) -> (Option<String>, &'static str) {
    let s = raw.trim();
    if s.is_empty() { return (None, "empty_image_path"); }
    if s.encode_utf16().count() > MAX_IMAGE_UNITS || s.contains('\0') {
        return (None, "image_path_limit");
    }
    let candidate = if let Some(rest) = s.strip_prefix('"') {
        match rest.find('"') {
            Some(end) => &rest[..end],
            None => return (None, "unclosed_quote"),
        }
    } else {
        // Do not guess which executable the SCM will choose from an
        // unquoted service command with spaces.
        if let Some(index) = s.find(char::is_whitespace) {
            let prefix = &s[..index];
            if !has_binary_suffix(prefix) {
                return (None, "ambiguous_unquoted_path");
            }
            prefix
        } else { s }
    };
    let cleaned = candidate.replace('/', r"\");
    if cleaned.split('\\').any(|p| p == ".." || p == ".") {
        return (None, "relative_component");
    }
    let lower = cleaned.to_ascii_lowercase();
    let win = windows_dir.trim_end_matches(['\\', '/']);
    let resolved = if lower.starts_with(r"\systemroot\") {
        format!(r"{}\{}", win, &cleaned[r"\SystemRoot\".len()..])
    } else if lower.starts_with(r"%systemroot%\") {
        format!(r"{}\{}", win, &cleaned[r"%SystemRoot%\".len()..])
    } else if lower.starts_with(r"%windir%\") {
        format!(r"{}\{}", win, &cleaned[r"%windir%\".len()..])
    } else if lower.starts_with(r"system32\") {
        format!(r"{}\{}", win, cleaned)
    } else if lower.starts_with(r"\??\") {
        cleaned[r"\??\".len()..].to_string()
    } else if lower.starts_with(r"\\?\") {
        cleaned[r"\\?\".len()..].to_string()
    } else { cleaned };
    let chars = resolved.as_bytes();
    if chars.len() < 3 || !chars[0].is_ascii_alphabetic() || chars[1] != b':' || chars[2] != b'\\'
        || resolved.contains('%') || resolved.starts_with(r"\\")
    {
        return (None, "unresolved_image_path");
    }
    if !has_binary_suffix(&resolved) {
        return (None, "unsupported_binary_name");
    }
    (Some(resolved), "resolved")
}

fn has_binary_suffix(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    [".exe", ".sys", ".dll"].iter().any(|suffix| l.ends_with(suffix))
}

fn disclosed_path(path: &str, windows_dir: &str, show_paths: bool) -> String {
    if show_paths { return path.to_string(); }
    let p = path.to_ascii_lowercase();
    let prefix = format!("{}\\", windows_dir.trim_end_matches(['\\', '/']).to_ascii_lowercase());
    if p.starts_with(&prefix) { path.to_string() }
    else { "[redacted_non_system_path]".to_string() }
}

fn accepted_file_state(s: &str) -> Option<&'static str> {
    match s {
        "exists" => Some("exists"), "missing" => Some("missing"),
        "permission_denied" => Some("permission_denied"),
        "unknown" => Some("unknown"), "virtual" => Some("virtual"),
        "not_checked" => Some("not_checked"), "error" => Some("error"),
        _ => None,
    }
}
fn accepted_signature(s: &str) -> Option<&'static str> {
    match s {
        "not_checked" => Some("not_checked"), "verified_embedded" => Some("verified_embedded"),
        "invalid" => Some("invalid"), "unknown" => Some("unknown"),
        "untrusted_chain" => Some("untrusted_chain"),
        _ => None,
    }
}
fn accepted_error(s: &str) -> Option<&'static str> {
    match s {
        "permission_denied" => Some("permission_denied"), "unavailable" => Some("unavailable"),
        "error" => Some("error"), "config_too_large" => Some("config_too_large"),
        _ => None,
    }
}
fn accepted_status(s: &str) -> Option<&'static str> {
    match s {
        "complete" => Some("complete"), "partial" => Some("partial"),
        "unavailable" => Some("unavailable"), "permission_denied" => Some("permission_denied"),
        "error" => Some("error"), _ => None,
    }
}

pub fn fixture(bytes: &[u8]) -> Result<Collection, &'static str> {
    if bytes.len() > MAX_FIXTURE_BYTES { return Err("fixture_size_limit"); }
    let root: Value = serde_json::from_slice(bytes).map_err(|_| "invalid_json")?;
    let obj = root.as_object().ok_or("invalid_fixture_root")?;
    if obj.get("schema_version").and_then(Value::as_u64) != Some(1) {
        return Err("unsupported_fixture_schema");
    }
    let status = obj.get("enumeration_status")
        .and_then(Value::as_str).and_then(accepted_status).ok_or("invalid_enumeration_status")?;
    let list = obj.get("services").and_then(Value::as_array).ok_or("invalid_services")?;
    if list.len() > MAX_ENTRIES { return Err("entry_limit"); }
    let mut services = Vec::with_capacity(list.len());
    for record in list {
        let o = record.as_object().ok_or("invalid_service")?;
        let name = o.get("name").and_then(Value::as_str).ok_or("invalid_name")?;
        if name.encode_utf16().count() > 256 { return Err("name_limit"); }
        let t = o.get("service_type").and_then(Value::as_u64)
            .and_then(|n| u32::try_from(n).ok()).ok_or("invalid_service_type")?;
        let state = o.get("state").and_then(Value::as_u64)
            .and_then(|n| u32::try_from(n).ok()).ok_or("invalid_state")?;
        let start = match o.get("start_type") {
            None | Some(Value::Null) => None,
            Some(v) => Some(u32::try_from(v.as_u64().ok_or("invalid_start_type")?)
                .map_err(|_| "invalid_start_type")?),
        };
        let image_path = match o.get("image_path") {
            None | Some(Value::Null) => None,
            Some(v) => {
                let p = v.as_str().ok_or("invalid_image_path")?;
                if p.encode_utf16().count() > MAX_IMAGE_UNITS { return Err("image_path_limit"); }
                Some(p.to_string())
            }
        };
        let delayed = match o.get("delayed_auto_start") {
            None | Some(Value::Null) => None,
            Some(v) => Some(v.as_bool().ok_or("invalid_delay")?),
        };
        let dependency_count = match o.get("dependency_count") {
            None | Some(Value::Null) => None,
            Some(v) => {
                let n = v.as_u64().ok_or("invalid_dependency_count")?;
                if n > 64 { return Err("dependency_limit"); }
                Some(n as usize)
            }
        };
        let config_error = o.get("config_error").filter(|v| !v.is_null())
            .map(|v| v.as_str().and_then(accepted_error).ok_or("invalid_config_error"))
            .transpose()?;
        let file_state = o.get("file_state").filter(|v| !v.is_null())
            .map(|v| v.as_str().and_then(accepted_file_state).ok_or("invalid_file_state"))
            .transpose()?;
        let signature = o.get("signature").filter(|v| !v.is_null())
            .map(|v| v.as_str().and_then(accepted_signature).ok_or("invalid_signature"))
            .transpose()?;
        services.push(RawService { name: name.to_string(), evidence_source: "fixture", service_type: t,
            state, start_type: start, image_path, delayed_auto_start: delayed,
            dependency_count, config_error, file_state, signature });
    }
    Ok(Collection { services, enumeration_status: status, error_code: None, pages: 0 })
}

pub fn error_report(code: &'static str) -> Value {
    json!({
        "schema_version": SCHEMA_VERSION, "module": "driver-inventory",
        "generated_at_unix_ms": now_ms(), "status": "error",
        "entries": [], "warnings": [code],
        "coverage": {"enumerated": 0, "reported": 0, "scope": "none",
            "max_entries": MAX_ENTRIES, "complete_for_visible_services": false,
            "permission_filtered_possible": true}
    })
}

/// No probing occurs for fixtures, even if a fixture mentions a real OS path.
/// Live probes are performed by the Windows backend and supplied as evidence.
pub fn report(collection: Collection, drivers_only: bool, show_paths: bool, windows_dir: &str) -> Value {
    let enumerated = collection.services.len();
    let mut entries = Vec::new();
    let mut warnings = vec!["scm_permission_filtered_possible".to_string()];
    let mut seen = HashSet::new();
    let mut partial = false;
    let mut truncated = false;
    for s in collection.services {
        if drivers_only && !is_driver(s.service_type) { continue; }
        if entries.len() >= MAX_ENTRIES { truncated = true; break; }
        let service_name = sanitized_name(&s.name);
        if service_name == "[redacted]" { partial = true; }
        if !seen.insert(s.name.to_lowercase()) {
            partial = true;
            warnings.push("duplicate_service_name".into());
            continue;
        }
        let (normalized, path_reason) = match s.image_path.as_deref() {
            Some(raw) => normalize_image_path(raw, windows_dir),
            None => (None, "image_path_unavailable"),
        };
        let file_state = s.file_state.unwrap_or("not_checked");
        let signature = s.signature.unwrap_or("not_checked");
        let mut indicators: Vec<&str> = Vec::new();
        if normalized.is_none() { indicators.push(path_reason); partial = true; }
        if file_state == "missing" { indicators.push("file_missing_review"); }
        if signature == "invalid" { indicators.push("invalid_embedded_signature_review"); }
        if s.config_error.is_some() { partial = true; indicators.push("config_not_assessed"); }
        if matches!(file_state, "permission_denied" | "error") { partial = true; }
        let is_fixture = s.evidence_source == "fixture";
        entries.push(json!({
            "service_name": service_name, "kind": kind(s.service_type),
            "service_type_raw": s.service_type, "state": state(s.state),
            "start_type": start_type(s.start_type), "delayed_auto_start": s.delayed_auto_start,
            "delayed_auto_start_status": if is_driver(s.service_type) || s.start_type != Some(2) {
                "not_applicable"
            } else if s.delayed_auto_start.is_some() {
                "known"
            } else if s.config_error == Some("permission_denied") {
                "permission_denied"
            } else {
                "unknown"
            },
            "dependency_count": s.dependency_count,
            "binary": {
                "normalized_path": normalized.map(|p| disclosed_path(&p, windows_dir, show_paths)),
                "path_resolution": path_reason, "file_state": file_state,
                "signature": signature,
                "signature_scope": if is_fixture { "fixture_assertion" } else { "embedded_only" },
                "file_state_source": if is_fixture { "fixture_assertion" } else { "local_filesystem" },
                "source": if is_fixture { "fixture_assertion" } else if s.config_error.is_none() { "scm_query_service_config" } else { "unavailable" },
            },
            "indicators": indicators, "config_error": s.config_error,
            "source": s.evidence_source
        }));
    }
    if truncated { partial = true; warnings.push("entry_limit".into()); }
    if let Some(e) = collection.error_code { warnings.push(e.to_string()); }
    if partial { warnings.push("entry_metadata_incomplete".into()); }
    let status = match collection.enumeration_status {
        "complete" if !partial => "complete",
        "complete" | "partial" => "partial",
        other => other,
    };
    let reported = entries.len();
    json!({
        "schema_version": SCHEMA_VERSION, "module": "driver-inventory",
        "generated_at_unix_ms": now_ms(), "status": status,
        "entries": entries, "warnings": warnings,
        "coverage": {
            "enumerated": enumerated, "reported": reported,
            "pages": collection.pages, "max_entries": MAX_ENTRIES,
            "scope": "visible_scm_entries", "drivers_only": drivers_only,
            "complete_for_visible_services": status == "complete",
            "permission_filtered_possible": true
        }
    })
}

/// Validate and count a bounded Windows MULTI_SZ (double-NUL terminated).
/// Only the count is emitted; dependency names may reveal private software.
pub fn count_multisz_units(units: &[u16]) -> Result<usize, &'static str> {
    if units.len() > 1024 { return Err("multisz_limit"); }
    let mut offset = 0;
    let mut count = 0;
    loop {
        if offset >= units.len() { return Err("multisz_missing_terminator"); }
        let end = units[offset..].iter().position(|&unit| unit == 0)
            .map(|n| n + offset).ok_or("multisz_missing_terminator")?;
        if end == offset { return Ok(count); }
        String::from_utf16(&units[offset..end]).map_err(|_| "multisz_invalid_utf16")?;
        count += 1;
        if count > 64 { return Err("dependency_limit"); }
        offset = end + 1;
    }
}

/// Model the SCM pagination contract without OS calls, for deterministic tests.
pub fn next_page(code: u32, returned: usize, previous_resume: u32, resume: u32)
    -> Result<bool, &'static str>
{
    match code {
        0 => Ok(false),
        234 if returned > 0 && resume != 0 && resume != previous_resume => Ok(true),
        234 => Err("enumeration_no_progress"),
        5 => Err("permission_denied"),
        _ => Err("enumeration_error"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn types_and_states() {
        assert!(is_driver(1)); assert!(is_driver(2)); assert!(is_driver(8));
        assert!(!is_driver(16)); assert_eq!(kind(32), "win32_shared_process");
        assert_eq!(state(4), "running"); assert_eq!(state(1), "stopped");
        assert_eq!(start_type(Some(0)), "boot"); assert_eq!(start_type(Some(4)), "disabled");
    }
    #[test]
    fn normalization_is_conservative() {
        let win = r"C:\Windows";
        assert_eq!(normalize_image_path(r"\SystemRoot\System32\drivers\x.sys", win).0,
            Some(r"C:\Windows\System32\drivers\x.sys".to_string()));
        assert_eq!(normalize_image_path(r#""C:\Program Files\A\svc.exe" --secret KEY"#, win).0,
            Some(r"C:\Program Files\A\svc.exe".into()));
        assert_eq!(normalize_image_path(r"C:\Program Files\A\svc.exe --token secret", win).1,
            "ambiguous_unquoted_path");
        assert_eq!(normalize_image_path(r"%TEMP%\x.sys", win).1, "unresolved_image_path");
        assert_eq!(normalize_image_path(r"C:\Windows\..\evil.sys", win).1, "relative_component");
    }
    #[test]
    fn multisz_handles_unicode_and_malformed_termination() {
        let valid: Vec<u16> = "Net\0日本語\0\0".encode_utf16().collect();
        assert_eq!(count_multisz_units(&valid), Ok(2));
        assert_eq!(count_multisz_units(&[0, 0]), Ok(0));
        assert_eq!(count_multisz_units(&[65, 0]), Err("multisz_missing_terminator"));
        assert_eq!(count_multisz_units(&[0xd800, 0, 0]), Err("multisz_invalid_utf16"));
        assert_eq!(count_multisz_units(&vec![1; 1025]), Err("multisz_limit"));
    }
    #[test]
    fn pages_fail_closed() {
        assert_eq!(next_page(234, 10, 0, 12), Ok(true));
        assert_eq!(next_page(0, 1, 0, 0), Ok(false));
        assert_eq!(next_page(234, 0, 0, 1), Err("enumeration_no_progress"));
        assert_eq!(next_page(234, 3, 3, 3), Err("enumeration_no_progress"));
        assert_eq!(next_page(5, 0, 0, 0), Err("permission_denied"));
    }
}
