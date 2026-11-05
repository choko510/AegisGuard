pub mod runner;
#[cfg(windows)]
pub mod windows;

use serde_json::{json, Map, Value};

pub const SCHEMA_VERSION: u64 = 1;
pub const EXPECTED_CONTROLS: usize = 5;
pub const MAX_FIXTURE_BYTES: u64 = 65_536;

#[derive(Debug)]
pub struct PostureControl {
    pub id: &'static str,
    pub availability: &'static str,
    pub state: &'static str,
    pub source: &'static str,
    pub checked_at: u64,
    pub warnings: Vec<&'static str>,
}

impl PostureControl {
    fn new(id: &'static str, source: &'static str, checked_at: u64) -> Self {
        Self {
            id,
            availability: "unknown",
            state: "unknown",
            source,
            checked_at,
            warnings: Vec::new(),
        }
    }

    fn value(self) -> Value {
        json!({
            "id": self.id,
            "availability": self.availability,
            "state": self.state,
            "source": self.source,
            "checked_at": self.checked_at,
            "warnings": self.warnings,
        })
    }
}

fn probe<'a>(
    root: &'a Map<String, Value>,
    key: &str,
    fields: &[&str],
) -> Result<Option<&'a Map<String, Value>>, &'static str> {
    let Some(value) = root.get(key) else {
        return Ok(None);
    };
    let object = value.as_object().ok_or("invalid_probe_object")?;
    if object.len() > fields.len() || object.keys().any(|key| !fields.contains(&key.as_str())) {
        return Err("unknown_probe_field");
    }
    let status = object
        .get("status")
        .and_then(Value::as_str)
        .ok_or("missing_probe_status")?;
    if !matches!(
        status,
        "ok" | "unsupported" | "permission_denied" | "timeout" | "error"
    ) {
        return Err("invalid_probe_status");
    }
    Ok(Some(object))
}

fn early(control: &mut PostureControl, probe: Option<&Map<String, Value>>) -> bool {
    let Some(probe) = probe else {
        control.warnings.push("not_collected");
        return true;
    };
    match probe["status"].as_str().unwrap_or("") {
        "ok" => false,
        "permission_denied" => {
            control.availability = "permission_denied";
            control.state = "permission_denied";
            control.warnings.push("requires_access");
            true
        }
        "unsupported" => {
            if matches!(control.id, "secure_boot" | "tpm_2_0") {
                control.availability = "not_applicable";
                control.state = "not_applicable";
                control.warnings.push("platform_unsupported");
            } else {
                // A missing WMI provider cannot prove that the hardware is unsupported.
                control.warnings.push("provider_unsupported_or_unavailable");
            }
            true
        }
        "timeout" => {
            control.warnings.push("probe_timeout");
            true
        }
        _ => {
            control.warnings.push("probe_failed");
            true
        }
    }
}

fn opt_bool(probe: &Map<String, Value>, field: &str) -> Result<Option<bool>, &'static str> {
    match probe.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(value)) => Ok(Some(*value)),
        _ => Err("invalid_field_type"),
    }
}

fn opt_int(probe: &Map<String, Value>, field: &str) -> Result<Option<u64>, &'static str> {
    match probe.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(value)) => value.as_u64().map(Some).ok_or("invalid_field_type"),
        _ => Err("invalid_field_type"),
    }
}

fn opt_codes(probe: &Map<String, Value>, field: &str) -> Result<Option<Vec<u64>>, &'static str> {
    match probe.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(values)) if values.len() <= 16 => values
            .iter()
            .map(|value| {
                value
                    .as_u64()
                    .filter(|value| *value <= 255)
                    .ok_or("invalid_field_type")
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Some),
        _ => Err("invalid_field_type"),
    }
}

fn secure_boot(probe: Option<&Map<String, Value>>, checked_at: u64) -> Result<PostureControl, &'static str> {
    let mut result = PostureControl::new("secure_boot", "Confirm-SecureBootUEFI", checked_at);
    if early(&mut result, probe) {
        return Ok(result);
    }
    match opt_bool(probe.ok_or("missing_probe")?, "enabled")? {
        Some(enabled) => {
            result.availability = "supported";
            result.state = if enabled { "enabled" } else { "disabled" };
        }
        None => result.warnings.push("missing_value"),
    }
    Ok(result)
}

fn tpm(probe: Option<&Map<String, Value>>, checked_at: u64) -> Result<PostureControl, &'static str> {
    let mut result = PostureControl::new("tpm_2_0", "Win32_Tpm.SpecVersion;IsReady", checked_at);
    if early(&mut result, probe) {
        return Ok(result);
    }
    let probe = probe.ok_or("missing_probe")?;
    let present = opt_bool(probe, "present")?;
    let ready = opt_bool(probe, "ready")?;
    let spec = opt_bool(probe, "spec_2_0")?;

    if present == Some(false) && (ready == Some(true) || spec == Some(true)) {
        result.warnings.push("conflicting_evidence");
    } else if present == Some(false) || (present == Some(true) && spec == Some(false)) {
        result.availability = "not_applicable";
        result.state = "not_applicable";
        result.warnings.push("tpm_2_0_not_available");
    } else if present == Some(true) && spec == Some(true) {
        result.availability = "supported";
        match ready {
            Some(true) => result.state = "enabled",
            Some(false) => result.state = "disabled",
            None => result.warnings.push("readiness_unknown"),
        }
    } else {
        result.warnings.push("tpm_version_or_presence_unknown");
    }
    Ok(result)
}

fn device_guard(
    probe: Option<&Map<String, Value>>,
    checked_at: u64,
) -> Result<(PostureControl, PostureControl), &'static str> {
    let mut vbs = PostureControl::new("vbs", "Win32_DeviceGuard.VirtualizationBasedSecurityStatus", checked_at);
    let mut hvci = PostureControl::new("hvci", "Win32_DeviceGuard.SecurityServicesRunning", checked_at);
    if early(&mut vbs, probe) {
        let _ = early(&mut hvci, probe);
        return Ok((vbs, hvci));
    }
    let probe = probe.ok_or("missing_probe")?;
    let state = opt_int(probe, "vbs_status")?;
    let running = opt_codes(probe, "running_services")?;
    let configured = opt_codes(probe, "configured_services")?;

    let contradictory = running.as_ref().is_some_and(|codes| {
        codes.contains(&0) && codes.iter().any(|code| *code != 0)
            || codes.iter().enumerate().any(|(i, code)| codes[..i].contains(code))
            || codes.contains(&2) && state != Some(2)
    });

    if contradictory {
        vbs.warnings.push("conflicting_evidence");
        hvci.warnings.push("conflicting_evidence");
        return Ok((vbs, hvci));
    }

    match state {
        Some(0) => {
            vbs.availability = "supported";
            vbs.state = "disabled";
        }
        Some(1) => {
            vbs.availability = "supported";
            vbs.state = "disabled";
            vbs.warnings.push("configured_but_not_running");
        }
        Some(2) => {
            vbs.availability = "supported";
            vbs.state = "enabled";
        }
        _ => vbs.warnings.push("vbs_status_unknown"),
    }

    if let Some(running) = &running {
        if state.is_some_and(|s| s <= 2) {
            hvci.availability = "supported";
            hvci.state = if running.contains(&2) { "enabled" } else { "disabled" };
            if hvci.state == "disabled" && configured.as_ref().is_some_and(|c| c.contains(&2)) {
                hvci.warnings.push("configured_but_not_running");
            }
        } else {
            hvci.warnings.push("vbs_status_unknown");
        }
    } else {
        hvci.warnings.push("services_running_unknown");
    }
    Ok((vbs, hvci))
}

fn bitlocker(probe: Option<&Map<String, Value>>, checked_at: u64) -> Result<PostureControl, &'static str> {
    let mut result = PostureControl::new(
        "bitlocker_os_volume",
        "Win32_EncryptableVolume.GetProtectionStatus;GetConversionStatus",
        checked_at,
    );
    if early(&mut result, probe) {
        return Ok(result);
    }
    let probe = probe.ok_or("missing_probe")?;
    let count = opt_int(probe, "os_volume_count")?;
    let protection = opt_int(probe, "protection")?;
    let conversion = opt_int(probe, "conversion")?;

    if count != Some(1) {
        result.warnings.push("os_volume_missing_or_ambiguous");
        return Ok(result);
    }
    match (protection, conversion) {
        (Some(1), Some(1)) => {
            result.availability = "supported";
            result.state = "enabled";
        }
        (Some(0), Some(0)) => {
            result.availability = "supported";
            result.state = "disabled";
        }
        (Some(0), Some(1)) => {
            result.availability = "supported";
            result.state = "disabled";
            result.warnings.push("encrypted_but_protection_off");
        }
        (Some(0), Some(2..=5)) => {
            result.availability = "supported";
            result.state = "disabled";
            result.warnings.push("conversion_in_progress_or_paused");
        }
        (Some(2), _) => result.warnings.push("protection_status_unknown"),
        (Some(1), Some(0 | 2..=5)) => result.warnings.push("conflicting_evidence"),
        _ => result.warnings.push("missing_or_invalid_status"),
    }
    Ok(result)
}

/// Accepts only the documented, allowlisted, secret-free probe schema.
/// Neither raw values nor errors from the host are copied into the report.
pub fn evaluate(input: &Value, checked_at: u64) -> Result<Value, &'static str> {
    let root = input.as_object().ok_or("fixture_not_object")?;
    if root.len() > 5
        || root.keys().any(|key| {
            !matches!(
                key.as_str(),
                "edition" | "secure_boot" | "tpm" | "device_guard" | "bitlocker"
            )
        })
    {
        return Err("unknown_fixture_field");
    }
    if let Some(edition) = root.get("edition") {
        let value = edition.as_str().ok_or("invalid_edition")?;
        if !matches!(
            value,
            "home" | "pro" | "enterprise" | "education" | "unknown"
        ) {
            return Err("invalid_edition");
        }
    }
    let secure = probe(root, "secure_boot", &["status", "enabled"])?;
    let tpm_raw = probe(root, "tpm", &["status", "present", "ready", "spec_2_0"])?;
    let device_raw = probe(
        root,
        "device_guard",
        &["status", "vbs_status", "running_services", "configured_services"],
    )?;
    let bitlocker_raw = probe(
        root,
        "bitlocker",
        &["status", "os_volume_count", "protection", "conversion"],
    )?;

    let (vbs, hvci) = device_guard(device_raw, checked_at)?;
    let controls = [
        secure_boot(secure, checked_at)?,
        tpm(tpm_raw, checked_at)?,
        vbs,
        hvci,
        bitlocker(bitlocker_raw, checked_at)?,
    ];
    let entries: Vec<Value> = controls
        .into_iter()
        .map(PostureControl::value)
        .collect();
    let assessed = entries
        .iter()
        .filter(|value| {
            matches!(
                value["state"].as_str(),
                Some("enabled" | "disabled" | "not_applicable")
            )
        })
        .count();
    let denied = entries
        .iter()
        .filter(|value| value["state"] == "permission_denied")
        .count();
    let status = if assessed == EXPECTED_CONTROLS {
        "complete"
    } else if assessed > 0 {
        "partial"
    } else if denied > 0 {
        "permission_denied"
    } else {
        "unavailable"
    };
    Ok(json!({
        "schema_version": SCHEMA_VERSION,
        "module": "windows-posture",
        "generated_at_unix_ms": checked_at,
        "status": status,
        "entries": entries,
        "warnings": [],
        "coverage": {
            "expected": EXPECTED_CONTROLS,
            "assessed": assessed,
            "unknown": EXPECTED_CONTROLS - assessed - denied,
            "permission_denied": denied
        }
    }))
}

pub fn error_report(checked_at: u64, error_code: &'static str) -> Value {
    json!({
        "schema_version": SCHEMA_VERSION,
        "module": "windows-posture",
        "generated_at_unix_ms": checked_at,
        "status": "error",
        "entries": [],
        "warnings": [error_code],
        "coverage": {
            "expected": EXPECTED_CONTROLS,
            "assessed": 0,
            "unknown": EXPECTED_CONTROLS,
            "permission_denied": 0
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_fixtures_is_unavailable_not_safe() {
        let report = evaluate(&json!({}), 123).unwrap();
        assert_eq!(report["status"], "unavailable");
        assert_eq!(report["coverage"]["assessed"], 0);
        assert_eq!(report["entries"].as_array().unwrap().len(), 5);
    }

    #[test]
    fn boot_requires_explicit_boolean() {
        let report = evaluate(&json!({"secure_boot":{"status":"ok"}}), 9).unwrap();
        assert_eq!(report["entries"][0]["state"], "unknown");
    }

    #[test]
    fn rejects_secret_bearing_unknown_field_without_echoing() {
        let fixture = json!({"bitlocker":{"status":"ok","recovery_key":"SENSITIVE"}});
        assert_eq!(evaluate(&fixture, 1).unwrap_err(), "unknown_probe_field");
        let output = error_report(1, "invalid_fixture").to_string();
        assert!(!output.contains("SENSITIVE"));
    }
}
