//! Read-only Microsoft Defender / ASR state audit (P4-02). The only calls are
//! Microsoft's `Get-MpComputerStatus` and `Get-MpPreference` (and a test for
//! the Defender policy registry key), run by a fixed script through the
//! system PowerShell. Nothing is set, added or removed. Values that cannot be
//! read are reported as `unknown`, never as protected or safe. Exclusion
//! paths are counted, not printed.
use crate::Result;
use serde::Serialize;
use serde_json::Value;

/// Fixed, read-only query. No sample or user input is interpolated.
#[cfg(windows)]
const QUERY: &str = r#"$ErrorActionPreference = 'Stop'
$r = [ordered]@{}
try { $r.status = Get-MpComputerStatus | Select-Object AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled, BehaviorMonitorEnabled, IoavProtectionEnabled, OnAccessProtectionEnabled, IsTamperProtected, AntivirusSignatureAge, AMRunningMode, AMProductVersion } catch { $r.status_error = $_.Exception.Message }
try { $r.preference = Get-MpPreference | Select-Object AttackSurfaceReductionRules_Ids, AttackSurfaceReductionRules_Actions, EnableControlledFolderAccess, EnableNetworkProtection, PUAProtection, DisableRealtimeMonitoring, MAPSReporting, SubmitSamplesConsent, ExclusionPath, ExclusionProcess, ExclusionExtension } catch { $r.preference_error = $_.Exception.Message }
$r.policy_key_present = Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
$r | ConvertTo-Json -Depth 4 -Compress"#;

/// ASR rule GUIDs from Microsoft's ASR rules reference. Unknown GUIDs are
/// reported as `unknown_rule`, never dropped.
const ASR_RULES: &[(&str, &str)] = &[
    ("56a863a9-875e-4185-98a7-b882c64b5ce5", "Block abuse of exploited vulnerable signed drivers"),
    ("7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c", "Block Adobe Reader from creating child processes"),
    ("d4f940ab-401b-4efc-aadc-ad5f3c50688a", "Block all Office applications from creating child processes"),
    ("9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", "Block credential stealing from the Windows local security authority subsystem (lsass.exe)"),
    ("be9ba2d9-53ea-4cdc-84e5-9b1eeee46550", "Block executable content from email client and webmail"),
    ("01443614-cd74-433a-b99e-2ecdc07bfc25", "Block executable files from running unless they meet a prevalence, age, or trusted list criterion"),
    ("5beb7efe-fd9a-4556-801d-275e5ffc04cc", "Block execution of potentially obfuscated scripts"),
    ("d3e037e1-3eb8-44c8-a917-57927947596d", "Block JavaScript or VBScript from launching downloaded executable content"),
    ("3b576869-a4ec-4529-8536-b80a7769e899", "Block Office applications from creating executable content"),
    ("75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84", "Block Office applications from injecting code into other processes"),
    ("26190899-1602-49e8-8b27-eb1d0a1ce869", "Block Office communication application from creating child processes"),
    ("e6db77e5-3df2-4cf1-b95a-636979351e5b", "Block persistence through WMI event subscription"),
    ("d1e49aac-8f56-4280-b9ba-993a6d77406c", "Block process creations originating from PSExec and WMI commands"),
    ("33ddedf1-c6e0-47cb-833e-de6133960387", "Block rebooting machine in Safe Mode"),
    ("b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4", "Block untrusted and unsigned processes that run from USB"),
    ("c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb", "Block use of copied or impersonated system tools"),
    ("a8f5898e-1dc8-49a9-9878-85004b8a61e6", "Block Webshell creation for Servers"),
    ("92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b", "Block Win32 API calls from Office macros"),
    ("c1db55ab-c21a-4637-bb3f-a12568109d35", "Use advanced protection against ransomware"),
];

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Control {
    pub name: &'static str,
    /// enabled, disabled, audit, warn, block_disk_modification, ..., unknown
    pub state: String,
    pub raw: Value,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct AsrRule {
    pub guid: String,
    pub name: &'static str,
    pub state: &'static str,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Exclusions {
    /// None when the values are hidden (non-administrator) or unreadable.
    pub path_count: Option<usize>,
    pub process_count: Option<usize>,
    pub extension_count: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct DefenderAudit {
    pub available: bool,
    pub errors: Vec<String>,
    pub running_mode: String,
    pub controls: Vec<Control>,
    pub asr_rules: Vec<AsrRule>,
    pub exclusions: Exclusions,
    /// `policy_key_present` means Group Policy/MDM may own settings; local
    /// values can then differ from what is enforced.
    pub management: &'static str,
    pub signature_age_days: Option<u64>,
    pub note: &'static str,
}

fn flag(value: &Value) -> String {
    match value.as_bool() {
        Some(true) => "enabled",
        Some(false) => "disabled",
        None => "unknown",
    }
    .into()
}

fn mode(value: &Value, names: &[&'static str]) -> String {
    value
        .as_u64()
        .and_then(|n| names.get(n as usize).copied())
        .unwrap_or("unknown")
        .into()
}

fn asr_state(action: Option<u64>) -> &'static str {
    match action {
        Some(0) => "disabled",
        Some(1) => "block",
        Some(2) => "audit",
        Some(5) => "not_configured",
        Some(6) => "warn",
        _ => "unknown",
    }
}

/// PowerShell serializes a single-element array as a scalar.
fn as_list(value: &Value) -> Vec<Value> {
    match value {
        Value::Null => Vec::new(),
        Value::Array(items) => items.clone(),
        other => vec![other.clone()],
    }
}

fn exclusion_count(value: &Value) -> Option<usize> {
    let items = as_list(value);
    // Non-administrators get a placeholder instead of the configured values.
    if items
        .iter()
        .any(|v| v.as_str().is_some_and(|s| s.starts_with("N/A")))
    {
        return None;
    }
    if !value.is_null() && !value.is_array() && !value.is_string() {
        return None;
    }
    Some(items.len())
}

/// Interpret the JSON produced by the read-only query.
pub fn interpret(raw: &Value) -> DefenderAudit {
    let status = &raw["status"];
    let pref = &raw["preference"];
    let mut errors = Vec::new();
    for key in ["status_error", "preference_error"] {
        if let Some(e) = raw[key].as_str() {
            errors.push(format!("{key}: {e}"));
        }
    }
    let available = status.is_object() || pref.is_object();
    let mut controls = vec![
        Control {
            name: "service",
            state: flag(&status["AMServiceEnabled"]),
            raw: status["AMServiceEnabled"].clone(),
        },
        Control {
            name: "antivirus",
            state: flag(&status["AntivirusEnabled"]),
            raw: status["AntivirusEnabled"].clone(),
        },
        Control {
            name: "real_time_protection",
            state: flag(&status["RealTimeProtectionEnabled"]),
            raw: status["RealTimeProtectionEnabled"].clone(),
        },
        Control {
            name: "behavior_monitoring",
            state: flag(&status["BehaviorMonitorEnabled"]),
            raw: status["BehaviorMonitorEnabled"].clone(),
        },
        Control {
            name: "download_scanning",
            state: flag(&status["IoavProtectionEnabled"]),
            raw: status["IoavProtectionEnabled"].clone(),
        },
        Control {
            name: "tamper_protection",
            state: flag(&status["IsTamperProtected"]),
            raw: status["IsTamperProtected"].clone(),
        },
        Control {
            name: "controlled_folder_access",
            state: mode(
                &pref["EnableControlledFolderAccess"],
                &[
                    "disabled",
                    "enabled",
                    "audit",
                    "block_disk_modification",
                    "audit_disk_modification",
                ],
            ),
            raw: pref["EnableControlledFolderAccess"].clone(),
        },
        Control {
            name: "network_protection",
            state: mode(
                &pref["EnableNetworkProtection"],
                &["disabled", "enabled", "audit"],
            ),
            raw: pref["EnableNetworkProtection"].clone(),
        },
        Control {
            name: "pua_protection",
            state: mode(&pref["PUAProtection"], &["disabled", "enabled", "audit"]),
            raw: pref["PUAProtection"].clone(),
        },
        Control {
            name: "cloud_protection",
            state: mode(&pref["MAPSReporting"], &["disabled", "basic", "advanced"]),
            raw: pref["MAPSReporting"].clone(),
        },
    ];
    // DisableRealtimeMonitoring is inverted: true means the preference turns it off.
    controls.push(Control {
        name: "realtime_monitoring_preference",
        state: match pref["DisableRealtimeMonitoring"].as_bool() {
            Some(true) => "disabled".into(),
            Some(false) => "enabled".into(),
            None => "unknown".into(),
        },
        raw: pref["DisableRealtimeMonitoring"].clone(),
    });

    let ids = as_list(&pref["AttackSurfaceReductionRules_Ids"]);
    let actions = as_list(&pref["AttackSurfaceReductionRules_Actions"]);
    let mut asr_rules: Vec<AsrRule> = ids
        .iter()
        .enumerate()
        .map(|(i, id)| {
            let guid = id.as_str().unwrap_or("").to_ascii_lowercase();
            let name = ASR_RULES
                .iter()
                .find(|(g, _)| *g == guid)
                .map(|(_, n)| *n)
                .unwrap_or("unknown_rule");
            let action = actions.get(i).and_then(Value::as_u64);
            AsrRule {
                guid,
                name,
                state: if ids.len() == actions.len() {
                    asr_state(action)
                } else {
                    "unknown"
                },
            }
        })
        .collect();
    asr_rules.sort_by(|a, b| a.guid.cmp(&b.guid));

    DefenderAudit {
        available,
        errors,
        running_mode: status["AMRunningMode"].as_str().unwrap_or("unknown").into(),
        controls,
        asr_rules,
        exclusions: Exclusions {
            path_count: exclusion_count(&pref["ExclusionPath"]),
            process_count: exclusion_count(&pref["ExclusionProcess"]),
            extension_count: exclusion_count(&pref["ExclusionExtension"]),
        },
        management: match raw["policy_key_present"].as_bool() {
            Some(true) => "policy_key_present",
            Some(false) => "no_policy_key",
            None => "unknown",
        },
        signature_age_days: status["AntivirusSignatureAge"].as_u64(),
        note: "Read-only snapshot. Preferences can differ from enforced state under Group Policy/MDM or Tamper Protection; unknown means not readable, not protected.",
    }
}

/// Run the fixed read-only query with the system PowerShell (60 s limit).
#[cfg(windows)]
pub fn query() -> Result<Value> {
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    let root = std::env::var_os("SystemRoot").ok_or("SystemRoot is not set")?;
    let exe = std::path::Path::new(&root).join(r"System32\WindowsPowerShell\v1.0\powershell.exe");
    let mut child = Command::new(exe)
        .args(["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    {
        use std::io::Write;
        let mut stdin = child.stdin.take().ok_or("no stdin")?;
        stdin.write_all(QUERY.as_bytes())?;
    }
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if child.try_wait()?.is_some() {
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            return Err("Defender query timed out".into());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let out = child.wait_with_output()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let json = text
        .lines()
        .rev()
        .find(|l| l.trim_start().starts_with('{'))
        .ok_or_else(|| {
            format!(
                "Defender query returned no JSON: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )
        })?;
    Ok(serde_json::from_str(json)?)
}

#[cfg(not(windows))]
pub fn query() -> Result<Value> {
    Err("the Defender audit reads Windows settings and is only available on Windows".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn state<'a>(audit: &'a DefenderAudit, name: &str) -> &'a str {
        &audit
            .controls
            .iter()
            .find(|c| c.name == name)
            .unwrap()
            .state
    }

    #[test]
    fn healthy_snapshot_is_interpreted_with_asr_names() {
        let raw = json!({
            "status": {"AMServiceEnabled": true, "AntivirusEnabled": true, "RealTimeProtectionEnabled": true,
                       "BehaviorMonitorEnabled": true, "IoavProtectionEnabled": true, "IsTamperProtected": true,
                       "AntivirusSignatureAge": 0, "AMRunningMode": "Normal"},
            "preference": {"AttackSurfaceReductionRules_Ids": ["9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2", "00000000-0000-0000-0000-000000000000"],
                           "AttackSurfaceReductionRules_Actions": [1, 2],
                           "EnableControlledFolderAccess": 2, "EnableNetworkProtection": 1, "PUAProtection": 1,
                           "DisableRealtimeMonitoring": false, "MAPSReporting": 2,
                           "ExclusionPath": ["C:\\a", "C:\\b"], "ExclusionProcess": null, "ExclusionExtension": "tmp"},
            "policy_key_present": true
        });
        let audit = interpret(&raw);
        assert!(audit.available && audit.errors.is_empty());
        assert_eq!(state(&audit, "real_time_protection"), "enabled");
        assert_eq!(state(&audit, "controlled_folder_access"), "audit");
        assert_eq!(audit.management, "policy_key_present");
        assert_eq!(audit.asr_rules[0].name, "unknown_rule");
        assert_eq!(audit.asr_rules[0].state, "audit");
        assert!(audit.asr_rules[1].name.contains("lsass"));
        assert_eq!(audit.asr_rules[1].state, "block");
        assert_eq!(
            audit.exclusions,
            Exclusions {
                path_count: Some(2),
                process_count: Some(0),
                extension_count: Some(1)
            }
        );
        // Exclusion paths themselves are never part of the output.
        assert!(!serde_json::to_string(&audit).unwrap().contains("C:\\\\a"));
    }

    #[test]
    fn unreadable_values_are_unknown_not_protected() {
        let raw = json!({
            "status_error": "Access denied",
            "preference_error": "Operation failed with the following error: 0x800106ba",
            "policy_key_present": false
        });
        let audit = interpret(&raw);
        assert!(!audit.available);
        assert_eq!(audit.errors.len(), 2);
        assert!(audit.controls.iter().all(|c| c.state == "unknown"));
        assert_eq!(audit.running_mode, "unknown");
        assert_eq!(audit.signature_age_days, None);
    }

    #[test]
    fn hidden_exclusions_and_mismatched_asr_arrays_are_unknown() {
        let raw = json!({
            "status": {"AMRunningMode": "Passive", "RealTimeProtectionEnabled": false},
            "preference": {"ExclusionPath": ["N/A: Must be and administrator to view exclusions"],
                           "AttackSurfaceReductionRules_Ids": "d4f940ab-401b-4efc-aadc-ad5f3c50688a",
                           "AttackSurfaceReductionRules_Actions": [1, 1],
                           "DisableRealtimeMonitoring": true}
        });
        let audit = interpret(&raw);
        assert_eq!(audit.exclusions.path_count, None);
        assert_eq!(audit.asr_rules.len(), 1);
        assert_eq!(audit.asr_rules[0].state, "unknown");
        assert_eq!(audit.running_mode, "Passive");
        assert_eq!(state(&audit, "real_time_protection"), "disabled");
        assert_eq!(state(&audit, "realtime_monitoring_preference"), "disabled");
        assert_eq!(audit.management, "unknown");
    }

    /// Runs the real read-only query twice on Windows; the observed preferences
    /// must not change (the audit itself never writes).
    #[cfg(windows)]
    #[test]
    fn real_query_is_repeatable_and_does_not_change_preferences() {
        let Ok(first) = query() else { return };
        let second = query().unwrap();
        assert_eq!(first["preference"], second["preference"]);
        let audit = interpret(&first);
        assert_eq!(
            audit.available,
            first["status"].is_object() || first["preference"].is_object()
        );
    }
}
