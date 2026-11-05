//! Windows-only, local, read-only PowerShell/CIM probes.
//! No user input is ever interpolated into any of these fixed scripts.
use crate::runner::{run_program, RunFailure};
use serde_json::{json, Map, Value};
use std::path::PathBuf;
use std::time::Duration;

const SECURE_BOOT: &str = r#"
$ErrorActionPreference='Stop'
try {
    $enabled=Confirm-SecureBootUEFI -ErrorAction Stop
    @{status='ok';enabled=[bool]$enabled} | ConvertTo-Json -Compress
} catch {
    $id=[string]$_.FullyQualifiedErrorId
    $category=[string]$_.CategoryInfo.Category
    $hr=$_.Exception.HResult
    $status='error'
    if ($hr -eq -2147024891 -or $category -eq 'PermissionDenied' -or $id -match 'Unauthorized|AccessDenied') {
        $status='permission_denied'
    } elseif ($id -match 'NotSupported' -or $category -eq 'NotImplemented' -or $_.Exception.Message -match 'Cmdlet not supported on this platform') {
        $status='unsupported'
    }
    @{status=$status} | ConvertTo-Json -Compress
}
"#;

const TPM: &str = r#"
$ErrorActionPreference='Stop'
try {
    # Query only explicit non-secret WMI properties. Get-Tpm is deliberately
    # avoided because its TpmObject may contain the OwnerAuth secret.
    $t=Get-CimInstance -Namespace 'root\CIMV2\Security\MicrosoftTpm' -ClassName 'Win32_Tpm' -Property SpecVersion -OperationTimeoutSec 5 -ErrorAction Stop
    if ($null -eq $t) {
        @{status='ok';present=$false;ready=$false;spec_2_0=$null} | ConvertTo-Json -Compress
    } else {
        $spec=$null
        if ($null -ne $t.SpecVersion -and [string]$t.SpecVersion -ne 'Not Supported') {
            $spec=[bool]([regex]::IsMatch([string]$t.SpecVersion,'(^|[,;\s])2\.0([,;\s]|$)'))
        }
        $ready=$null
        $status='ok'
        try {
            $r=Invoke-CimMethod -InputObject $t -MethodName IsReady -ErrorAction Stop
            if ($r.ReturnValue -eq 0) { $ready=[bool]$r.IsReady }
        } catch {
            if ($_.Exception.HResult -eq -2147024891 -or [string]$_.CategoryInfo.Category -eq 'PermissionDenied') {
                $status='permission_denied'
            }
        }
        @{status=$status;present=$true;ready=$ready;spec_2_0=$spec} | ConvertTo-Json -Compress
    }
} catch {
    $status='error'
    if ($_.Exception.HResult -eq -2147024891 -or [string]$_.CategoryInfo.Category -eq 'PermissionDenied') {
        $status='permission_denied'
    }
    @{status=$status} | ConvertTo-Json -Compress
}
"#;

const DEVICE_GUARD: &str = r#"
$ErrorActionPreference='Stop'
try {
    $d=Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName 'Win32_DeviceGuard' -OperationTimeoutSec 5 -ErrorAction Stop
    if ($null -eq $d) { throw 'NoDeviceGuardInstance' }
    $v=$null
    if ($null -ne $d.VirtualizationBasedSecurityStatus) { $v=[int]$d.VirtualizationBasedSecurityStatus }
    $running=$null
    if ($null -ne $d.SecurityServicesRunning) { $running=@($d.SecurityServicesRunning | ForEach-Object { [int]$_ }) }
    $configured=$null
    if ($null -ne $d.SecurityServicesConfigured) { $configured=@($d.SecurityServicesConfigured | ForEach-Object { [int]$_ }) }
    @{status='ok';vbs_status=$v;running_services=$running;configured_services=$configured} | ConvertTo-Json -Compress -Depth 4
} catch {
    $status='error'
    if ($_.Exception.HResult -eq -2147024891 -or [string]$_.CategoryInfo.Category -eq 'PermissionDenied') {
        $status='permission_denied'
    } elseif ([string]$_.FullyQualifiedErrorId -match 'InvalidNamespace|InvalidClass') {
        $status='unsupported'
    }
    @{status=$status} | ConvertTo-Json -Compress
}
"#;

const BITLOCKER: &str = r#"
$ErrorActionPreference='Stop'
try {
    # Only three harmless metadata properties are selected. Never request key protectors,
    # numerical passwords, recovery keys or drive identifiers.
    $volumes=@(Get-CimInstance -Namespace 'root\CIMV2\Security\MicrosoftVolumeEncryption' -ClassName 'Win32_EncryptableVolume' -Property VolumeType,ProtectionStatus,ConversionStatus -OperationTimeoutSec 5 -ErrorAction Stop | Where-Object { $_.VolumeType -eq 0 })
    $count=[math]::Min($volumes.Count,2)
    $protection=$null
    $conversion=$null
    if ($count -eq 1) {
        if ($null -ne $volumes[0].ProtectionStatus) { $protection=[int]$volumes[0].ProtectionStatus }
        if ($null -ne $volumes[0].ConversionStatus) { $conversion=[int]$volumes[0].ConversionStatus }
    }
    @{status='ok';os_volume_count=$count;protection=$protection;conversion=$conversion} | ConvertTo-Json -Compress
} catch {
    $status='error'
    if ($_.Exception.HResult -eq -2147024891 -or [string]$_.CategoryInfo.Category -eq 'PermissionDenied') {
        $status='permission_denied'
    } elseif ([string]$_.FullyQualifiedErrorId -match 'InvalidNamespace|InvalidClass') {
        $status='unsupported'
    }
    @{status=$status} | ConvertTo-Json -Compress
}
"#;

fn powershell_path() -> Option<PathBuf> {
    let root = PathBuf::from(std::env::var_os("SystemRoot")?);
    if !root.is_absolute() {
        return None;
    }
    Some(
        root.join("System32")
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe"),
    )
}

fn query(script: &'static str) -> Value {
    let Some(powershell) = powershell_path() else {
        return json!({"status":"error"});
    };
    let args = ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script];
    match run_program(&powershell, &args, Duration::from_secs(10)) {
        Ok(output) => {
            let parsed = serde_json::from_slice::<Value>(&output);
            match parsed {
                Ok(Value::Object(object)) if object.contains_key("status") => {
                    Value::Object(object)
                }
                _ => json!({"status":"error"}),
            }
        }
        Err(RunFailure::PermissionDenied) => json!({"status":"permission_denied"}),
        Err(RunFailure::Timeout) => json!({"status":"timeout"}),
        Err(_) => json!({"status":"error"}),
    }
}

/// No networking, policy writes, privilege escalation, or dynamic commands.
pub fn collect() -> Value {
    let mut root = Map::new();
    root.insert("secure_boot".to_owned(), query(SECURE_BOOT));
    root.insert("tpm".to_owned(), query(TPM));
    root.insert("device_guard".to_owned(), query(DEVICE_GUARD));
    root.insert("bitlocker".to_owned(), query(BITLOCKER));
    Value::Object(root)
}
