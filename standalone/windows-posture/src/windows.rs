//! Windows-only, local, read-only PowerShell/CIM probes.
//! No user input is ever interpolated into any of these fixed scripts.
use crate::runner::{run_program, RunFailure};
use serde_json::{json, Map, Value};
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
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
    # Read only VolumeType to identify the OS volume. No recovery key,
    # protector IDs, passwords, drive letters, or raw CIM objects are output.
    $volumes=@(Get-CimInstance -Namespace 'root\CIMV2\Security\MicrosoftVolumeEncryption' -ClassName 'Win32_EncryptableVolume' -Property VolumeType -OperationTimeoutSec 5 -ErrorAction Stop | Where-Object { $_.VolumeType -eq 0 })
    $count=[math]::Min($volumes.Count,2)
    $protection=$null
    $conversion=$null
    $status='ok'
    if ($count -eq 1) {
        # These are the documented read-only methods for current state.
        # Do not fall back to potentially stale WMI properties on failure.
        $volume=$volumes[0]
        $p=Invoke-CimMethod -InputObject $volume -MethodName 'GetProtectionStatus' -ErrorAction Stop
        $c=Invoke-CimMethod -InputObject $volume -MethodName 'GetConversionStatus' -Arguments @{PrecisionFactor=[uint32]0} -ErrorAction Stop
        if ($null -eq $p.ReturnValue -or $null -eq $c.ReturnValue) {
            $status='error'
        } elseif ([uint64]$p.ReturnValue -eq 0 -and [uint64]$c.ReturnValue -eq 0) {
            if ($null -ne $p.ProtectionStatus -and $null -ne $c.ConversionStatus) {
                $protection=[uint32]$p.ProtectionStatus
                $conversion=[uint32]$c.ConversionStatus
            } else {
                $status='error'
            }
        } elseif ([uint64]$p.ReturnValue -eq 2147942405 -or [uint64]$c.ReturnValue -eq 2147942405) {
            $status='permission_denied'
        } else {
            # A locked volume, unsupported call or provider error is unknown.
            $status='error'
        }
    }
    @{status=$status;os_volume_count=$count;protection=$protection;conversion=$conversion} | ConvertTo-Json -Compress
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

// GetSystemDirectoryW is a kernel32 API. The environment, PATH, working
// directory, and user-provided fixture never determine the executable path.
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetSystemDirectoryW(buffer: *mut u16, buffer_length: u32) -> u32;
}

fn powershell_path_from_directory(buffer: &[u16], length: usize) -> Option<PathBuf> {
    if length == 0 || length >= buffer.len() || buffer[..length].contains(&0) {
        return None;
    }
    let directory = PathBuf::from(OsString::from_wide(&buffer[..length]));
    if !directory.is_absolute() {
        return None;
    }
    Some(
        directory
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe"),
    )
}

fn powershell_path() -> Option<PathBuf> {
    // A 32-bit process on 64-bit Windows may be redirected to SysWOW64.
    // Only the native 64-bit build is supported for live audit.
    if cfg!(target_pointer_width = "32") {
        return None;
    }
    const MAX_SYSTEM_DIRECTORY_CHARS: usize = 1024;
    let mut buffer = [0_u16; MAX_SYSTEM_DIRECTORY_CHARS];
    // SAFETY: The buffer has capacity MAX_SYSTEM_DIRECTORY_CHARS UTF-16 code
    // units and remains alive during the call. Zero/truncation is rejected.
    let written = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) };
    powershell_path_from_directory(&buffer, usize::try_from(written).ok()?)
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


#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::ffi::OsStrExt;

    #[test]
    fn rejects_bogus_windows_api_results() {
        let units: Vec<u16> = std::ffi::OsStr::new(r"C:\Windows\System32")
            .encode_wide()
            .collect();
        assert!(powershell_path_from_directory(&units, 0).is_none());
        assert!(powershell_path_from_directory(&units, units.len()).is_none());
        let relative: Vec<u16> = std::ffi::OsStr::new(r"Windows\System32")
            .encode_wide()
            .collect();
        assert!(powershell_path_from_directory(&relative, relative.len() - 1).is_none());
    }

    #[test]
    fn rejects_embedded_nul_in_system_directory() {
        let mut units: Vec<u16> = std::ffi::OsStr::new(r"C:\Windows\System32")
            .encode_wide()
            .collect();
        units[3] = 0;
        units.push(0);
        assert!(powershell_path_from_directory(&units, units.len() - 1).is_none());
    }

    #[test]
    fn appends_only_fixed_power_shell_location() {
        let mut units: Vec<u16> = std::ffi::OsStr::new(r"C:\Windows\System32")
            .encode_wide()
            .collect();
        let length = units.len();
        units.push(0);
        let expected = std::path::Path::new(r"C:\Windows\System32")
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe");
        assert_eq!(powershell_path_from_directory(&units, length), Some(expected));
    }
}
