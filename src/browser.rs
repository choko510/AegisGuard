//! Read-only checks for browser-integrity traces (P6-01).
//!
//! The first check looks for the publicly reported traces of the 2026 NIKKE PC
//! launcher incident ("k2f"): a DLL named `platform_experience_helper.dll` in a
//! 64-hex-digit directory under Chrome's `PlatformExperienceHelper` folder, and
//! a per-user (HKCU) COM registration of CLSID
//! `{E77CC89B-7401-4C04-8CED-149DB35ADD04}` whose `InprocServer32` loads it.
//!
//! The `PlatformExperienceHelper` folder itself is normal Chrome data and is
//! never reported on its own. Nothing is deleted, modified, quarantined or
//! uploaded; the DLL is read through the same handle-based scanner as `scan`
//! and never loaded or executed. Other users' profiles and hives are not
//! inspected and are reported as not assessed.
use crate::model::Report;
use crate::{model, scan};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const CHECK_ID: &str = "AG-K2F-TRACE";
pub const CHECK_VERSION: u32 = 1;
pub const CLSID: &str = "{E77CC89B-7401-4C04-8CED-149DB35ADD04}";
const DLL_NAME: &str = "platform_experience_helper.dll";
const REFERENCE: &str = "https://nikke.gg/official-announcement-pc-launcher-security-incident/";
/// At most this many 64-hex directories are inspected; more is reported.
const MAX_CANDIDATE_DIRS: usize = 64;
const DLL_TIME_LIMIT: Duration = Duration::from_secs(10);

/// Registry locations of the CLSID's `InprocServer32` default value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegLocation {
    /// `HKCU\Software\Classes\CLSID\{..}\InprocServer32`
    HkcuClasses,
    /// `HKCU\Software\Classes\WOW6432Node\CLSID\{..}\InprocServer32`
    HkcuClassesWow64,
    /// `HKLM\Software\Classes\CLSID\{..}\InprocServer32` (machine-wide;
    /// reported as context only, never as an indicator by itself)
    HklmClasses,
}

impl RegLocation {
    pub fn subkey(self) -> String {
        match self {
            Self::HkcuClasses | Self::HklmClasses => {
                format!(r"Software\Classes\CLSID\{CLSID}\InprocServer32")
            }
            Self::HkcuClassesWow64 => {
                format!(r"Software\Classes\WOW6432Node\CLSID\{CLSID}\InprocServer32")
            }
        }
    }
}

/// Result of reading one registry value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", content = "detail", rename_all = "snake_case")]
pub enum RegLookup {
    Missing,
    Value(String),
    AccessDenied,
    Error(String),
    /// No registry on this platform, or the check was not run.
    Unavailable(String),
}

/// Registry access, abstracted so tests never touch the real registry.
pub trait ComRegistry {
    fn inproc_server(&self, location: RegLocation) -> RegLookup;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// DLL present and the HKCU registration loads that same DLL.
    CorrelatedSuspicion,
    /// One trace alone (DLL or HKCU registration): look closer.
    IndicatorPresent,
    /// The inspected locations showed neither trace. Not proof of absence.
    NotObserved,
    /// A required location could not be inspected and nothing was found.
    NotAssessed,
}

#[derive(Debug, Serialize)]
pub struct DllCandidate {
    pub path: String,
    /// `present`, `link_refused` (reparse point), or `unreadable`.
    pub state: &'static str,
    /// Status from the static scanner (`analyzed`, `invalid_pe`, ...).
    pub scan_status: Option<&'static str>,
    pub sha256: Option<String>,
    pub assessment: Option<model::Assessment>,
    pub signal_level: Option<model::SignalLevel>,
    pub signals: Vec<&'static str>,
    pub size_bytes: Option<u64>,
    /// Authenticode result (Windows); a valid signature is not proof of safety.
    pub signature: Option<crate::authenticode::Authenticode>,
    /// True when an HKCU registration's path names this file.
    pub registered_in_hkcu: bool,
}

#[derive(Debug, Serialize)]
pub struct RegistryEvidence {
    pub location: RegLocation,
    pub lookup: RegLookup,
    /// The value has the incident's path shape (…\PlatformExperienceHelper\<64 hex>\platform_experience_helper.dll).
    pub matches_trace_shape: bool,
}

#[derive(Debug, Serialize)]
pub struct K2fReport {
    pub check_id: &'static str,
    pub check_version: u32,
    pub verdict: Verdict,
    pub checked_at_unix_ms: u64,
    pub helper_dir: String,
    /// `absent`, `present`, `link_refused` or `unreadable: <reason>`.
    pub helper_dir_state: String,
    pub dll_candidates: Vec<DllCandidate>,
    pub candidate_dirs_omitted: usize,
    pub registry: Vec<RegistryEvidence>,
    /// Parts that were not inspected; any entry means the result is partial.
    pub not_assessed: Vec<String>,
    pub explanation: &'static str,
    pub reference: &'static str,
}

fn is_hex64(name: &str) -> bool {
    name.len() == 64 && name.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Normalize a registry path value for comparison: strip quotes and the
/// `\\?\` prefix, unify separators and case.
pub fn normalize_path(value: &str) -> String {
    let v = value.trim().trim_matches('"');
    let v = v.strip_prefix(r"\\?\").unwrap_or(v);
    v.replace('/', "\\").to_lowercase()
}

/// Whether a path has the incident's shape, wherever its root is.
pub fn matches_trace_shape(value: &str) -> bool {
    let norm = normalize_path(value);
    let parts: Vec<&str> = norm.rsplit('\\').take(3).collect();
    matches!(parts.as_slice(), [file, dir, parent]
        if *file == DLL_NAME && is_hex64(dir) && *parent == "platformexperiencehelper")
}

#[cfg(windows)]
fn is_link_dir(meta: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    meta.file_type().is_symlink() || meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_link_dir(meta: &std::fs::Metadata) -> bool {
    meta.file_type().is_symlink()
}

fn summarize_dll(path: &Path) -> DllCandidate {
    let report: Report = scan::scan_file(path, DLL_TIME_LIMIT, scan::Engines::default());
    // The file exists whenever it could be read (even if it is not a valid
    // PE) or was too large to read in full.
    let state = match report.not_assessed_reason {
        Some("symlink_not_followed") | Some("not_regular_file") => "link_refused",
        _ if report.sha256.is_some() => "present",
        None | Some("size_limit_exceeded") => "present",
        Some(_) => "unreadable",
    };
    DllCandidate {
        path: path.display().to_string(),
        state,
        scan_status: Some(report.status),
        sha256: report.sha256.clone(),
        assessment: Some(report.assessment),
        signal_level: Some(report.signal_level),
        signals: report.signals.iter().map(|s| s.code).collect(),
        size_bytes: report.file_identity.as_ref().map(|i| i.size_bytes),
        signature: report.pe.as_ref().and_then(|p| p.authenticode.clone()),
        registered_in_hkcu: false,
    }
}

/// Run the check. `local_app_data` is the user's `%LOCALAPPDATA%`.
pub fn check_k2f(local_app_data: Option<&Path>, registry: &dyn ComRegistry) -> K2fReport {
    let mut not_assessed = vec!["other_user_profiles_and_hives".to_string()];
    let helper_dir: PathBuf = local_app_data
        .map(|l| {
            l.join("Google")
                .join("Chrome")
                .join("User Data")
                .join("PlatformExperienceHelper")
        })
        .unwrap_or_default();
    let mut dll_candidates = Vec::new();
    let mut omitted = 0usize;
    let helper_dir_state = match local_app_data {
        None => {
            not_assessed.push("local_app_data_unknown".into());
            "unreadable: LOCALAPPDATA is not set".to_string()
        }
        Some(_) => match std::fs::symlink_metadata(&helper_dir) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => "absent".into(),
            Err(e) => {
                not_assessed.push("helper_dir".into());
                format!("unreadable: {e}")
            }
            Ok(meta) if is_link_dir(&meta) => {
                not_assessed.push("helper_dir (reparse point not followed)".into());
                "link_refused".into()
            }
            Ok(meta) if !meta.is_dir() => "absent".into(),
            Ok(_) => match std::fs::read_dir(&helper_dir) {
                Err(e) => {
                    not_assessed.push("helper_dir".into());
                    format!("unreadable: {e}")
                }
                Ok(entries) => {
                    let mut dirs: Vec<PathBuf> = Vec::new();
                    for entry in entries {
                        let Ok(entry) = entry else {
                            not_assessed.push("helper_dir_entry".into());
                            continue;
                        };
                        let name = entry.file_name().to_string_lossy().into_owned();
                        if !is_hex64(&name) {
                            continue;
                        }
                        match std::fs::symlink_metadata(entry.path()) {
                            Ok(m) if is_link_dir(&m) => {
                                not_assessed.push(format!("{name} (reparse point not followed)"));
                            }
                            Ok(m) if m.is_dir() => dirs.push(entry.path()),
                            Ok(_) => {}
                            Err(_) => not_assessed.push(format!("{name} (unreadable)")),
                        }
                    }
                    dirs.sort();
                    if dirs.len() > MAX_CANDIDATE_DIRS {
                        omitted = dirs.len() - MAX_CANDIDATE_DIRS;
                        dirs.truncate(MAX_CANDIDATE_DIRS);
                        not_assessed.push("candidate_dir_limit".into());
                    }
                    for dir in dirs {
                        let dll = dir.join(DLL_NAME);
                        match std::fs::symlink_metadata(&dll) {
                            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                            Err(_) => dll_candidates.push(DllCandidate {
                                path: dll.display().to_string(),
                                state: "unreadable",
                                scan_status: None,
                                sha256: None,
                                assessment: None,
                                signal_level: None,
                                signals: Vec::new(),
                                size_bytes: None,
                                signature: None,
                                registered_in_hkcu: false,
                            }),
                            Ok(_) => dll_candidates.push(summarize_dll(&dll)),
                        }
                    }
                    "present".into()
                }
            },
        },
    };

    let registry: Vec<RegistryEvidence> = [
        RegLocation::HkcuClasses,
        RegLocation::HkcuClassesWow64,
        RegLocation::HklmClasses,
    ]
    .into_iter()
    .map(|location| {
        let lookup = registry.inproc_server(location);
        let matches_trace_shape = matches!(&lookup, RegLookup::Value(v) if matches_trace_shape(v));
        RegistryEvidence {
            location,
            lookup,
            matches_trace_shape,
        }
    })
    .collect();

    let hkcu: Vec<&RegistryEvidence> = registry
        .iter()
        .filter(|r| r.location != RegLocation::HklmClasses)
        .collect();
    for r in &hkcu {
        match &r.lookup {
            RegLookup::AccessDenied | RegLookup::Error(_) | RegLookup::Unavailable(_) => {
                not_assessed.push(format!("registry {:?}", r.location));
            }
            RegLookup::Value(v) => {
                let norm = normalize_path(v);
                for dll in &mut dll_candidates {
                    if normalize_path(&dll.path) == norm {
                        dll.registered_in_hkcu = true;
                    }
                }
            }
            RegLookup::Missing => {}
        }
    }

    let dll_present = dll_candidates.iter().any(|d| d.state != "link_refused");
    let hkcu_registered = hkcu.iter().any(|r| matches!(r.lookup, RegLookup::Value(_)));
    let correlated = dll_candidates.iter().any(|d| d.registered_in_hkcu);
    let missing_required = not_assessed.iter().any(|n| {
        n.starts_with("helper_dir") || n.starts_with("registry") || n == "local_app_data_unknown"
    });
    let verdict = if correlated {
        Verdict::CorrelatedSuspicion
    } else if dll_present || hkcu_registered || !dll_candidates.is_empty() {
        Verdict::IndicatorPresent
    } else if missing_required {
        Verdict::NotAssessed
    } else {
        Verdict::NotObserved
    };
    K2fReport {
        check_id: CHECK_ID,
        check_version: CHECK_VERSION,
        verdict,
        checked_at_unix_ms: model::now_unix_ms(),
        helper_dir: helper_dir.display().to_string(),
        helper_dir_state,
        dll_candidates,
        candidate_dirs_omitted: omitted,
        registry,
        not_assessed,
        explanation: "Looks for the publicly reported k2f traces: a platform_experience_helper.dll in a 64-hex directory under Chrome's PlatformExperienceHelper folder and an HKCU COM registration of the CLSID that loads it. The folder itself is normal Chrome data. A per-user registration or DLL alone is a reason to look, both together are a stronger reason; neither is proof of infection, and not_observed is not proof of absence. Nothing was deleted or changed.",
        reference: REFERENCE,
    }
}

/// The real registry (read-only `RegGetValueW`).
#[cfg(windows)]
pub struct WindowsRegistry;

#[cfg(windows)]
impl ComRegistry for WindowsRegistry {
    fn inproc_server(&self, location: RegLocation) -> RegLookup {
        read_string(
            location == RegLocation::HklmClasses,
            &location.subkey(),
            None,
        )
    }
}

/// Read a REG_SZ / REG_EXPAND_SZ value (the default value when `name` is
/// `None`) with `RegGetValueW`. Read-only; values are capped at 64 KiB.
#[cfg(windows)]
pub fn read_string(machine: bool, subkey: &str, name: Option<&str>) -> RegLookup {
    use windows_sys::Win32::Foundation::{
        ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_PATH_NOT_FOUND,
        ERROR_SUCCESS,
    };
    use windows_sys::Win32::System::Registry::{
        RegGetValueW, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, RRF_RT_REG_EXPAND_SZ, RRF_RT_REG_SZ,
        RRF_SUBKEY_WOW6464KEY,
    };
    let (root, extra) = if machine {
        (HKEY_LOCAL_MACHINE, RRF_SUBKEY_WOW6464KEY)
    } else {
        (HKEY_CURRENT_USER, 0)
    };
    let wide = |s: &str| -> Vec<u16> { s.encode_utf16().chain(std::iter::once(0)).collect() };
    let subkey = wide(subkey);
    let name = name.map(wide);
    let name_ptr = name.as_ref().map_or(std::ptr::null(), |n| n.as_ptr());
    let mut buf: Vec<u16> = vec![0; 1024];
    loop {
        let mut bytes = u32::try_from(buf.len() * 2).unwrap_or(u32::MAX);
        // SAFETY: subkey/name are NUL-terminated UTF-16; buf has `bytes` bytes.
        let status = unsafe {
            RegGetValueW(
                root,
                subkey.as_ptr(),
                name_ptr,
                RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | extra,
                std::ptr::null_mut(),
                buf.as_mut_ptr().cast(),
                &mut bytes,
            )
        };
        match status {
            ERROR_SUCCESS => {
                let len = (bytes as usize / 2).min(buf.len());
                let text = String::from_utf16_lossy(&buf[..len]);
                return RegLookup::Value(text.trim_end_matches('\0').to_string());
            }
            ERROR_MORE_DATA if buf.len() < 32 * 1024 => {
                buf = vec![0; (bytes as usize / 2 + 1).min(32 * 1024)];
            }
            ERROR_MORE_DATA => return RegLookup::Error("value exceeds 64 KiB".into()),
            ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => return RegLookup::Missing,
            ERROR_ACCESS_DENIED => return RegLookup::AccessDenied,
            other => return RegLookup::Error(format!("RegGetValueW failed: {other}")),
        }
    }
}

/// Registry stand-in for platforms without a Windows registry.
pub struct NoRegistry;

impl ComRegistry for NoRegistry {
    fn inproc_server(&self, _location: RegLocation) -> RegLookup {
        RegLookup::Unavailable("no Windows registry on this platform".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::fs;

    struct FakeRegistry(HashMap<RegLocation, RegLookup>);

    impl ComRegistry for FakeRegistry {
        fn inproc_server(&self, location: RegLocation) -> RegLookup {
            self.0.get(&location).cloned().unwrap_or(RegLookup::Missing)
        }
    }

    const HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn root(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("aegis-k2f-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn helper(root: &Path) -> PathBuf {
        let dir = root.join(
            r"Google\Chrome\User Data\PlatformExperienceHelper"
                .replace('\\', std::path::MAIN_SEPARATOR_STR),
        );
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn plant_dll(root: &Path, hex: &str) -> PathBuf {
        let dir = helper(root).join(hex);
        fs::create_dir_all(&dir).unwrap();
        let dll = dir.join(DLL_NAME);
        // Not a real PE: harmless bytes, never loaded.
        fs::write(&dll, b"MZ synthetic fixture, not executable").unwrap();
        dll
    }

    fn reg(entries: &[(RegLocation, RegLookup)]) -> FakeRegistry {
        FakeRegistry(entries.iter().cloned().collect())
    }

    #[test]
    fn normal_helper_folder_alone_is_not_reported() {
        let r = root("normal");
        let h = helper(&r);
        fs::create_dir_all(h.join("SomeNormalState")).unwrap();
        fs::write(h.join("state.json"), b"{}").unwrap();
        let report = check_k2f(Some(&r), &reg(&[]));
        assert_eq!(report.verdict, Verdict::NotObserved);
        assert_eq!(report.helper_dir_state, "present");
        assert!(report.dll_candidates.is_empty());
    }

    #[test]
    fn missing_chrome_profile_is_not_observed() {
        let r = root("nochrome");
        let report = check_k2f(Some(&r), &reg(&[]));
        assert_eq!(report.verdict, Verdict::NotObserved);
        assert_eq!(report.helper_dir_state, "absent");
    }

    #[test]
    fn dll_alone_is_a_single_indicator() {
        let r = root("dllonly");
        plant_dll(&r, HEX);
        let report = check_k2f(Some(&r), &reg(&[]));
        assert_eq!(report.verdict, Verdict::IndicatorPresent);
        assert_eq!(report.dll_candidates.len(), 1);
        assert!(report.dll_candidates[0].sha256.is_some());
        assert_eq!(report.dll_candidates[0].state, "present");
        assert_eq!(report.dll_candidates[0].scan_status, Some("invalid_pe"));
        assert!(!report.dll_candidates[0].registered_in_hkcu);
    }

    #[test]
    fn clsid_alone_is_a_single_indicator() {
        let r = root("clsidonly");
        let value = format!(
            r"C:\Users\x\AppData\Local\Google\Chrome\User Data\PlatformExperienceHelper\{HEX}\{DLL_NAME}"
        );
        let report = check_k2f(
            Some(&r),
            &reg(&[(RegLocation::HkcuClasses, RegLookup::Value(value))]),
        );
        assert_eq!(report.verdict, Verdict::IndicatorPresent);
        assert!(report.registry[0].matches_trace_shape);
    }

    #[test]
    fn dll_and_matching_registration_are_correlated() {
        let r = root("both");
        let dll = plant_dll(&r, HEX);
        let value = format!("\"{}\"", dll.display().to_string().to_uppercase());
        let report = check_k2f(
            Some(&r),
            &reg(&[(RegLocation::HkcuClassesWow64, RegLookup::Value(value))]),
        );
        assert_eq!(report.verdict, Verdict::CorrelatedSuspicion);
        assert!(report.dll_candidates[0].registered_in_hkcu);
    }

    #[test]
    fn registration_naming_a_different_hex_dir_is_not_correlated() {
        let r = root("otherhex");
        plant_dll(&r, HEX);
        let other = "f".repeat(64);
        let value = format!(
            r"C:\Users\y\AppData\Local\Google\Chrome\User Data\PlatformExperienceHelper\{other}\{DLL_NAME}"
        );
        let report = check_k2f(
            Some(&r),
            &reg(&[(RegLocation::HkcuClasses, RegLookup::Value(value))]),
        );
        assert_eq!(report.verdict, Verdict::IndicatorPresent);
        assert!(!report.dll_candidates[0].registered_in_hkcu);
    }

    #[test]
    fn machine_wide_registration_is_context_not_an_indicator() {
        let r = root("hklm");
        let report = check_k2f(
            Some(&r),
            &reg(&[(
                RegLocation::HklmClasses,
                RegLookup::Value(r"C:\Program Files\Google\Chrome\Application\x.dll".into()),
            )]),
        );
        assert_eq!(report.verdict, Verdict::NotObserved);
    }

    #[test]
    fn wrong_names_and_short_hex_are_ignored() {
        let r = root("names");
        let h = helper(&r);
        fs::create_dir_all(h.join("abc")).unwrap();
        fs::write(h.join("abc").join(DLL_NAME), b"x").unwrap();
        let d = h.join(HEX);
        fs::create_dir_all(&d).unwrap();
        fs::write(d.join("other.dll"), b"x").unwrap();
        let report = check_k2f(Some(&r), &reg(&[]));
        assert_eq!(report.verdict, Verdict::NotObserved);
    }

    #[test]
    fn unreadable_registry_without_findings_is_not_assessed() {
        let r = root("denied");
        let report = check_k2f(
            Some(&r),
            &reg(&[(RegLocation::HkcuClasses, RegLookup::AccessDenied)]),
        );
        assert_eq!(report.verdict, Verdict::NotAssessed);
        let none = check_k2f(None, &reg(&[]));
        assert_eq!(none.verdict, Verdict::NotAssessed);
        let no_registry = check_k2f(Some(&r), &NoRegistry);
        assert_eq!(no_registry.verdict, Verdict::NotAssessed);
    }

    #[test]
    fn trace_shape_matching_is_normalized() {
        assert!(matches_trace_shape(&format!(
            r#""\\?\C:/U/PlatformExperienceHelper/{}/PLATFORM_EXPERIENCE_HELPER.DLL""#,
            HEX.to_uppercase()
        )));
        assert!(!matches_trace_shape(&format!(
            r"C:\U\Other\{HEX}\{DLL_NAME}"
        )));
        assert!(!matches_trace_shape(&format!(
            r"C:\U\PlatformExperienceHelper\{}\{DLL_NAME}",
            &HEX[1..]
        )));
    }

    #[cfg(unix)]
    #[test]
    fn linked_hex_directory_is_not_followed() {
        let r = root("link");
        let h = helper(&r);
        let target = r.join("elsewhere");
        fs::create_dir_all(&target).unwrap();
        fs::write(target.join(DLL_NAME), b"x").unwrap();
        std::os::unix::fs::symlink(&target, h.join(HEX)).unwrap();
        let report = check_k2f(Some(&r), &reg(&[]));
        assert!(report.dll_candidates.is_empty());
        assert!(report.not_assessed.iter().any(|n| n.contains("reparse")));
    }

    #[cfg(windows)]
    #[test]
    fn real_registry_reads_values_and_reports_missing_keys() {
        let product = read_string(
            true,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            Some("ProductName"),
        );
        assert!(matches!(product, RegLookup::Value(v) if v.contains("Windows")));
        let missing = read_string(false, r"Software\AegisGuard\DoesNotExist\{0}", None);
        assert_eq!(missing, RegLookup::Missing);
    }

    #[test]
    fn nothing_is_modified() {
        let r = root("readonly");
        let dll = plant_dll(&r, HEX);
        let before = fs::read(&dll).unwrap();
        let _ = check_k2f(Some(&r), &reg(&[]));
        assert_eq!(fs::read(&dll).unwrap(), before);
    }
}
