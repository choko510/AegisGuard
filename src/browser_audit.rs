//! Read-only browser audit across Chrome, Edge, Brave, Vivaldi, Opera and
//! Firefox (P6-05).
//!
//! - Per browser: installed?, user data present?, extensions force-installed
//!   by policy (HKCU/HKLM `ExtensionInstallForcelist`, Firefox
//!   `distribution\policies.json`). Policies are normal in managed fleets and
//!   are a known hijack vector elsewhere, so they are reported as `observed`
//!   with counts only (no extension contents are read).
//! - Per-user COM classes (HKCU `Software\Classes\CLSID\*\InprocServer32`):
//!   a server DLL inside any browser's user data is `review`; per-user
//!   servers elsewhere under the profile are common (OneDrive, Teams) and are
//!   listed as `observed`. Server DLLs are checked with Authenticode (bounded).
//!
//! Nothing is deleted or changed. Other users' hives are not inspected.
use crate::authenticode::{self, Authenticode};
use crate::browser::RegLookup;
use crate::events::process::path_key;
use serde::Serialize;
use std::path::{Path, PathBuf};

const MAX_CLSIDS: usize = 20_000;
const MAX_SIGNATURE_CHECKS: usize = 200;

/// Registry access needed by the audit; faked in tests.
pub trait RegistryView {
    /// Subkey names of `path` (HKLM when `machine`), at most `limit`.
    fn subkeys(&self, machine: bool, path: &str, limit: usize) -> RegResult<Vec<String>>;
    /// Default or named string value.
    fn string(&self, machine: bool, path: &str, name: Option<&str>) -> RegLookup;
    /// Number of values in a key.
    fn value_count(&self, machine: bool, path: &str) -> RegResult<usize>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", content = "detail", rename_all = "snake_case")]
pub enum RegResult<T> {
    Ok(T),
    Missing,
    Error(String),
}

pub struct BrowserSpec {
    pub name: &'static str,
    /// Install locations (relative to Program Files / LOCALAPPDATA).
    pub install: &'static [&'static str],
    /// User data root relative to LOCALAPPDATA (or APPDATA for Firefox).
    pub user_data: &'static str,
    pub roaming: bool,
    /// Policy key for forced extensions (Chromium), if any.
    pub policy: Option<&'static str>,
}

pub const BROWSERS: &[BrowserSpec] = &[
    BrowserSpec {
        name: "Google Chrome",
        install: &[r"Google\Chrome\Application\chrome.exe"],
        user_data: r"Google\Chrome\User Data",
        roaming: false,
        policy: Some(r"Software\Policies\Google\Chrome\ExtensionInstallForcelist"),
    },
    BrowserSpec {
        name: "Microsoft Edge",
        install: &[r"Microsoft\Edge\Application\msedge.exe"],
        user_data: r"Microsoft\Edge\User Data",
        roaming: false,
        policy: Some(r"Software\Policies\Microsoft\Edge\ExtensionInstallForcelist"),
    },
    BrowserSpec {
        name: "Brave",
        install: &[r"BraveSoftware\Brave-Browser\Application\brave.exe"],
        user_data: r"BraveSoftware\Brave-Browser\User Data",
        roaming: false,
        policy: Some(r"Software\Policies\BraveSoftware\Brave\ExtensionInstallForcelist"),
    },
    BrowserSpec {
        name: "Vivaldi",
        install: &[r"Vivaldi\Application\vivaldi.exe"],
        user_data: r"Vivaldi\User Data",
        roaming: false,
        policy: None,
    },
    BrowserSpec {
        name: "Opera",
        install: &[r"Programs\Opera\opera.exe"],
        user_data: r"Opera Software\Opera Stable",
        roaming: true,
        policy: None,
    },
    BrowserSpec {
        name: "Mozilla Firefox",
        install: &[r"Mozilla Firefox\firefox.exe"],
        user_data: r"Mozilla\Firefox\Profiles",
        roaming: true,
        policy: None,
    },
];

/// Where to look; overridable for tests and copied profiles.
#[derive(Debug, Clone, Default)]
pub struct Roots {
    pub program_files: Vec<PathBuf>,
    pub local_app_data: Option<PathBuf>,
    pub app_data: Option<PathBuf>,
}

impl Roots {
    pub fn from_env() -> Self {
        let var = |k: &str| std::env::var_os(k).map(PathBuf::from);
        Self {
            program_files: [var("ProgramFiles"), var("ProgramFiles(x86)")]
                .into_iter()
                .flatten()
                .collect(),
            local_app_data: var("LOCALAPPDATA"),
            app_data: var("APPDATA"),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct BrowserState {
    pub name: &'static str,
    pub installed: bool,
    pub user_data: Option<String>,
    pub user_data_present: bool,
    /// Forced extension entries per scope (`null` = could not be read).
    pub forced_extensions_hkcu: Option<usize>,
    pub forced_extensions_hklm: Option<usize>,
    /// Firefox: `distribution\policies.json` present in the install folder.
    pub enterprise_policies_file: Option<bool>,
    pub verdict: &'static str,
    pub notes: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ComServer {
    pub clsid: String,
    pub server: String,
    /// Browser whose user data holds the server DLL, if any.
    pub browser_user_data: Option<&'static str>,
    pub signature: Option<Authenticode>,
    /// `review` (in browser user data) or `observed` (elsewhere in the profile).
    pub verdict: &'static str,
}

#[derive(Debug, Serialize)]
pub struct BrowserAudit {
    pub browsers: Vec<BrowserState>,
    pub per_user_com_servers: Vec<ComServer>,
    pub clsids_scanned: usize,
    pub clsids_truncated: bool,
    pub not_assessed: Vec<String>,
    pub explanation: &'static str,
}

fn user_data_dir(spec: &BrowserSpec, roots: &Roots) -> Option<PathBuf> {
    let base = if spec.roaming {
        roots.app_data.as_ref()
    } else {
        roots.local_app_data.as_ref()
    }?;
    Some(base.join(spec.user_data))
}

fn installed(spec: &BrowserSpec, roots: &Roots) -> bool {
    spec.install.iter().any(|rel| {
        roots
            .program_files
            .iter()
            .chain(roots.local_app_data.iter())
            .any(|root| root.join(rel).is_file())
    })
}

fn count(r: RegResult<usize>, notes: &mut Vec<String>, what: &str) -> Option<usize> {
    match r {
        RegResult::Ok(n) => Some(n),
        RegResult::Missing => Some(0),
        RegResult::Error(e) => {
            notes.push(format!("{what}: {e}"));
            None
        }
    }
}

/// Server path from an InprocServer32 value: quotes stripped; environment
/// variables are expanded by the registry read for REG_EXPAND_SZ.
fn server_path(value: &str) -> String {
    value.trim().trim_matches('"').to_string()
}

pub fn audit(roots: &Roots, registry: &dyn RegistryView) -> BrowserAudit {
    let mut not_assessed = vec!["other_user_profiles_and_hives".to_string()];
    let mut browsers = Vec::new();
    for spec in BROWSERS {
        let mut notes = Vec::new();
        let dir = user_data_dir(spec, roots);
        let present = dir.as_ref().is_some_and(|d| d.is_dir());
        let (hkcu, hklm) = match spec.policy {
            Some(key) => (
                count(registry.value_count(false, key), &mut notes, "HKCU policy"),
                count(registry.value_count(true, key), &mut notes, "HKLM policy"),
            ),
            None => (None, None),
        };
        let firefox_policies = (spec.name == "Mozilla Firefox").then(|| {
            roots.program_files.iter().any(|p| {
                p.join(r"Mozilla Firefox\distribution\policies.json")
                    .is_file()
            })
        });
        let forced = hkcu.unwrap_or(0) + hklm.unwrap_or(0) > 0 || firefox_policies == Some(true);
        if forced {
            notes.push(
                "拡張機能がポリシーで強制インストールされています（組織の管理なら正常、心当たりがなければ確認）".into(),
            );
        }
        let verdict = if forced {
            "observed"
        } else if !notes.is_empty() {
            "not_assessed"
        } else {
            "not_observed"
        };
        browsers.push(BrowserState {
            name: spec.name,
            installed: installed(spec, roots),
            user_data: dir.map(|d| d.display().to_string()),
            user_data_present: present,
            forced_extensions_hkcu: hkcu,
            forced_extensions_hklm: hklm,
            enterprise_policies_file: firefox_policies,
            verdict,
            notes,
        });
    }

    // Per-user COM servers.
    let base = r"Software\Classes\CLSID";
    let mut servers = Vec::new();
    let (clsids, truncated) = match registry.subkeys(false, base, MAX_CLSIDS + 1) {
        RegResult::Ok(mut v) => {
            let truncated = v.len() > MAX_CLSIDS;
            v.truncate(MAX_CLSIDS);
            (v, truncated)
        }
        RegResult::Missing => (Vec::new(), false),
        RegResult::Error(e) => {
            not_assessed.push(format!("HKCU CLSID enumeration: {e}"));
            (Vec::new(), false)
        }
    };
    if truncated {
        not_assessed.push("clsid_limit".into());
    }
    let browser_dirs: Vec<(&'static str, String)> = BROWSERS
        .iter()
        .filter_map(|s| {
            user_data_dir(s, roots).map(|d| (s.name, path_key(&d.display().to_string())))
        })
        .collect();
    let profile = roots
        .local_app_data
        .as_ref()
        .and_then(|l| l.parent())
        .map(|p| path_key(&p.display().to_string()));
    let mut checks = 0;
    for clsid in &clsids {
        let value = registry.string(false, &format!(r"{base}\{clsid}\InprocServer32"), None);
        let RegLookup::Value(v) = value else {
            continue;
        };
        let server = server_path(&v);
        let key = path_key(&server);
        let browser = browser_dirs
            .iter()
            .find(|(_, d)| key.starts_with(&format!("{d}\\")))
            .map(|(n, _)| *n);
        let in_profile = profile
            .as_ref()
            .is_some_and(|p| key.starts_with(p.as_str()))
            || key.contains(r"\appdata\")
            || key.contains(r"\temp\");
        if browser.is_none() && !in_profile {
            continue;
        }
        let signature = (checks < MAX_SIGNATURE_CHECKS).then(|| {
            checks += 1;
            match std::fs::File::open(&server) {
                Ok(f) => authenticode::verify(&f, Path::new(&server)),
                Err(e) => Authenticode::not_assessed(Some(format!("cannot open: {e}"))),
            }
        });
        servers.push(ComServer {
            clsid: clsid.clone(),
            server,
            browser_user_data: browser,
            signature,
            verdict: if browser.is_some() {
                "review"
            } else {
                "observed"
            },
        });
    }
    BrowserAudit {
        browsers,
        per_user_com_servers: servers,
        clsids_scanned: clsids.len(),
        clsids_truncated: truncated,
        not_assessed,
        explanation: "Read-only. Per-user COM servers inside a browser's user data are a DLL-hijack pattern (review); per-user servers elsewhere in the profile are common and only listed. Forced extensions are normal in managed environments. Nothing found is not proof of absence; nothing was changed.",
    }
}

/// The real registry (read-only).
#[cfg(windows)]
pub struct WindowsRegistry;

#[cfg(windows)]
impl RegistryView for WindowsRegistry {
    fn subkeys(&self, machine: bool, path: &str, limit: usize) -> RegResult<Vec<String>> {
        win::with_key(machine, path, |key| {
            let mut out = Vec::new();
            let mut index = 0u32;
            loop {
                let mut name = [0u16; 256];
                let mut len = name.len() as u32;
                // SAFETY: key is open; buffers sized by `len`.
                let status = unsafe {
                    windows_sys::Win32::System::Registry::RegEnumKeyExW(
                        key,
                        index,
                        name.as_mut_ptr(),
                        &mut len,
                        std::ptr::null(),
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                    )
                };
                match status {
                    0 => out.push(String::from_utf16_lossy(&name[..len as usize])),
                    259 => break, // ERROR_NO_MORE_ITEMS
                    other => return RegResult::Error(format!("RegEnumKeyExW failed: {other}")),
                }
                index += 1;
                if out.len() >= limit {
                    break;
                }
            }
            RegResult::Ok(out)
        })
    }

    fn string(&self, machine: bool, path: &str, name: Option<&str>) -> RegLookup {
        crate::browser::read_string(machine, path, name)
    }

    fn value_count(&self, machine: bool, path: &str) -> RegResult<usize> {
        win::with_key(machine, path, |key| {
            let mut values = 0u32;
            // SAFETY: key is open; only the value count is requested.
            let status = unsafe {
                windows_sys::Win32::System::Registry::RegQueryInfoKeyW(
                    key,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    &mut values,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            if status == 0 {
                RegResult::Ok(values as usize)
            } else {
                RegResult::Error(format!("RegQueryInfoKeyW failed: {status}"))
            }
        })
    }
}

#[cfg(windows)]
mod win {
    use super::RegResult;
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ,
        KEY_WOW64_64KEY,
    };

    pub fn with_key<T>(
        machine: bool,
        path: &str,
        f: impl FnOnce(HKEY) -> RegResult<T>,
    ) -> RegResult<T> {
        let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
        let root = if machine {
            HKEY_LOCAL_MACHINE
        } else {
            HKEY_CURRENT_USER
        };
        let mut key: HKEY = std::ptr::null_mut();
        // SAFETY: NUL-terminated path; read-only access; closed below.
        let status =
            unsafe { RegOpenKeyExW(root, wide.as_ptr(), 0, KEY_READ | KEY_WOW64_64KEY, &mut key) };
        match status {
            0 => {
                let r = f(key);
                // SAFETY: opened above.
                unsafe { RegCloseKey(key) };
                r
            }
            2 | 3 => RegResult::Missing,
            other => RegResult::Error(format!("RegOpenKeyExW failed: {other}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[derive(Default)]
    struct Fake {
        subkeys: Vec<String>,
        values: HashMap<String, String>,
        policies: HashMap<(bool, String), usize>,
        fail_enum: bool,
    }

    impl RegistryView for Fake {
        fn subkeys(&self, _: bool, _: &str, limit: usize) -> RegResult<Vec<String>> {
            if self.fail_enum {
                return RegResult::Error("denied".into());
            }
            RegResult::Ok(self.subkeys.iter().take(limit).cloned().collect())
        }
        fn string(&self, _: bool, path: &str, _: Option<&str>) -> RegLookup {
            self.values
                .get(path)
                .cloned()
                .map_or(RegLookup::Missing, RegLookup::Value)
        }
        fn value_count(&self, machine: bool, path: &str) -> RegResult<usize> {
            self.policies
                .get(&(machine, path.to_string()))
                .copied()
                .map_or(RegResult::Missing, RegResult::Ok)
        }
    }

    fn roots(name: &str) -> (PathBuf, Roots) {
        let d = std::env::temp_dir().join(format!("aegis-baudit-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let local = d.join("Users").join("u").join("AppData").join("Local");
        let roaming = d.join("Users").join("u").join("AppData").join("Roaming");
        std::fs::create_dir_all(
            local.join(r"Microsoft\Edge\User Data".replace('\\', std::path::MAIN_SEPARATOR_STR)),
        )
        .unwrap();
        std::fs::create_dir_all(&roaming).unwrap();
        (
            d.clone(),
            Roots {
                program_files: vec![d.join("PF")],
                local_app_data: Some(local),
                app_data: Some(roaming),
            },
        )
    }

    fn clsid_value(clsid: &str) -> String {
        format!(r"Software\Classes\CLSID\{clsid}\InprocServer32")
    }

    #[test]
    fn com_server_in_any_browser_user_data_is_review_and_profile_ones_are_observed() {
        let (_, r) = roots("com");
        let local = r.local_app_data.clone().unwrap();
        let edge_dll = local
            .join(r"Microsoft\Edge\User Data\x\h.dll")
            .display()
            .to_string();
        let onedrive = local
            .join(r"Microsoft\OneDrive\FileSyncShell64.dll")
            .display()
            .to_string();
        let mut f = Fake {
            subkeys: vec!["{A}".into(), "{B}".into(), "{C}".into()],
            ..Fake::default()
        };
        f.values
            .insert(clsid_value("{A}"), format!("\"{edge_dll}\""));
        f.values.insert(clsid_value("{B}"), onedrive);
        f.values.insert(
            clsid_value("{C}"),
            r"C:\Windows\System32\shell32.dll".into(),
        );
        let a = audit(&r, &f);
        assert_eq!(a.clsids_scanned, 3);
        assert_eq!(a.per_user_com_servers.len(), 2);
        let edge = a
            .per_user_com_servers
            .iter()
            .find(|s| s.clsid == "{A}")
            .unwrap();
        assert_eq!(edge.verdict, "review");
        assert_eq!(edge.browser_user_data, Some("Microsoft Edge"));
        assert!(edge.signature.is_some());
        let od = a
            .per_user_com_servers
            .iter()
            .find(|s| s.clsid == "{B}")
            .unwrap();
        assert_eq!(od.verdict, "observed");
    }

    #[test]
    fn forced_extension_policies_are_observed_and_firefox_policies_file_is_seen() {
        let (d, r) = roots("policy");
        let mut f = Fake::default();
        f.policies.insert(
            (
                true,
                r"Software\Policies\Google\Chrome\ExtensionInstallForcelist".into(),
            ),
            2,
        );
        std::fs::create_dir_all(
            d.join(r"PF\Mozilla Firefox\distribution".replace('\\', std::path::MAIN_SEPARATOR_STR)),
        )
        .unwrap();
        std::fs::write(
            d.join(
                r"PF\Mozilla Firefox\distribution\policies.json"
                    .replace('\\', std::path::MAIN_SEPARATOR_STR),
            ),
            b"{}",
        )
        .unwrap();
        let a = audit(&r, &f);
        let chrome = a
            .browsers
            .iter()
            .find(|b| b.name == "Google Chrome")
            .unwrap();
        assert_eq!(chrome.forced_extensions_hklm, Some(2));
        assert_eq!(chrome.verdict, "observed");
        let edge = a
            .browsers
            .iter()
            .find(|b| b.name == "Microsoft Edge")
            .unwrap();
        assert!(edge.user_data_present);
        assert_eq!(edge.verdict, "not_observed");
        let ff = a
            .browsers
            .iter()
            .find(|b| b.name == "Mozilla Firefox")
            .unwrap();
        if cfg!(windows) {
            assert_eq!(ff.enterprise_policies_file, Some(true));
            assert_eq!(ff.verdict, "observed");
        }
    }

    #[test]
    fn unreadable_registry_is_not_assessed() {
        let (_, r) = roots("denied");
        let f = Fake {
            fail_enum: true,
            ..Fake::default()
        };
        let a = audit(&r, &f);
        assert!(a.not_assessed.iter().any(|n| n.contains("CLSID")));
        assert!(a.per_user_com_servers.is_empty());
    }

    #[cfg(windows)]
    #[test]
    fn real_registry_enumeration_and_counts_work() {
        let reg = WindowsRegistry;
        assert!(
            matches!(reg.subkeys(true, r"SOFTWARE\Microsoft", 5), RegResult::Ok(v) if !v.is_empty())
        );
        assert_eq!(
            reg.value_count(false, r"Software\AegisGuard\Nope"),
            RegResult::Missing
        );
    }
}
