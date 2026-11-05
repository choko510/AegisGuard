//! Authenticode verification of PE files (P5-04), read-only.
//!
//! Windows verifies the file through the handle AegisGuard already opened
//! (so the verified bytes are the scanned bytes) with `WinVerifyTrust`: no
//! UI, and revocation checked from the local cache only (no network). Files
//! without an embedded signature are looked up in the system catalogs, which
//! sign most Windows components. A valid signature is evidence of origin,
//! never of safety; it does not lower any score.
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureStatus {
    /// Valid signature with a trusted chain and no known revocation.
    Signed,
    /// A signature exists but does not verify (tampered, revoked, bad digest).
    Invalid,
    /// No embedded signature and no catalog entry.
    Unsigned,
    /// The chain does not reach a trusted root, or is expired/not trusted.
    ChainUnknown,
    /// The signature verified but revocation could not be checked offline.
    RevocationUnknown,
    /// Verification could not run (platform, API error, unsupported file).
    NotAssessed,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Authenticode {
    pub status: SignatureStatus,
    /// `embedded` or `catalog` when a signature was found.
    pub source: Option<&'static str>,
    pub signer: Option<String>,
    /// HRESULT returned by WinVerifyTrust, for the record.
    pub code: Option<String>,
    pub note: &'static str,
}

const NOTE: &str =
    "A valid signature identifies the publisher; it is not proof that the file is safe.";

impl Authenticode {
    pub fn not_assessed(code: Option<String>) -> Self {
        Self {
            status: SignatureStatus::NotAssessed,
            source: None,
            signer: None,
            code,
            note: NOTE,
        }
    }
}

/// Map a WinVerifyTrust result to a status.
pub fn classify(hresult: i32) -> SignatureStatus {
    // Compare as u32 bit patterns.
    match hresult as u32 {
        0 => SignatureStatus::Signed,
        // TRUST_E_NOSIGNATURE
        0x800B_0100 => SignatureStatus::Unsigned,
        // TRUST_E_BAD_DIGEST, CERT_E_REVOKED, TRUST_E_CERT_SIGNATURE,
        // CRYPT_E_SECURITY_SETTINGS? (no), TRUST_E_EXPLICIT_DISTRUST
        0x8009_6010 | 0x800B_010C | 0x8009_6004 | 0x800B_0111 => SignatureStatus::Invalid,
        // CERT_E_UNTRUSTEDROOT, CERT_E_CHAINING, CERT_E_EXPIRED,
        // TRUST_E_SUBJECT_NOT_TRUSTED, CERT_E_UNTRUSTEDTESTROOT, CERT_E_WRONG_USAGE
        0x800B_0109 | 0x800B_010A | 0x800B_0101 | 0x800B_0004 | 0x800B_010D | 0x800B_0110 => {
            SignatureStatus::ChainUnknown
        }
        // CRYPT_E_REVOCATION_OFFLINE, CERT_E_REVOCATION_FAILURE, CRYPT_E_NO_REVOCATION_CHECK
        0x8009_2013 | 0x800B_010E | 0x8009_2012 => SignatureStatus::RevocationUnknown,
        _ => SignatureStatus::NotAssessed,
    }
}

#[cfg(windows)]
pub fn verify(file: &std::fs::File, path: &std::path::Path) -> Authenticode {
    imp::verify(file, path)
}

#[cfg(not(windows))]
pub fn verify(_file: &std::fs::File, _path: &std::path::Path) -> Authenticode {
    Authenticode::not_assessed(Some("authenticode verification needs Windows".into()))
}

#[cfg(windows)]
mod imp {
    use super::{classify, Authenticode, SignatureStatus, NOTE};
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Security::Cryptography::Catalog::{
        CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle2,
        CryptCATAdminEnumCatalogFromHash, CryptCATAdminReleaseCatalogContext,
        CryptCATAdminReleaseContext, CryptCATCatalogInfoFromContext, CATALOG_INFO,
    };
    use windows_sys::Win32::Security::Cryptography::CertGetNameStringW;
    use windows_sys::Win32::Security::WinTrust::{
        WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData, WinVerifyTrust,
        WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_CATALOG_INFO, WINTRUST_DATA,
        WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_CATALOG, WTD_CHOICE_FILE,
        WTD_REVOKE_WHOLECHAIN, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
    };

    /// CERT_NAME_SIMPLE_DISPLAY_TYPE
    const SIMPLE_DISPLAY: u32 = 4;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Run WinVerifyTrust with state, read the signer name, close the state.
    unsafe fn run(data: &mut WINTRUST_DATA) -> (i32, Option<String>) {
        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        data.dwStateAction = WTD_STATEACTION_VERIFY;
        let status = WinVerifyTrust(
            std::ptr::null_mut(),
            &mut action,
            (data as *mut WINTRUST_DATA).cast(),
        );
        let mut signer = None;
        if !data.hWVTStateData.is_null() {
            let prov = WTHelperProvDataFromStateData(data.hWVTStateData);
            if !prov.is_null() {
                let sgnr = WTHelperGetProvSignerFromChain(prov, 0, 0, 0);
                if !sgnr.is_null() && (*sgnr).csCertChain > 0 && !(*sgnr).pasCertChain.is_null() {
                    let cert = (*(*sgnr).pasCertChain).pCert;
                    if !cert.is_null() {
                        let mut buf = [0u16; 256];
                        let n = CertGetNameStringW(
                            cert,
                            SIMPLE_DISPLAY,
                            0,
                            std::ptr::null(),
                            buf.as_mut_ptr(),
                            buf.len() as u32,
                        );
                        if n > 1 {
                            signer = Some(String::from_utf16_lossy(&buf[..(n - 1) as usize]));
                        }
                    }
                }
            }
            data.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(
                std::ptr::null_mut(),
                &mut action,
                (data as *mut WINTRUST_DATA).cast(),
            );
        }
        (status, signer)
    }

    fn base_data() -> WINTRUST_DATA {
        WINTRUST_DATA {
            cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
            dwUIChoice: WTD_UI_NONE,
            fdwRevocationChecks: WTD_REVOKE_WHOLECHAIN,
            // Never fetch CRLs/OCSP over the network during a scan.
            dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL,
            ..Default::default()
        }
    }

    fn embedded(handle: HANDLE, path: &[u16]) -> (i32, Option<String>) {
        let mut file = WINTRUST_FILE_INFO {
            cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
            pcwszFilePath: path.as_ptr(),
            hFile: handle,
            pgKnownSubject: std::ptr::null_mut(),
        };
        let mut data = base_data();
        data.dwUnionChoice = WTD_CHOICE_FILE;
        data.Anonymous.pFile = &mut file;
        // SAFETY: all pointers outlive the call; state is closed in `run`.
        unsafe { run(&mut data) }
    }

    /// Look the file hash up in the system catalogs and verify that catalog.
    /// `None` when no catalog lists the file; `Err` when the lookup failed.
    fn catalog(handle: HANDLE, path: &[u16]) -> Result<Option<(i32, Option<String>)>, String> {
        // SAFETY: handles are released on every path; buffers are sized by the API.
        unsafe {
            let mut admin: isize = 0;
            let sha256 = wide("SHA256");
            if CryptCATAdminAcquireContext2(
                &mut admin,
                std::ptr::null(),
                sha256.as_ptr(),
                std::ptr::null(),
                0,
            ) == 0
            {
                return Err("CryptCATAdminAcquireContext2 failed".into());
            }
            let mut len: u32 = 0;
            CryptCATAdminCalcHashFromFileHandle2(admin, handle, &mut len, std::ptr::null_mut(), 0);
            if len == 0 || len > 128 {
                CryptCATAdminReleaseContext(admin, 0);
                return Err("cannot hash file for catalog lookup".into());
            }
            let mut hash = vec![0u8; len as usize];
            if CryptCATAdminCalcHashFromFileHandle2(admin, handle, &mut len, hash.as_mut_ptr(), 0)
                == 0
            {
                CryptCATAdminReleaseContext(admin, 0);
                return Err("cannot hash file for catalog lookup".into());
            }
            let ctx = CryptCATAdminEnumCatalogFromHash(
                admin,
                hash.as_ptr(),
                len,
                0,
                std::ptr::null_mut(),
            );
            if ctx == 0 {
                CryptCATAdminReleaseContext(admin, 0);
                return Ok(None);
            }
            let mut info = CATALOG_INFO {
                cbStruct: std::mem::size_of::<CATALOG_INFO>() as u32,
                ..Default::default()
            };
            let result = if CryptCATCatalogInfoFromContext(ctx, &mut info, 0) != 0 {
                let tag: String = hash.iter().map(|b| format!("{b:02X}")).collect();
                let tag = wide(&tag);
                let mut cat = WINTRUST_CATALOG_INFO {
                    cbStruct: std::mem::size_of::<WINTRUST_CATALOG_INFO>() as u32,
                    pcwszCatalogFilePath: info.wszCatalogFile.as_ptr(),
                    pcwszMemberTag: tag.as_ptr(),
                    pcwszMemberFilePath: path.as_ptr(),
                    hMemberFile: handle,
                    pbCalculatedFileHash: hash.as_mut_ptr(),
                    cbCalculatedFileHash: len,
                    hCatAdmin: admin,
                    ..Default::default()
                };
                let mut data = base_data();
                data.dwUnionChoice = WTD_CHOICE_CATALOG;
                data.Anonymous.pCatalog = &mut cat;
                Ok(Some(run(&mut data)))
            } else {
                Err("CryptCATCatalogInfoFromContext failed".into())
            };
            CryptCATAdminReleaseCatalogContext(admin, ctx, 0);
            CryptCATAdminReleaseContext(admin, 0);
            result
        }
    }

    pub fn verify(file: &std::fs::File, path: &std::path::Path) -> Authenticode {
        let handle = file.as_raw_handle() as HANDLE;
        let wpath = wide(&path.display().to_string());
        let (code, signer) = embedded(handle, &wpath);
        let status = classify(code);
        let hex = |c: i32| Some(format!("0x{:08X}", c as u32));
        if status != SignatureStatus::Unsigned {
            return Authenticode {
                status,
                source: matches!(
                    status,
                    SignatureStatus::Signed
                        | SignatureStatus::RevocationUnknown
                        | SignatureStatus::ChainUnknown
                        | SignatureStatus::Invalid
                )
                .then_some("embedded"),
                signer,
                code: hex(code),
                note: NOTE,
            };
        }
        match catalog(handle, &wpath) {
            Ok(None) => Authenticode {
                status: SignatureStatus::Unsigned,
                source: None,
                signer: None,
                code: hex(code),
                note: NOTE,
            },
            Ok(Some((cat_code, cat_signer))) => Authenticode {
                status: classify(cat_code),
                source: Some("catalog"),
                signer: cat_signer,
                code: hex(cat_code),
                note: NOTE,
            },
            Err(e) => Authenticode::not_assessed(Some(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hresults_map_to_distinct_states() {
        assert_eq!(classify(0), SignatureStatus::Signed);
        assert_eq!(classify(0x800B_0100u32 as i32), SignatureStatus::Unsigned);
        assert_eq!(classify(0x8009_6010u32 as i32), SignatureStatus::Invalid);
        assert_eq!(classify(0x800B_010Cu32 as i32), SignatureStatus::Invalid);
        assert_eq!(
            classify(0x800B_0109u32 as i32),
            SignatureStatus::ChainUnknown
        );
        assert_eq!(
            classify(0x8009_2013u32 as i32),
            SignatureStatus::RevocationUnknown
        );
        assert_eq!(classify(0x1234), SignatureStatus::NotAssessed);
    }

    #[cfg(windows)]
    fn sys(name: &str) -> std::path::PathBuf {
        let root = std::env::var_os("WINDIR").unwrap_or_else(|| "C:\\Windows".into());
        std::path::PathBuf::from(root).join(name)
    }

    #[cfg(windows)]
    #[test]
    fn real_windows_files_verify_and_unsigned_or_tampered_files_do_not() {
        // A Microsoft-signed system binary (embedded or catalog).
        let path = sys("explorer.exe");
        let f = std::fs::File::open(&path).unwrap();
        let a = verify(&f, &path);
        assert!(
            matches!(
                a.status,
                SignatureStatus::Signed | SignatureStatus::RevocationUnknown
            ),
            "{a:?}"
        );
        assert!(
            a.signer.as_deref().unwrap_or("").contains("Microsoft"),
            "{a:?}"
        );

        let dir = std::env::temp_dir().join(format!("aegis-authenticode-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // An unsigned, structurally valid PE stub.
        let mut stub = vec![0u8; 1024];
        stub[0..2].copy_from_slice(b"MZ");
        stub[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        stub[0x80..0x84].copy_from_slice(b"PE\0\0");
        let unsigned = dir.join("stub.dll");
        std::fs::write(&unsigned, &stub).unwrap();
        let f = std::fs::File::open(&unsigned).unwrap();
        let a = verify(&f, &unsigned);
        assert!(
            matches!(
                a.status,
                SignatureStatus::Unsigned | SignatureStatus::NotAssessed
            ),
            "{a:?}"
        );
        assert_ne!(a.status, SignatureStatus::Signed);

        // A copy of a signed binary with one byte changed must not verify.
        // (Never executed; only read by WinVerifyTrust.)
        let mut bytes = std::fs::read(sys("System32\\notepad.exe")).unwrap();
        let mid = bytes.len() / 3;
        bytes[mid] ^= 0xFF;
        let tampered = dir.join("tampered.exe");
        std::fs::write(&tampered, &bytes).unwrap();
        let f = std::fs::File::open(&tampered).unwrap();
        let a = verify(&f, &tampered);
        assert_ne!(a.status, SignatureStatus::Signed, "{a:?}");
        drop(f);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
