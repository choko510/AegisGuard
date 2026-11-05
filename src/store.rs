//! Two-generation durable storage for small state files (C2 cache, later rule
//! manifests). A new generation is written to `<file>.tmp`, flushed, re-read and
//! validated, then `<file>` becomes `<file>.prev` and `.tmp` becomes `<file>`.
//! A crash at any step leaves either the old or the new validated generation
//! loadable; readers never see a mix and never treat a broken file as empty.
use crate::Result;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Generation {
    Current,
    /// A fully written and validated update whose final rename was interrupted.
    Pending,
    /// The previous validated generation, used when the current one is missing or broken.
    Previous,
}

impl Generation {
    pub fn as_str(self) -> &'static str {
        match self {
            Generation::Current => "current",
            Generation::Pending => "pending",
            Generation::Previous => "previous",
        }
    }
}

fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(suffix);
    path.with_file_name(name)
}

pub fn pending_path(path: &Path) -> PathBuf {
    sibling(path, ".tmp")
}

pub fn previous_path(path: &Path) -> PathBuf {
    sibling(path, ".prev")
}

fn read_bounded(path: &Path, max_bytes: u64) -> Result<Vec<u8>> {
    let file = File::open(path)?;
    let mut bytes = Vec::new();
    file.take(max_bytes + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        return Err(format!("{} exceeds the safe size limit", path.display()).into());
    }
    Ok(bytes)
}

/// Load the newest valid generation. `Ok(None)` only when no generation exists
/// at all; files that exist but fail `parse` are skipped and, if nothing valid
/// remains, reported as an error rather than an empty state.
pub fn load<T>(
    path: &Path,
    max_bytes: u64,
    parse: impl Fn(&[u8]) -> Result<T>,
) -> Result<Option<(T, Generation)>> {
    let candidates = [
        (path.to_path_buf(), Generation::Current),
        (pending_path(path), Generation::Pending),
        (previous_path(path), Generation::Previous),
    ];
    let mut errors = Vec::new();
    for (candidate, generation) in candidates {
        // A pending file next to a valid current one is an interrupted write
        // that never became current; it is ignored by returning early above it.
        if !candidate.exists() {
            continue;
        }
        match read_bounded(&candidate, max_bytes).and_then(|bytes| parse(&bytes)) {
            Ok(value) => return Ok(Some((value, generation))),
            Err(e) => errors.push(format!("{}: {e}", candidate.display())),
        }
    }
    if errors.is_empty() {
        Ok(None)
    } else {
        Err(format!("no valid generation: {}", errors.join("; ")).into())
    }
}

fn sync_dir(dir: &Path) {
    // Directory fsync makes renames durable on Unix; Windows has no equivalent
    // for directories and relies on the file flushes.
    #[cfg(unix)]
    if let Ok(d) = File::open(dir) {
        let _ = d.sync_all();
    }
    #[cfg(not(unix))]
    let _ = dir;
}

/// Write `bytes` as the new current generation.
pub fn store(path: &Path, bytes: &[u8], validate: impl Fn(&[u8]) -> Result<()>) -> Result<()> {
    store_steps(path, bytes, validate, usize::MAX)
}

/// `store` that stops after `steps` completed steps, to inject crashes in tests.
fn store_steps(
    path: &Path,
    bytes: &[u8],
    validate: impl Fn(&[u8]) -> Result<()>,
    steps: usize,
) -> Result<()> {
    validate(bytes)?;
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    fs::create_dir_all(&dir)?;
    let pending = pending_path(path);
    let previous = previous_path(path);
    if pending.exists() {
        // Left over from an interrupted write; it never became authoritative.
        fs::remove_file(&pending)?;
    }

    // 1. Write and flush the pending generation.
    {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&pending)?;
        restrict_to_owner(&pending)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    if steps == 1 {
        return Ok(());
    }
    // 2. Re-read what reached the disk before trusting it.
    let written = read_bounded(&pending, bytes.len() as u64)?;
    if written != bytes {
        fs::remove_file(&pending)?;
        return Err("pending generation did not read back identically".into());
    }
    validate(&written)?;
    if steps == 2 {
        return Ok(());
    }
    // 3. Keep the last validated generation as `.prev` (replaces an older one).
    if path.exists() {
        fs::rename(path, &previous)?;
        sync_dir(&dir);
    }
    if steps == 3 {
        return Ok(());
    }
    // 4. Promote the pending generation.
    fs::rename(&pending, path)?;
    sync_dir(&dir);
    Ok(())
}

/// Limit a file AegisGuard creates to its owner (Unix mode 0600; on Windows a
/// protected DACL granting the owner, SYSTEM and Administrators only).
#[cfg(unix)]
pub fn restrict_to_owner(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(windows)]
pub fn restrict_to_owner(path: &Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{
        SetFileSecurityW, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR,
    };
    // P: protected (no inheritance); OW: owner rights, SY: SYSTEM, BA: Administrators.
    let sddl: Vec<u16> = "D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)"
        .encode_utf16()
        .chain([0])
        .collect();
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: both strings are NUL-terminated; the descriptor allocated by the
    // conversion is released with LocalFree after use.
    unsafe {
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            std::ptr::null_mut(),
        ) == 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        let ok = SetFileSecurityW(
            wide.as_ptr(),
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            descriptor,
        );
        let error = std::io::Error::last_os_error();
        LocalFree(descriptor as _);
        if ok == 0 {
            return Err(error.into());
        }
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
pub fn restrict_to_owner(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("aegisguard-store-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn parse(bytes: &[u8]) -> Result<String> {
        let text = std::str::from_utf8(bytes)?;
        // Stand-in for real validation: complete records end with ";end".
        if !text.ends_with(";end") {
            return Err("truncated".into());
        }
        Ok(text.to_owned())
    }

    fn validate(bytes: &[u8]) -> Result<()> {
        parse(bytes).map(|_| ())
    }

    fn load_text(path: &Path) -> Result<Option<(String, Generation)>> {
        load(path, 1024, parse)
    }

    #[test]
    fn crash_at_every_step_leaves_old_or_new_generation() {
        let dir = temp_dir("crash");
        let path = dir.join("cache.json");
        for steps in 1..=4 {
            let _ = fs::remove_dir_all(&dir);
            store(&path, b"A;end", validate).unwrap();
            store_steps(&path, b"B;end", validate, steps).unwrap();
            let (value, generation) = load_text(&path).unwrap().unwrap();
            match steps {
                1 | 2 => assert_eq!((value.as_str(), generation), ("A;end", Generation::Current)),
                3 => assert_eq!((value.as_str(), generation), ("B;end", Generation::Pending)),
                _ => assert_eq!((value.as_str(), generation), ("B;end", Generation::Current)),
            }
            // The next successful write repairs any interrupted state.
            store(&path, b"C;end", validate).unwrap();
            assert_eq!(
                load_text(&path).unwrap().unwrap(),
                ("C;end".to_owned(), Generation::Current)
            );
            assert!(!pending_path(&path).exists());
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn truncated_current_falls_back_to_previous_generation() {
        let dir = temp_dir("truncated");
        let path = dir.join("cache.json");
        store(&path, b"A;end", validate).unwrap();
        store(&path, b"B;end", validate).unwrap();
        fs::write(&path, b"B;e").unwrap();
        assert_eq!(
            load_text(&path).unwrap().unwrap(),
            ("A;end".to_owned(), Generation::Previous)
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn nothing_valid_is_an_error_not_an_empty_state() {
        let dir = temp_dir("broken");
        let path = dir.join("cache.json");
        assert!(load_text(&path).unwrap().is_none());
        fs::write(&path, b"garbage").unwrap();
        assert!(load_text(&path).is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn invalid_new_generation_is_rejected_before_touching_current() {
        let dir = temp_dir("invalid");
        let path = dir.join("cache.json");
        store(&path, b"A;end", validate).unwrap();
        assert!(store(&path, b"half", validate).is_err());
        assert_eq!(
            load_text(&path).unwrap().unwrap(),
            ("A;end".to_owned(), Generation::Current)
        );
        assert!(!pending_path(&path).exists());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn oversized_generation_is_not_loaded() {
        let dir = temp_dir("oversized");
        let path = dir.join("cache.json");
        fs::write(&path, vec![b'x'; 2048]).unwrap();
        assert!(load_text(&path).is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn stored_files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("mode");
        let path = dir.join("cache.json");
        store(&path, b"A;end", validate).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn stored_files_have_a_protected_owner_only_dacl() {
        let dir = temp_dir("acl");
        let path = dir.join("cache.json");
        store(&path, b"A;end", validate).unwrap();
        let out = std::process::Command::new("icacls")
            .arg(&path)
            .output()
            .unwrap();
        let acl = String::from_utf8_lossy(&out.stdout).to_lowercase();
        // Inherited entries (I) and broad groups must be gone.
        assert!(!acl.contains("(i)"), "{acl}");
        assert!(
            !acl.contains("everyone") && !acl.contains("\\users:"),
            "{acl}"
        );
        fs::remove_dir_all(dir).unwrap();
    }
}
