//! Handle-based file access for the scanner. The final path component is opened
//! without following symlinks/reparse points, the opened handle's identity is
//! recorded, and the path is re-resolved after reading so that a swapped or
//! modified file is reported instead of being attributed to the wrong path.
//! Files are opened with full sharing so that AegisGuard never blocks other writers.
use std::fs::{File, Metadata, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

/// Stable identity of an opened file: (device, file id) on Unix,
/// (volume serial, file index) on Windows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandleId {
    pub device: u64,
    pub file: u64,
    pub links: u64,
}

#[derive(Debug)]
pub enum OpenFailure {
    /// The final component is a symlink or other reparse point.
    Link,
    NotRegular,
    Io(io::Error),
}

#[cfg(unix)]
fn no_follow(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
}

#[cfg(windows)]
fn no_follow(options: &mut OpenOptions) {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
    // FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE: never block other programs.
    options.share_mode(0x7);
    options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
}

#[cfg(not(any(unix, windows)))]
fn no_follow(_options: &mut OpenOptions) {}

#[cfg(windows)]
fn is_link(meta: &Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
    meta.file_type().is_symlink() || meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_link(meta: &Metadata) -> bool {
    meta.file_type().is_symlink()
}

/// Open a regular file for reading without following a link in the final component.
pub fn open_regular(path: &Path) -> Result<(File, Metadata), OpenFailure> {
    let mut options = OpenOptions::new();
    options.read(true);
    no_follow(&mut options);
    let file = match options.open(path) {
        Ok(file) => file,
        // O_NOFOLLOW on a symlink fails with ELOOP.
        #[cfg(unix)]
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => return Err(OpenFailure::Link),
        Err(e) => return Err(OpenFailure::Io(e)),
    };
    let meta = file.metadata().map_err(OpenFailure::Io)?;
    if is_link(&meta) {
        return Err(OpenFailure::Link);
    }
    if !meta.is_file() {
        return Err(OpenFailure::NotRegular);
    }
    Ok((file, meta))
}

#[cfg(unix)]
pub fn handle_id(file: &File) -> io::Result<HandleId> {
    use std::os::unix::fs::MetadataExt;
    let meta = file.metadata()?;
    Ok(HandleId {
        device: meta.dev(),
        file: meta.ino(),
        links: meta.nlink(),
    })
}

#[cfg(windows)]
pub fn handle_id(file: &File) -> io::Result<HandleId> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };
    // SAFETY: the handle is owned by `file` and valid for this call; the
    // output struct is plain data written by the API.
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle() as _, &mut info) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(HandleId {
        device: u64::from(info.dwVolumeSerialNumber),
        file: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
        links: u64::from(info.nNumberOfLinks),
    })
}

#[cfg(not(any(unix, windows)))]
pub fn handle_id(_file: &File) -> io::Result<HandleId> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "no handle identity",
    ))
}

/// The path the OS resolves for an open handle, when the platform exposes it.
#[cfg(windows)]
pub fn final_path(file: &File) -> Option<PathBuf> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFinalPathNameByHandleW, FILE_NAME_NORMALIZED, VOLUME_NAME_DOS,
    };
    let mut buf = vec![0u16; 1024];
    for _ in 0..2 {
        // SAFETY: `buf` is a writable buffer of the advertised length.
        let len = unsafe {
            GetFinalPathNameByHandleW(
                file.as_raw_handle() as _,
                buf.as_mut_ptr(),
                buf.len() as u32,
                FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
            )
        } as usize;
        if len == 0 || len > 32_768 {
            return None;
        }
        if len < buf.len() {
            return Some(PathBuf::from(OsString::from_wide(&buf[..len])));
        }
        buf.resize(len + 1, 0);
    }
    None
}

#[cfg(target_os = "linux")]
pub fn final_path(file: &File) -> Option<PathBuf> {
    use std::os::unix::io::AsRawFd;
    std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd())).ok()
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn final_path(_file: &File) -> Option<PathBuf> {
    None
}

/// Where the path should resolve: its canonical parent joined with the final
/// component, so the final component itself is never followed.
pub fn expected_path(path: &Path) -> io::Result<PathBuf> {
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?;
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    Ok(std::fs::canonicalize(parent)?.join(name))
}

pub fn same_path(a: &Path, b: &Path) -> bool {
    if cfg!(windows) {
        // NTFS names are case-insensitive by default; compare the normalized forms.
        a.as_os_str().to_string_lossy().to_lowercase()
            == b.as_os_str().to_string_lossy().to_lowercase()
    } else {
        a == b
    }
}

/// Whether `path` still names the same file as `id`, re-opened without following links.
pub fn path_refers_to(path: &Path, id: &HandleId) -> bool {
    match open_regular(path) {
        Ok((file, _)) => handle_id(&file)
            .is_ok_and(|current| current.device == id.device && current.file == id.file),
        Err(_) => false,
    }
}

/// Size and modification time must not change while the handle is read.
pub fn unchanged(before: &Metadata, after: &Metadata) -> bool {
    before.len() == after.len() && before.modified().ok() == after.modified().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("aegisguard-fsafe-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn regular_file_has_identity_and_matching_final_path() {
        let dir = temp_dir("regular");
        let path = dir.join("a.ps1");
        fs::write(&path, "Write-Output 1").unwrap();
        let (file, meta) = open_regular(&path).unwrap();
        let id = handle_id(&file).unwrap();
        assert!(meta.is_file());
        assert!(id.links >= 1);
        assert!(path_refers_to(&path, &id));
        if let Some(actual) = final_path(&file) {
            assert!(same_path(&actual, &expected_path(&path).unwrap()));
        }
        drop(file);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn replaced_path_no_longer_refers_to_opened_file() {
        let dir = temp_dir("replace");
        let path = dir.join("a.py");
        let other = dir.join("b.py");
        fs::write(&path, "print(1)").unwrap();
        fs::write(&other, "print(2)").unwrap();
        let (file, _) = open_regular(&path).unwrap();
        let id = handle_id(&file).unwrap();
        // Full sharing allows the swap even on Windows; it must then be detected.
        fs::rename(&other, &path).unwrap();
        assert!(!path_refers_to(&path, &id));
        drop(file);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn deleted_path_does_not_refer_to_opened_file() {
        let dir = temp_dir("delete");
        let path = dir.join("a.js");
        fs::write(&path, "1").unwrap();
        let (file, _) = open_regular(&path).unwrap();
        let id = handle_id(&file).unwrap();
        fs::remove_file(&path).unwrap();
        assert!(!path_refers_to(&path, &id));
        drop(file);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn directory_is_not_a_regular_file() {
        let dir = temp_dir("dir");
        assert!(open_regular(&dir).is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn symlink_final_component_is_never_followed() {
        let dir = temp_dir("symlink");
        fs::write(dir.join("real.ps1"), "1").unwrap();
        std::os::unix::fs::symlink(dir.join("real.ps1"), dir.join("link.ps1")).unwrap();
        assert!(matches!(
            open_regular(&dir.join("link.ps1")),
            Err(OpenFailure::Link)
        ));
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_symlink_is_opened_as_reparse_point_and_rejected() {
        let dir = temp_dir("winlink");
        fs::write(dir.join("real.ps1"), "1").unwrap();
        // Creating symlinks needs Developer Mode or elevation; skip when unavailable.
        if std::os::windows::fs::symlink_file(dir.join("real.ps1"), dir.join("link.ps1")).is_ok() {
            assert!(matches!(
                open_regular(&dir.join("link.ps1")),
                Err(OpenFailure::Link)
            ));
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn modification_is_detected_by_metadata() {
        let dir = temp_dir("modify");
        let path = dir.join("a.py");
        fs::write(&path, "print(1)").unwrap();
        let (file, before) = open_regular(&path).unwrap();
        fs::write(&path, "print(1)\nprint(2)").unwrap();
        let after = file.metadata().unwrap();
        assert!(!unchanged(&before, &after));
        drop(file);
        fs::remove_dir_all(dir).unwrap();
    }
}
