//! Read-only Windows ADS probe. The input is restricted to local absolute drive paths.
use crate::{Evidence, MAX_STREAM_BYTES};
use std::ffi::{c_void, OsStr};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::Read;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::AsRawHandle;
use std::path::{Component, Path, PathBuf, Prefix};
use std::time::{Duration, Instant};

const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
const FILE_NAMED_STREAMS: u32 = 0x0004_0000;
const FILE_ID_INFO_CLASS: i32 = 18;
const MAX_PATH_CHARS: usize = 2048;
const FINAL_PATH_BUFFER_CHARS: usize = MAX_PATH_CHARS * 2 + 16;
const SOFT_DEADLINE: Duration = Duration::from_secs(3);

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdInfo {
    volume_serial_number: u64,
    file_id: [u8; 16],
}

#[link(name = "kernel32")]
extern "system" {
    fn GetDriveTypeW(root: *const u16) -> u32;
    fn GetFinalPathNameByHandleW(
        file: *mut c_void,
        output: *mut u16,
        output_len: u32,
        flags: u32,
    ) -> u32;
    fn GetVolumeInformationByHandleW(
        file: *mut c_void,
        volume_name: *mut u16,
        volume_name_length: u32,
        volume_serial: *mut u32,
        max_component_length: *mut u32,
        flags: *mut u32,
        fs_name: *mut u16,
        fs_name_length: u32,
    ) -> i32;
    fn GetFileInformationByHandleEx(
        file: *mut c_void,
        class: i32,
        buffer: *mut c_void,
        size: u32,
    ) -> i32;
}

fn io_error(error: std::io::Error) -> Evidence {
    match error.kind() {
        std::io::ErrorKind::PermissionDenied => Evidence::PermissionDenied,
        _ => Evidence::Error("windows_file_io_error"),
    }
}

fn get_id(file: &File) -> Result<FileIdInfo, Evidence> {
    let mut info = FileIdInfo {
        volume_serial_number: 0,
        file_id: [0; 16],
    };
    // SAFETY: file is a valid open handle and the output is a writable repr(C) buffer.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FILE_ID_INFO_CLASS,
            (&mut info as *mut FileIdInfo).cast(),
            std::mem::size_of::<FileIdInfo>() as u32,
        )
    };
    if ok == 0 {
        Err(Evidence::Error("file_identity_unavailable"))
    } else {
        Ok(info)
    }
}

fn supports_named_streams(file: &File) -> Result<bool, Evidence> {
    let mut flags = 0u32;
    // SAFETY: the handle is live; all optional buffers are null with zero lengths.
    let ok = unsafe {
        GetVolumeInformationByHandleW(
            file.as_raw_handle(),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut flags,
            std::ptr::null_mut(),
            0,
        )
    };
    if ok == 0 {
        Err(Evidence::Error("filesystem_capabilities_unavailable"))
    } else {
        Ok(flags & FILE_NAMED_STREAMS != 0)
    }
}

fn reject_suspicious_components(path: &Path) -> Result<(), Evidence> {
    let Some(name) = path.to_str() else {
        return Err(Evidence::Error("invalid_path_encoding"));
    };
    if name.chars().count() > MAX_PATH_CHARS || name.contains('\0') {
        return Err(Evidence::Error("path_length_or_control_limit"));
    }
    let mut components = path.components();
    let disk = match components.next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            Prefix::Disk(letter) => letter,
            _ => return Err(Evidence::Error("nonlocal_path_rejected")),
        },
        _ => return Err(Evidence::Error("absolute_drive_path_required")),
    };
    if !matches!(components.next(), Some(Component::RootDir)) {
        return Err(Evidence::Error("absolute_drive_path_required"));
    }
    if !matches!(components.next_back(), Some(Component::Normal(_))) {
        return Err(Evidence::Error("regular_file_path_required"));
    }
    let root = format!("{}:\\", char::from(disk));
    let wide: Vec<u16> = OsStr::new(&root).encode_wide().chain(Some(0)).collect();
    // SAFETY: wide is a valid, NUL-terminated Windows root path.
    let kind = unsafe { GetDriveTypeW(wide.as_ptr()) };
    if !matches!(kind, 2 | 3 | 6) {
        return Err(Evidence::Error("nonlocal_or_unknown_drive_rejected"));
    }
    for component in path.components() {
        match component {
            Component::ParentDir | Component::CurDir => {
                return Err(Evidence::Error("path_traversal_rejected"));
            }
            Component::Normal(part) => {
                let Some(s) = part.to_str() else {
                    return Err(Evidence::Error("invalid_path_encoding"));
                };
                if s.contains(':')
                    || s.ends_with(' ')
                    || s.ends_with('.')
                    || s.chars().any(char::is_control)
                {
                    return Err(Evidence::Error("unsafe_path_component"));
                }
                let stem = s.split('.').next().unwrap_or("").to_ascii_uppercase();
                if matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
                    || (stem.len() == 4
                        && (stem.starts_with("COM") || stem.starts_with("LPT"))
                        && stem.as_bytes()[3].is_ascii_digit()
                        && stem.as_bytes()[3] != b'0')
                {
                    return Err(Evidence::Error("device_path_rejected"));
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn reject_reparse_chain(path: &Path) -> Result<(), Evidence> {
    let mut step = PathBuf::new();
    for component in path.components() {
        step.push(component.as_os_str());
        if !step.has_root() {
            continue;
        }
        let info = fs::symlink_metadata(&step).map_err(io_error)?;
        if info.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(Evidence::Error("reparse_point_rejected"));
        }
    }
    Ok(())
}

fn read_only(path: &Path) -> Result<File, Evidence> {
    OpenOptions::new()
        .read(true)
        .share_mode(0x1 | 0x2 | 0x4)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(io_error)
}

/// Fail closed if a junction or directory symlink redirected the opened file
/// away from the requested lexical path. This is not an atomic path traversal.
fn verify_opened_path(file: &File, path: &Path) -> Result<(), Evidence> {
    let expected = path
        .to_str()
        .ok_or(Evidence::Error("invalid_path_encoding"))?
        .replace('/', "\\")
        .to_lowercase();
    let mut buffer = [0u16; FINAL_PATH_BUFFER_CHARS];
    // SAFETY: the file handle remains live, the output buffer is writable,
    // and its length is passed in UTF-16 code units.
    let length = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle(),
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            0, // FILE_NAME_NORMALIZED | VOLUME_NAME_DOS
        )
    };
    if length == 0 || length as usize >= buffer.len() {
        return Err(Evidence::Error("resolved_path_unavailable"));
    }
    let resolved = String::from_utf16(&buffer[..length as usize])
        .map_err(|_| Evidence::Error("invalid_resolved_path"))?;
    let without_prefix = resolved
        .strip_prefix(r"\\?\")
        .ok_or(Evidence::Error("resolved_path_not_local_drive"))?;
    if without_prefix.to_lowercase() != expected {
        return Err(Evidence::Error("path_identity_mismatch"));
    }
    Ok(())
}

fn read_only_stream(path: &Path) -> Result<Option<File>, Evidence> {
    match OpenOptions::new()
        .read(true)
        .share_mode(0x1 | 0x2 | 0x4)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
    {
        Ok(file) => Ok(Some(file)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(io_error(error)),
    }
}

fn verify_unchanged(
    path: &Path,
    base_identity: FileIdInfo,
    base_info: &Metadata,
    start: Instant,
) -> Result<(), Evidence> {
    reject_reparse_chain(path)?;
    let current = read_only(path)?;
    verify_opened_path(&current, path)?;
    let identity = get_id(&current)?;
    let info = current.metadata().map_err(io_error)?;
    if identity != base_identity
        || info.len() != base_info.len()
        || info.modified().ok() != base_info.modified().ok()
    {
        return Err(Evidence::Error("file_changed_during_read"));
    }
    if start.elapsed() > SOFT_DEADLINE {
        return Err(Evidence::Error("soft_time_budget_exceeded"));
    }
    Ok(())
}

pub fn probe(path: &Path) -> Evidence {
    let start = Instant::now();
    if let Err(error) = reject_suspicious_components(path) {
        return error;
    }
    if let Err(error) = reject_reparse_chain(path) {
        return error;
    }
    let base = match read_only(path) {
        Ok(file) => file,
        Err(e) => return e,
    };
    if let Err(error) = verify_opened_path(&base, path) {
        return error;
    }
    let base_info = match base.metadata() {
        Ok(info) => info,
        Err(e) => return io_error(e),
    };
    if !base_info.is_file() || base_info.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Evidence::Error("regular_file_required");
    }
    let identity = match get_id(&base) {
        Ok(identity) => identity,
        Err(e) => return e,
    };
    let evidence = match supports_named_streams(&base) {
        Ok(false) => Evidence::NotSupported,
        Err(e) => e,
        Ok(true) => {
            let mut stream_name = path.as_os_str().to_os_string();
            stream_name.push(":Zone.Identifier");
            let stream_path = PathBuf::from(stream_name);
            match read_only_stream(&stream_path) {
                Ok(Some(mut stream)) => {
                    match get_id(&stream) {
                        Err(e) => e,
                        Ok(stream_id) if stream_id != identity => {
                            Evidence::Error("stream_file_identity_mismatch")
                        }
                        Ok(_) => {
                            let info_before = stream.metadata();
                            match info_before {
                                Err(e) => io_error(e),
                                Ok(before) if before.len() > MAX_STREAM_BYTES as u64 => {
                                    Evidence::Error("stream_size_limit_exceeded")
                                }
                                Ok(before) => {
                                    let mut bytes = Vec::new();
                                    let read = (&mut stream)
                                        .take((MAX_STREAM_BYTES + 1) as u64)
                                        .read_to_end(&mut bytes);
                                    match read {
                                        Err(e) => io_error(e),
                                        Ok(_) if bytes.len() > MAX_STREAM_BYTES => {
                                            Evidence::Error("stream_size_limit_exceeded")
                                        }
                                        Ok(_) => match stream.metadata() {
                                            Err(e) => io_error(e),
                                            Ok(after) if before.len() != after.len()
                                                || before.modified().ok() != after.modified().ok() => {
                                                Evidence::Error("stream_changed_during_read")
                                            }
                                            Ok(_) => Evidence::Stream(bytes),
                                        },
                                    }
                                }
                            }
                        }
                    }
                }
                Ok(None) => Evidence::Absent,
                Err(e) => e,
            }
        }
    };
    match verify_unchanged(path, identity, &base_info, start) {
        Ok(()) => evidence,
        Err(e) => e,
    }
}
