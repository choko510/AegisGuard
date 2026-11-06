//! Windows-only, read-only SCM bindings. No service-control mutation APIs.
#![allow(non_snake_case)] // Win32 function names match their published ABI.
use driver_inventory::{
    count_multisz_units, next_page, normalize_image_path, Collection, RawService, MAX_DURATION_MS,
    MAX_ENTRIES, MAX_ENUM_PAGES,
};
use std::ffi::c_void;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsRawHandle;
use std::ptr::null;
use std::time::Instant;

type Handle = *mut c_void;
const ENUM_BUFFER: usize = 256 * 1024;
const CONFIG_BUFFER: usize = 8192;
const ERROR_MORE_DATA: u32 = 234;
const ERROR_ACCESS_DENIED: u32 = 5;
const SERVICE_QUERY_CONFIG: u32 = 0x0001;
const SC_MANAGER_ENUMERATE_SERVICE: u32 = 0x0004;
const SERVICE_STATE_ALL: u32 = 3;
const SERVICE_DRIVER_AND_WIN32: u32 = 0x3b;
const SC_ENUM_PROCESS_INFO: i32 = 0;
const SERVICE_CONFIG_DELAYED_AUTO_START_INFO: u32 = 3;

#[repr(C)]
#[derive(Clone, Copy)]
struct ServiceStatusProcess {
    service_type: u32,
    current_state: u32,
    controls_accepted: u32,
    win32_exit_code: u32,
    service_specific_exit_code: u32,
    check_point: u32,
    wait_hint: u32,
    process_id: u32,
    service_flags: u32,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct EnumServiceStatusProcessW {
    name: *const u16,
    display_name: *const u16,
    status: ServiceStatusProcess,
}
#[repr(C)]
struct QueryServiceConfigW {
    service_type: u32,
    start_type: u32,
    error_control: u32,
    binary_path: *const u16,
    load_order_group: *const u16,
    tag_id: u32,
    dependencies: *const u16,
    service_start_name: *const u16,
    display_name: *const u16,
}

#[link(name = "Advapi32")]
extern "system" {
    fn OpenSCManagerW(machine: *const u16, database: *const u16, access: u32) -> Handle;
    fn EnumServicesStatusExW(
        manager: Handle,
        info_level: i32,
        service_type: u32,
        service_state: u32,
        services: *mut u8,
        buffer_size: u32,
        needed: *mut u32,
        returned: *mut u32,
        resume: *mut u32,
        group_name: *const u16,
    ) -> i32;
    fn OpenServiceW(manager: Handle, name: *const u16, access: u32) -> Handle;
    fn QueryServiceConfigW(
        service: Handle,
        config: *mut QueryServiceConfigW,
        buffer_size: u32,
        needed: *mut u32,
    ) -> i32;
    fn QueryServiceConfig2W(
        service: Handle,
        level: u32,
        buffer: *mut u8,
        buffer_size: u32,
        needed: *mut u32,
    ) -> i32;
    fn CloseServiceHandle(handle: Handle) -> i32;
}
#[link(name = "Kernel32")]
extern "system" {
    fn GetWindowsDirectoryW(buffer: *mut u16, capacity: u32) -> u32;
}

struct OwnedHandle(Handle);
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: An SCM-owned handle returned by OpenSCManagerW/OpenServiceW.
            unsafe {
                CloseServiceHandle(self.0);
            }
        }
    }
}
fn win_error() -> u32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32
}
fn error_code(code: u32) -> &'static str {
    if code == ERROR_ACCESS_DENIED {
        "permission_denied"
    } else {
        "error"
    }
}
fn wide(s: &str) -> Vec<u16> {
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(Some(0))
        .collect()
}

/// Validate that a returned UTF-16 pointer and terminating NUL reside wholly
/// inside the buffer supplied to SCM; never follow unbounded native pointers.
fn bounded_wide(ptr: *const u16, bytes: &[u64], max: usize) -> Result<String, &'static str> {
    if ptr.is_null() {
        return Err("missing_native_string");
    }
    let begin = bytes.as_ptr() as usize;
    let end = begin
        .checked_add(bytes.len() * 8)
        .ok_or("invalid_native_pointer")?;
    let address = ptr as usize;
    if address < begin || address >= end || address % 2 != 0 {
        return Err("invalid_native_pointer");
    }
    let available = (end - address) / 2;
    let mut result = Vec::new();
    for index in 0..available.min(max + 1) {
        // SAFETY: The pointer was range/alignment checked against our live
        // backing allocation; index is bounded by the allocation length.
        let unit = unsafe { *ptr.add(index) };
        if unit == 0 {
            return String::from_utf16(&result).map_err(|_| "invalid_utf16");
        }
        if index == max {
            break;
        }
        result.push(unit);
    }
    Err("native_string_limit")
}
fn bounded_multisz(ptr: *const u16, bytes: &[u64]) -> Result<usize, &'static str> {
    if ptr.is_null() {
        return Ok(0);
    }
    let begin = bytes.as_ptr() as usize;
    let end = begin
        .checked_add(bytes.len() * 8)
        .ok_or("invalid_native_pointer")?;
    let address = ptr as usize;
    if address < begin || address >= end || address % 2 != 0 {
        return Err("invalid_native_pointer");
    }
    let mut units = Vec::new();
    for index in 0..((end - address) / 2).min(1024) {
        // SAFETY: validated pointer/alignment and bounded by the owned SCM buffer.
        let unit = unsafe { *ptr.add(index) };
        if unit == 0 && (units.is_empty() || units.last() == Some(&0)) {
            units.push(0);
            return count_multisz_units(&units);
        }
        units.push(unit);
    }
    Err("multisz_limit")
}
fn query_config(manager: Handle, name: &str, service: &mut RawService) {
    let name_w = wide(name);
    // SAFETY: NUL-terminated UTF-16 name, QUERY_CONFIG only.
    let handle = unsafe { OpenServiceW(manager, name_w.as_ptr(), SERVICE_QUERY_CONFIG) };
    if handle.is_null() {
        service.config_error = Some(error_code(win_error()));
        return;
    }
    let _service_handle = OwnedHandle(handle);
    let mut mem = vec![0u64; CONFIG_BUFFER / 8];
    let mut needed = 0u32;
    // SAFETY: Owned, aligned, bounded 8-KiB buffer, SCM service handle.
    let ok = unsafe {
        QueryServiceConfigW(
            handle,
            mem.as_mut_ptr().cast::<QueryServiceConfigW>(),
            CONFIG_BUFFER as u32,
            &mut needed,
        )
    };
    if ok == 0 {
        service.config_error = Some(if needed as usize > CONFIG_BUFFER {
            "config_too_large"
        } else {
            error_code(win_error())
        });
        return;
    }
    // SAFETY: Successful QueryServiceConfigW writes a QUERY_SERVICE_CONFIGW.
    let config = unsafe { (mem.as_ptr().cast::<QueryServiceConfigW>()).read_unaligned() };
    service.start_type = Some(config.start_type);
    match bounded_wide(config.binary_path, &mem, driver_inventory::MAX_IMAGE_UNITS) {
        Ok(image) => service.image_path = Some(image),
        Err(_) => service.config_error = Some("unavailable"),
    }
    match bounded_multisz(config.dependencies, &mem) {
        Ok(count) => service.dependency_count = Some(count),
        Err(_) => service.config_error = Some("unavailable"),
    }
    // Delayed-auto-start applies to automatic Win32 services, not drivers.
    // Never silently label a failed query as "false"/disabled.
    if service.start_type == Some(2) && !driver_inventory::is_driver(service.service_type) {
        let mut delayed = [0u32; 2];
        let mut required = 0u32;
        // SAFETY: Exact 8-byte buffer and read-only configuration query.
        if unsafe {
            QueryServiceConfig2W(
                handle,
                SERVICE_CONFIG_DELAYED_AUTO_START_INFO,
                delayed.as_mut_ptr().cast::<u8>(),
                size_of::<[u32; 2]>() as u32,
                &mut required,
            )
        } != 0
        {
            service.delayed_auto_start = Some(delayed[0] != 0);
        } else if service.config_error.is_none() {
            service.config_error = Some(error_code(win_error()));
        }
    }
}
pub fn windows_directory() -> Result<String, &'static str> {
    let mut buffer = [0u16; 512];
    // SAFETY: Fixed-size output buffer and its capacity.
    let len = unsafe { GetWindowsDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
    if len == 0 || len >= buffer.len() {
        return Err("windows_directory_unavailable");
    }
    String::from_utf16(&buffer[..len]).map_err(|_| "windows_directory_invalid")
}

pub fn collect(drivers_only: bool, started: Instant) -> Collection {
    let mut result = Collection {
        services: Vec::new(),
        enumeration_status: "unavailable",
        error_code: None,
        pages: 0,
    };
    // SAFETY: Null machine/database means local active SCM; read-only access.
    let manager = unsafe { OpenSCManagerW(null(), null(), SC_MANAGER_ENUMERATE_SERVICE) };
    if manager.is_null() {
        result.error_code = Some(error_code(win_error()));
        result.enumeration_status = if result.error_code == Some("permission_denied") {
            "permission_denied"
        } else {
            "unavailable"
        };
        return result;
    }
    let _manager_handle = OwnedHandle(manager);
    let mut resume = 0u32;
    let mut seen = std::collections::HashSet::new();
    // Use a fixed 256-KiB page with alignment suitable for the C struct.
    let mut mem = vec![0u64; ENUM_BUFFER / 8];
    for page in 0..MAX_ENUM_PAGES {
        if started.elapsed().as_millis() > MAX_DURATION_MS {
            result.enumeration_status = "partial";
            result.error_code = Some("time_limit");
            return result;
        }
        let mut needed = 0u32;
        let mut returned = 0u32;
        let previous = resume;
        // SAFETY: All pointers refer to bounded writable storage; no mutation APIs.
        let ok = unsafe {
            EnumServicesStatusExW(
                manager,
                SC_ENUM_PROCESS_INFO,
                if drivers_only {
                    0x0b
                } else {
                    SERVICE_DRIVER_AND_WIN32
                },
                SERVICE_STATE_ALL,
                mem.as_mut_ptr().cast::<u8>(),
                ENUM_BUFFER as u32,
                &mut needed,
                &mut returned,
                &mut resume,
                null(),
            )
        };
        result.pages = page + 1;
        let code = if ok != 0 { 0 } else { win_error() };
        if code != 0 && code != ERROR_MORE_DATA {
            result.error_code = Some(error_code(code));
            result.enumeration_status = if result.services.is_empty() {
                if code == ERROR_ACCESS_DENIED {
                    "permission_denied"
                } else {
                    "error"
                }
            } else {
                "partial"
            };
            return result;
        }
        let count = returned as usize;
        if count > ENUM_BUFFER / size_of::<EnumServiceStatusProcessW>() {
            result.enumeration_status = "partial";
            result.error_code = Some("invalid_native_count");
            return result;
        }
        for index in 0..count {
            if result.services.len() >= MAX_ENTRIES {
                result.enumeration_status = "partial";
                result.error_code = Some("entry_limit");
                return result;
            }
            // SAFETY: count checked against buffer size, and memory is aligned.
            let row = unsafe {
                mem.as_ptr()
                    .cast::<EnumServiceStatusProcessW>()
                    .add(index)
                    .read_unaligned()
            };
            let name = match bounded_wide(row.name, &mem, 256) {
                Ok(name) => name,
                Err(_) => {
                    result.error_code = Some("invalid_service_name");
                    result.enumeration_status = "partial";
                    return result;
                }
            };
            if !seen.insert(name.to_lowercase()) {
                result.enumeration_status = "partial";
                result.error_code = Some("duplicate_scm_name");
                return result;
            }
            let mut record = RawService {
                name: name.clone(),
                evidence_source: "windows_scm",
                service_type: row.status.service_type,
                state: row.status.current_state,
                start_type: None,
                image_path: None,
                delayed_auto_start: None,
                dependency_count: None,
                config_error: None,
                file_state: None,
                signature: None,
            };
            query_config(manager, &name, &mut record);
            result.services.push(record);
        }
        match next_page(code, count, previous, resume) {
            Ok(true) => {}
            Ok(false) => {
                result.enumeration_status = "complete";
                return result;
            }
            Err(code) => {
                result.enumeration_status = if result.services.is_empty() {
                    "error"
                } else {
                    "partial"
                };
                result.error_code = Some(code);
                return result;
            }
        }
    }
    result.enumeration_status = "partial";
    result.error_code = Some("page_limit");
    result
}

pub fn enrich(
    collection: &mut Collection,
    windows_dir: &str,
    verify_signatures: bool,
    started: Instant,
) {
    if verify_signatures && collection.services.len() > 256 {
        collection.enumeration_status = "partial";
        collection.error_code = Some("signature_count_limit");
    }
    for (index, service) in collection.services.iter_mut().enumerate() {
        if started.elapsed().as_millis() > MAX_DURATION_MS {
            collection.enumeration_status = "partial";
            collection.error_code = Some("probe_time_limit");
            break;
        }
        // Signature verification is a separate expensive opt-in with a hard count cap.
        let Some(raw) = service.image_path.as_deref() else {
            continue;
        };
        let (resolved, _) = normalize_image_path(raw, windows_dir);
        let Some(path) = resolved else {
            service.file_state = Some("unknown");
            continue;
        };
        match std::fs::symlink_metadata(&path) {
            Ok(meta) if meta.file_type().is_symlink() => service.file_state = Some("unknown"),
            Ok(meta) if meta.is_file() => {
                service.file_state = Some("exists");
                if verify_signatures && index < 256 {
                    service.signature = Some(verify_embedded_signature(&path));
                }
            }
            Ok(_) => service.file_state = Some("unknown"),
            Err(e) => {
                service.file_state = Some(match e.kind() {
                    std::io::ErrorKind::NotFound => "missing",
                    std::io::ErrorKind::PermissionDenied => "permission_denied",
                    _ => "error",
                })
            }
        }
    }
}

#[repr(C)]
struct Guid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}
const VERIFY_V2: Guid = Guid {
    data1: 0x00aac56b,
    data2: 0xcd44,
    data3: 0x11d0,
    data4: [0x8c, 0xc2, 0, 0xc0, 0x4f, 0xc2, 0x95, 0xee],
};
#[repr(C)]
struct WintrustFileInfo {
    size: u32,
    filename: *const u16,
    file_handle: Handle,
    known_subject: *const Guid,
}
#[repr(C)]
struct WintrustData {
    size: u32,
    policy_data: Handle,
    sip_data: Handle,
    ui_choice: u32,
    revocation: u32,
    union_choice: u32,
    file_info: *mut WintrustFileInfo,
    state_action: u32,
    state_data: Handle,
    url: *const u16,
    provider_flags: u32,
    ui_context: u32,
    signature_settings: Handle,
}
#[link(name = "Wintrust")]
extern "system" {
    fn WinVerifyTrust(window: Handle, action: *const Guid, data: *mut WintrustData) -> i32;
}
fn verify_embedded_signature(path: &str) -> &'static str {
    // Keep the checked file open while WinVerifyTrust evaluates it. Some
    // providers may still resolve the path; this is not a complete TOCTOU
    // guarantee (notably for parent-directory reparse races).
    let opened = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(_) => return "unknown",
    };
    let wide_path = wide(path);
    let mut file = WintrustFileInfo {
        size: size_of::<WintrustFileInfo>() as u32,
        filename: wide_path.as_ptr(),
        file_handle: opened.as_raw_handle(),
        known_subject: null(),
    };
    let mut data = WintrustData {
        size: size_of::<WintrustData>() as u32,
        policy_data: std::ptr::null_mut(),
        sip_data: std::ptr::null_mut(),
        ui_choice: 2,
        revocation: 0,
        union_choice: 1,
        file_info: &mut file,
        state_action: 0,
        state_data: std::ptr::null_mut(),
        url: null(),
        provider_flags: 0x1010,
        ui_context: 0,
        signature_settings: std::ptr::null_mut(),
    };
    // SAFETY: Fixed WinTrust structures and NUL-terminated local filename; WTD_UI_NONE,
    // WTD_CACHE_ONLY_URL_RETRIEVAL and WTD_REVOCATION_CHECK_NONE forbid remote retrieval.
    let code = unsafe { WinVerifyTrust(std::ptr::null_mut(), &VERIFY_V2, &mut data) } as u32;
    match code {
        0 => "verified_embedded",
        0x80096010 => "invalid", // TRUST_E_BAD_DIGEST
        0x800b0109 => "untrusted_chain",
        _ => "unknown", // Catalog-only signed files can appear unsigned here.
    }
}
