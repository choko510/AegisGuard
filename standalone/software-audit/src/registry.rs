//! Windows-only Uninstall registry enumeration. No registry writes or processes.
#![cfg(windows)]
use std::ffi::c_void;
use std::ptr;
use crate::model::{RawEntry, SourceData};

const UNINSTALL: &str = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall";
const KEY_READ: u32 = 0x20019;
const KEY_QUERY_VALUE: u32 = 0x0001;
const VIEW_64: u32 = 0x0100;
const VIEW_32: u32 = 0x0200;
const REG_SZ: u32 = 1;
const REG_EXPAND_SZ: u32 = 2;
const SUCCESS: i32 = 0;
const FILE_NOT_FOUND: i32 = 2;
const ACCESS_DENIED: i32 = 5;
const NO_MORE_ITEMS: i32 = 259;
const MAX_KEYS_PER_SOURCE: u32 = 4096;
const MAX_VALUE_BYTES: u32 = 4096;
type Hkey = *mut c_void;

#[link(name = "Advapi32")]
unsafe extern "system" {
    fn RegOpenKeyExW(root: Hkey, subkey: *const u16, options: u32, access: u32, out: *mut Hkey) -> i32;
    fn RegEnumKeyExW(key: Hkey, index: u32, name: *mut u16, len: *mut u32,
        reserved: *mut u32, class: *mut u16, class_len: *mut u32, time: *mut c_void) -> i32;
    fn RegQueryValueExW(key: Hkey, name: *const u16, reserved: *mut u32,
        kind: *mut u32, data: *mut u8, size: *mut u32) -> i32;
    fn RegCloseKey(key: Hkey) -> i32;
}
struct Key(Hkey);
impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: Only successful RegOpenKeyExW handles are wrapped by Key.
        unsafe { RegCloseKey(self.0); }
    }
}
fn wide(s: &str) -> Vec<u16> { s.encode_utf16().chain(std::iter::once(0)).collect() }
fn open(root: Hkey, path: &str, access: u32) -> Result<Key, i32> {
    let mut handle: Hkey = ptr::null_mut();
    // SAFETY: path is terminated UTF-16, handle is writable, root is predefined or opened.
    let code = unsafe { RegOpenKeyExW(root, wide(path).as_ptr(), 0, access, &mut handle) };
    if code == SUCCESS && !handle.is_null() { Ok(Key(handle)) } else { Err(code) }
}
fn text(key: &Key, value_name: &str) -> Result<Option<String>, &'static str> {
    let name = wide(value_name);
    let mut kind = 0u32;
    let mut size = 0u32;
    // SAFETY: name is null terminated, null buffer requests the byte count.
    let code = unsafe { RegQueryValueExW(key.0, name.as_ptr(), ptr::null_mut(), &mut kind, ptr::null_mut(), &mut size) };
    if code == FILE_NOT_FOUND { return Ok(None); }
    if code != SUCCESS { return Err("value_read_failed"); }
    // REG_EXPAND_SZ contains an unexpanded string. Never execute or expand
    // environment variables from an untrusted Uninstall entry.
    if kind != REG_SZ && kind != REG_EXPAND_SZ { return Err("unsupported_value_type"); }
    if size == 0 || size > MAX_VALUE_BYTES || size % 2 != 0 { return Err("invalid_value_size"); }
    let mut buffer = vec![0u16; size as usize / 2 + 1];
    let mut written = size;
    // SAFETY: buffer has at least size bytes, API writes at most written bytes.
    let code = unsafe { RegQueryValueExW(key.0, name.as_ptr(), ptr::null_mut(), &mut kind,
        buffer.as_mut_ptr().cast(), &mut written) };
    if code != SUCCESS || (kind != REG_SZ && kind != REG_EXPAND_SZ)
        || written == 0 || written > size || written % 2 != 0 {
        return Err("value_changed_or_invalid");
    }
    let units = &buffer[..written as usize / 2];
    let end = units.iter().position(|&c| c == 0).unwrap_or(units.len());
    String::from_utf16(&units[..end]).map(Some).map_err(|_| "invalid_utf16")
}
fn collect_source(id: &str, root: Hkey, view: u32) -> SourceData {
    let mut data = SourceData { id: id.into(), status: "complete".into(), entries: Vec::new(), skipped: 0 };
    let parent = match open(root, UNINSTALL, KEY_READ | view) {
        Ok(key) => key,
        Err(FILE_NOT_FOUND) => return data,
        Err(ACCESS_DENIED) => { data.status = "permission_denied".into(); return data; }
        Err(_) => { data.status = "error".into(); return data; }
    };
    for index in 0..=MAX_KEYS_PER_SOURCE {
        let mut name = [0u16; 260];
        let mut len = name.len() as u32;
        // SAFETY: buffer is writable, length in UTF16 characters; other pointers are null.
        let code = unsafe { RegEnumKeyExW(parent.0, index, name.as_mut_ptr(), &mut len,
            ptr::null_mut(), ptr::null_mut(), ptr::null_mut(), ptr::null_mut()) };
        if code == NO_MORE_ITEMS { break; }
        if index == MAX_KEYS_PER_SOURCE || code != SUCCESS || len as usize >= name.len() {
            data.status = "partial".into(); break;
        }
        let Ok(subkey) = String::from_utf16(&name[..len as usize]) else {
            data.status = "partial".into(); continue;
        };
        let Ok(child) = open(parent.0, &subkey, KEY_QUERY_VALUE | view) else {
            data.status = "partial".into(); continue;
        };
        let name = match text(&child, "DisplayName") {
            Ok(Some(s)) if !s.trim().is_empty() => s,
            Ok(_) | Err(_) => {
                // Registered subkey exists but could not supply a usable name.
                // It must not silently disappear from the coverage report.
                data.skipped += 1;
                data.status = "partial".into();
                continue;
            }
        };
        let version = match text(&child, "DisplayVersion") {
            Ok(v) => v,
            Err(_) => { data.status = "partial".into(); None }
        };
        let publisher = match text(&child, "Publisher") {
            Ok(v) => v,
            Err(_) => { data.status = "partial".into(); None }
        };
        // Registry view does not prove executable architecture.
        data.entries.push(RawEntry { name, version, publisher, architecture: None, edition: None });
    }
    data
}
pub fn collect() -> Vec<SourceData> {
    let hklm = (0x8000_0002u32 as i32 as isize) as Hkey;
    let hkcu = (0x8000_0001u32 as i32 as isize) as Hkey;
    vec![
        collect_source("hklm64", hklm, VIEW_64),
        collect_source("hklm32", hklm, VIEW_32),
        collect_source("hkcu64", hkcu, VIEW_64),
        collect_source("hkcu32", hkcu, VIEW_32),
    ]
}
