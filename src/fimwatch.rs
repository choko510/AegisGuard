//! Windows change notifications (ReadDirectoryChangesW) for the FIM baseline.
//! Notifications only trigger work: every decision is made by a rescan against
//! the baseline. A notification buffer overflow or a stopped watcher forces a
//! full rescan, and the end of the watch is reported as `monitor_stopped`.
use crate::fim::{self, Baseline};
use crate::Result;
use serde_json::json;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, ReadDirectoryChangesW, FILE_FLAG_BACKUP_SEMANTICS, FILE_LIST_DIRECTORY,
    FILE_NOTIFY_CHANGE_CREATION, FILE_NOTIFY_CHANGE_DIR_NAME, FILE_NOTIFY_CHANGE_FILE_NAME,
    FILE_NOTIFY_CHANGE_LAST_WRITE, FILE_NOTIFY_CHANGE_SIZE, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, OPEN_EXISTING,
};

enum Message {
    Changed { action: u32, path: PathBuf },
    Overflow(PathBuf),
    Stopped(PathBuf, String),
}

struct DirHandle(HANDLE);

// SAFETY: the handle is only used by the watcher thread that owns it.
unsafe impl Send for DirHandle {}

impl Drop for DirHandle {
    fn drop(&mut self) {
        // SAFETY: valid handle from CreateFileW, closed once.
        unsafe { CloseHandle(self.0) };
    }
}

fn open_dir(dir: &Path) -> Result<DirHandle> {
    let wide: Vec<u16> = dir.as_os_str().encode_wide().chain([0]).collect();
    // SAFETY: NUL-terminated path; read-only directory listing access.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(format!("{}: {}", dir.display(), std::io::Error::last_os_error()).into());
    }
    Ok(DirHandle(handle))
}

fn action_name(action: u32) -> &'static str {
    match action {
        1 => "added",
        2 => "removed",
        3 => "modified",
        4 => "renamed_old_name",
        5 => "renamed_new_name",
        _ => "other",
    }
}

fn spawn_watcher(dir: PathBuf, subtree: bool, tx: mpsc::Sender<Message>) -> Result<()> {
    let handle = open_dir(&dir)?;
    std::thread::spawn(move || {
        // Capture the whole Send wrapper, not just its raw handle field.
        let handle = handle;
        // DWORD-aligned 64 KiB buffer, as ReadDirectoryChangesW requires.
        let mut buf = vec![0u32; 16 * 1024];
        loop {
            let mut bytes = 0u32;
            // SAFETY: synchronous call with a valid handle and buffer.
            let ok = unsafe {
                ReadDirectoryChangesW(
                    handle.0,
                    buf.as_mut_ptr().cast(),
                    (buf.len() * 4) as u32,
                    i32::from(subtree),
                    FILE_NOTIFY_CHANGE_FILE_NAME
                        | FILE_NOTIFY_CHANGE_DIR_NAME
                        | FILE_NOTIFY_CHANGE_SIZE
                        | FILE_NOTIFY_CHANGE_LAST_WRITE
                        | FILE_NOTIFY_CHANGE_CREATION,
                    &mut bytes,
                    std::ptr::null_mut(),
                    None,
                )
            };
            if ok == 0 {
                let error = std::io::Error::last_os_error().to_string();
                let _ = tx.send(Message::Stopped(dir.clone(), error));
                return;
            }
            if bytes == 0 {
                // The system dropped notifications; only a rescan can recover.
                if tx.send(Message::Overflow(dir.clone())).is_err() {
                    return;
                }
                continue;
            }
            let raw: &[u8] =
                // SAFETY: the API wrote `bytes` bytes into `buf`.
                unsafe { std::slice::from_raw_parts(buf.as_ptr().cast(), bytes as usize) };
            let mut offset = 0usize;
            loop {
                let field = |at: usize| {
                    raw.get(offset + at..offset + at + 4)
                        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
                };
                let (Some(next), Some(action), Some(len)) = (field(0), field(4), field(8)) else {
                    break;
                };
                let start = offset + 12;
                let Some(name) = raw.get(start..start + len as usize) else {
                    break;
                };
                let wide: Vec<u16> = name
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                let path = dir.join(String::from_utf16_lossy(&wide));
                if tx.send(Message::Changed { action, path }).is_err() {
                    return;
                }
                if next == 0 {
                    break;
                }
                offset += next as usize;
            }
        }
    });
    Ok(())
}

fn print_check(baseline: &Baseline, reason: &str) -> Result<()> {
    let result = fim::check(baseline);
    println!(
        "{}",
        json!({"kind": "rescan", "reason": reason, "result": result})
    );
    Ok(())
}

/// Watch the baseline roots for `duration`, rescanning on overflow, watcher
/// failure and at the end. Prints one JSON object per line.
pub fn watch(baseline: &Baseline, duration: Duration) -> Result<()> {
    let (tx, rx) = mpsc::channel();
    let mut watched = Vec::new();
    for root in &baseline.roots {
        let (dir, subtree) = if root.is_dir() {
            (root.clone(), true)
        } else {
            (
                root.parent()
                    .map(Path::to_path_buf)
                    .unwrap_or_else(|| ".".into()),
                false,
            )
        };
        if !watched.contains(&dir) {
            spawn_watcher(dir.clone(), subtree, tx.clone())?;
            watched.push(dir);
        }
    }
    drop(tx);
    println!(
        "{}",
        json!({"kind": "monitor_started", "directories": watched})
    );
    let deadline = Instant::now() + duration;
    let in_scope = |path: &Path| {
        baseline
            .roots
            .iter()
            .any(|r| path == r.as_path() || path.starts_with(r))
    };
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match rx.recv_timeout(remaining) {
            Ok(Message::Changed { action, path }) if in_scope(&path) => println!(
                "{}",
                json!({"kind": "notification", "action": action_name(action), "path": path})
            ),
            Ok(Message::Changed { .. }) => {}
            Ok(Message::Overflow(dir)) => {
                println!("{}", json!({"kind": "overflow", "directory": dir}));
                print_check(baseline, "notification_overflow")?;
            }
            Ok(Message::Stopped(dir, error)) => {
                println!(
                    "{}",
                    json!({"kind": "monitor_stopped", "directory": dir, "reason": error})
                );
                print_check(baseline, "watcher_stopped")?;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => break,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                println!(
                    "{}",
                    json!({"kind": "monitor_stopped", "reason": "all watchers ended"})
                );
                break;
            }
        }
    }
    println!(
        "{}",
        json!({"kind": "monitor_stopped", "reason": "duration_elapsed"})
    );
    // Catch anything that happened without (or after) a notification.
    print_check(baseline, "final")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notifications_are_parsed_for_a_watched_directory() {
        let dir = std::env::temp_dir().join(format!("aegisguard-fimwatch-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (tx, rx) = mpsc::channel();
        spawn_watcher(dir.clone(), true, tx).unwrap();
        // Give the watcher a moment to arm before changing anything.
        std::thread::sleep(Duration::from_millis(200));
        std::fs::write(dir.join("a.txt"), "x").unwrap();
        let mut seen = false;
        while let Ok(message) = rx.recv_timeout(Duration::from_secs(5)) {
            if let Message::Changed { path, .. } = message {
                if path.ends_with("a.txt") {
                    seen = true;
                    break;
                }
            }
        }
        assert!(seen, "no notification for a.txt");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
