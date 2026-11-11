//! Bounded, read-only invocation of the fixed PowerShell collector on Windows.
//! The process is always terminated on timeout, and stdout is capped.

use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crate::MAX_CAPTURE_BYTES;

#[link(name = "kernel32")]
extern "system" {
    fn GetSystemDirectoryW(buffer: *mut u16, length: u32) -> u32;
}

pub struct Capture {
    pub bytes: Vec<u8>,
    pub failure: Option<&'static str>,
}

fn system_powershell() -> Result<PathBuf, &'static str> {
    let mut chars = vec![0u16; 32_768];
    // SAFETY: buffer has length 32768 UTF-16 elements; GetSystemDirectoryW
    // writes at most the supplied length and is a read-only system query.
    let length = unsafe { GetSystemDirectoryW(chars.as_mut_ptr(), chars.len() as u32) };
    if length == 0 || length as usize >= chars.len() {
        return Err("system_directory_unavailable");
    }
    let directory =
        String::from_utf16(&chars[..length as usize]).map_err(|_| "system_directory_invalid")?;
    Ok(PathBuf::from(directory)
        .join("WindowsPowerShell")
        .join("v1.0")
        .join("powershell.exe"))
}

pub fn collect(limit: usize, include_wmi: bool) -> Result<Capture, &'static str> {
    let powershell = system_powershell()?;
    let wmi = if include_wmi { "$true" } else { "$false" };
    let script = format!(
        "$Max = {limit}\n$EnableWmi = {wmi}\n{}",
        include_str!("collector.ps1")
    );
    let mut child = Command::new(powershell)
        .arg("-NoLogo")
        .arg("-NoProfile")
        .arg("-NonInteractive")
        .arg("-Command")
        .arg(script)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "collector_launch_failed")?;
    let Some(stdout) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return Err("collector_pipe_unavailable");
    };
    let handle = thread::spawn(move || {
        let mut bounded = stdout.take((MAX_CAPTURE_BYTES + 1) as u64);
        let mut data = Vec::new();
        bounded.read_to_end(&mut data).map(|_| data)
    });
    let duration = if include_wmi { 25 } else { 15 };
    let deadline = Instant::now() + Duration::from_secs(duration);
    let mut timed_out = false;
    let exit = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(30)),
            Ok(None) => {
                timed_out = true;
                let _ = child.kill();
                break child.wait().ok();
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };
    let data = handle
        .join()
        .map_err(|_| "collector_reader_failed")?
        .map_err(|_| "collector_reader_failed")?;
    if data.len() > MAX_CAPTURE_BYTES {
        return Err("capture_too_large");
    }
    let failure = if timed_out {
        Some("collector_timeout")
    } else if exit.is_none_or(|s| !s.success()) {
        Some("collector_exit_nonzero")
    } else {
        None
    };
    Ok(Capture {
        bytes: data,
        failure,
    })
}
