//! Authenticated, read-only Named Pipe IPC between the service and the GUI
//! (P8-03).
//!
//! Frames are a little-endian u32 length followed by UTF-8 JSON. Requests
//! are capped at 64 KiB, responses at 8 MiB; every read and write has a
//! timeout. All methods are read-only: there is no method that runs a
//! command, changes a setting or scans a client-supplied path.
//!
//! Authorization: any interactive user may ask for `hello` and `status`.
//! `findings` (which can name other users' processes) is answered only for
//! administrators (elevated), the user the server runs as (console mode),
//! or clients in the active console session; other sessions are refused.
use super::{Layout, ServiceState};
use crate::model;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const PROTOCOL_VERSION: u32 = 1;
pub const PIPE_NAME: &str = r"\\.\pipe\AegisGuard.v1";
pub const MAX_REQUEST_BYTES: usize = 64 * 1024;
pub const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_FINDINGS_PAGE: usize = 500;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Request {
    pub v: u32,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Response {
    pub v: u32,
    pub ok: bool,
    #[serde(default)]
    pub result: Value,
    #[serde(default)]
    pub error: Option<String>,
}

impl Response {
    fn ok(result: Value) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            ok: true,
            result,
            error: None,
        }
    }
    fn err(message: impl Into<String>) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            ok: false,
            result: Value::Null,
            error: Some(message.into()),
        }
    }
}

/// Who is asking, as established by the server from the pipe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ClientInfo {
    pub pid: u32,
    pub session: u32,
    /// Member of Administrators with an elevated token.
    pub elevated_admin: bool,
    /// Same user account as the server process (console mode).
    pub same_user: bool,
    /// Session of the physical console at the time of the request.
    pub console_session: Option<u32>,
}

impl ClientInfo {
    pub fn may_read_findings(&self) -> bool {
        self.elevated_admin || self.same_user || self.console_session == Some(self.session)
    }
}

/// Encode one frame.
pub fn encode(value: &impl Serialize, max: usize) -> crate::Result<Vec<u8>> {
    let body = serde_json::to_vec(value)?;
    if body.len() > max {
        return Err(format!("message of {} bytes exceeds {max}", body.len()).into());
    }
    let mut out = (body.len() as u32).to_le_bytes().to_vec();
    out.extend(body);
    Ok(out)
}

/// Length of a frame body from its 4-byte header, refusing oversize frames
/// before any allocation.
pub fn frame_len(header: [u8; 4], max: usize) -> crate::Result<usize> {
    let len = u32::from_le_bytes(header) as usize;
    if len == 0 || len > max {
        return Err(format!("frame length {len} outside 1..={max}").into());
    }
    Ok(len)
}

/// Answer one request. Pure apart from reading the data directory.
pub fn handle(body: &[u8], client: &ClientInfo, layout: &Layout) -> Response {
    let request: Request = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(e) => return Response::err(format!("malformed request: {e}")),
    };
    if request.v != PROTOCOL_VERSION {
        return Response::err(format!(
            "unsupported protocol version {} (supported: {PROTOCOL_VERSION})",
            request.v
        ));
    }
    match request.method.as_str() {
        "hello" => Response::ok(serde_json::json!({
            "protocol_versions": [PROTOCOL_VERSION],
            "server_version": env!("CARGO_PKG_VERSION"),
            "read_only": true,
            "client": client,
            "may_read_findings": client.may_read_findings(),
        })),
        "status" => match ServiceState::load(&layout.state()) {
            Ok(Some(state)) => {
                let stale = state.is_stale(model::now_unix_ms());
                Response::ok(serde_json::json!({"state": state, "stale": stale}))
            }
            Ok(None) => Response::err("no service state has been written yet"),
            Err(e) => Response::err(format!("service state unreadable: {e}")),
        },
        "findings" => {
            if !client.may_read_findings() {
                return Response::err(
                    "findings are only available to administrators or the active console session",
                );
            }
            let offset = request.params["offset"].as_u64().unwrap_or(0) as usize;
            let limit = (request.params["limit"].as_u64().unwrap_or(100) as usize)
                .clamp(1, MAX_FINDINGS_PAGE);
            match super::findings::load(layout) {
                Ok(Some(doc)) => {
                    let total = doc.findings.len();
                    let page: Vec<_> = doc.findings.iter().skip(offset).take(limit).collect();
                    Response::ok(serde_json::json!({
                        "available": true,
                        "total": total,
                        "offset": offset,
                        "findings": page,
                        "rules": doc.rules,
                        "updated_at_unix_ms": doc.updated_at_unix_ms,
                        "window": doc.window,
                    }))
                }
                Ok(None) => Response::ok(
                    serde_json::json!({"available": false, "total": 0, "findings": []}),
                ),
                Err(e) => Response::err(format!("findings unreadable: {e}")),
            }
        }
        other => Response::err(format!(
            "unknown method {other} (methods: hello, status, findings)"
        )),
    }
}

#[cfg(windows)]
pub use win::{request, serve, ServerIdentity};

#[cfg(windows)]
mod win {
    use super::{
        encode, frame_len, handle, ClientInfo, Request, Response, MAX_REQUEST_BYTES,
        MAX_RESPONSE_BYTES, PROTOCOL_VERSION,
    };
    use crate::service::Layout;
    use crate::Result;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, LocalFree, ERROR_IO_PENDING, ERROR_PIPE_BUSY,
        ERROR_PIPE_CONNECTED, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
        WAIT_OBJECT_0,
    };
    use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
    use windows_sys::Win32::Security::{
        CheckTokenMembership, CreateWellKnownSid, EqualSid, GetTokenInformation, RevertToSelf,
        TokenElevation, TokenUser, WinBuiltinAdministratorsSid, PSECURITY_DESCRIPTOR,
        SECURITY_ATTRIBUTES, TOKEN_ELEVATION, TOKEN_QUERY, TOKEN_USER,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, ReadFile, WriteFile, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED,
        OPEN_EXISTING, PIPE_ACCESS_DUPLEX, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
    };
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
        GetNamedPipeClientSessionId, GetNamedPipeServerSessionId, ImpersonateNamedPipeClient,
        WaitNamedPipeW, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
    };
    use windows_sys::Win32::System::RemoteDesktop::{
        ProcessIdToSessionId, WTSGetActiveConsoleSessionId,
    };
    use windows_sys::Win32::System::Threading::{
        CreateEventW, GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken,
        WaitForSingleObject,
    };
    use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};

    const IO_TIMEOUT: Duration = Duration::from_secs(5);
    const MAX_ACTIVE: usize = 4;
    /// SYSTEM and Administrators: full; Interactive users: read + write data
    /// only (no FILE_CREATE_PIPE_INSTANCE, so they cannot host extra
    /// instances of this pipe and intercept other clients).
    const SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)(A;;0x12008b;;;IU)";

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn os_err(what: &str) -> crate::Error {
        format!("{what}: {}", std::io::Error::last_os_error()).into()
    }

    struct Owned(HANDLE);
    impl Drop for Owned {
        fn drop(&mut self) {
            if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
                // SAFETY: owned handle.
                unsafe {
                    CloseHandle(self.0);
                }
            }
        }
    }

    /// One overlapped read or write with a timeout; cancels on timeout.
    fn io(
        handle: HANDLE,
        buf: *mut u8,
        len: usize,
        write: bool,
        timeout: Duration,
    ) -> Result<usize> {
        // SAFETY: event and overlapped live until the operation finished or
        // was cancelled and waited for.
        unsafe {
            let event = Owned(CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()));
            if event.0.is_null() {
                return Err(os_err("CreateEventW"));
            }
            let mut ov: OVERLAPPED = std::mem::zeroed();
            ov.hEvent = event.0;
            let mut done: u32 = 0;
            let ok = if write {
                WriteFile(handle, buf, len as u32, &mut done, &mut ov)
            } else {
                ReadFile(handle, buf, len as u32, &mut done, &mut ov)
            };
            if ok == 0 && GetLastError() != ERROR_IO_PENDING {
                return Err(os_err(if write { "WriteFile" } else { "ReadFile" }));
            }
            if WaitForSingleObject(event.0, timeout.as_millis() as u32) != WAIT_OBJECT_0 {
                CancelIoEx(handle, &ov);
                GetOverlappedResult(handle, &ov, &mut done, 1);
                return Err("pipe I/O timed out".into());
            }
            if GetOverlappedResult(handle, &ov, &mut done, 0) == 0 {
                return Err(os_err("GetOverlappedResult"));
            }
            Ok(done as usize)
        }
    }

    fn read_exact(handle: HANDLE, buf: &mut [u8], timeout: Duration) -> Result<()> {
        let mut at = 0;
        while at < buf.len() {
            let n = io(
                handle,
                buf[at..].as_mut_ptr(),
                buf.len() - at,
                false,
                timeout,
            )?;
            if n == 0 {
                return Err("pipe closed".into());
            }
            at += n;
        }
        Ok(())
    }

    fn write_all(handle: HANDLE, buf: &[u8], timeout: Duration) -> Result<()> {
        let mut at = 0;
        while at < buf.len() {
            let n = io(
                handle,
                buf[at..].as_ptr() as *mut u8,
                buf.len() - at,
                true,
                timeout,
            )?;
            if n == 0 {
                return Err("pipe closed".into());
            }
            at += n;
        }
        Ok(())
    }

    fn read_frame(handle: HANDLE, max: usize) -> Result<Vec<u8>> {
        let mut header = [0u8; 4];
        read_exact(handle, &mut header, IO_TIMEOUT)?;
        let len = frame_len(header, max)?;
        let mut body = vec![0u8; len];
        read_exact(handle, &mut body, IO_TIMEOUT)?;
        Ok(body)
    }

    /// User SID bytes of a token.
    unsafe fn token_user(token: HANDLE) -> Option<Vec<u8>> {
        let mut len = 0u32;
        GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut len);
        if len == 0 || len > 4096 {
            return None;
        }
        let mut buf = vec![0u8; len as usize];
        if GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), len, &mut len) == 0 {
            return None;
        }
        let user = &*(buf.as_ptr() as *const TOKEN_USER);
        let sid = user.User.Sid;
        let sid_len = windows_sys::Win32::Security::GetLengthSid(sid) as usize;
        Some(std::slice::from_raw_parts(sid as *const u8, sid_len).to_vec())
    }

    unsafe fn process_user() -> Option<Vec<u8>> {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return None;
        }
        let token = Owned(token);
        token_user(token.0)
    }

    /// Identify the client via the pipe (identification-level impersonation).
    fn client_info(pipe: HANDLE, server_user: &Option<Vec<u8>>) -> ClientInfo {
        // SAFETY: the pipe handle is connected; impersonation is reverted
        // before returning; all buffers are sized by the APIs.
        unsafe {
            let mut pid = 0u32;
            GetNamedPipeClientProcessId(pipe, &mut pid);
            let mut session = u32::MAX;
            GetNamedPipeClientSessionId(pipe, &mut session);
            let console = WTSGetActiveConsoleSessionId();
            let mut info = ClientInfo {
                pid,
                session,
                elevated_admin: false,
                same_user: false,
                console_session: (console != u32::MAX).then_some(console),
            };
            if ImpersonateNamedPipeClient(pipe) == 0 {
                return info;
            }
            let mut token: HANDLE = std::ptr::null_mut();
            let opened = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) != 0;
            RevertToSelf();
            if !opened {
                return info;
            }
            let token = Owned(token);
            let mut sid = [0u8; 68];
            let mut sid_len = sid.len() as u32;
            if CreateWellKnownSid(
                WinBuiltinAdministratorsSid,
                std::ptr::null_mut(),
                sid.as_mut_ptr().cast(),
                &mut sid_len,
            ) != 0
            {
                let mut member = 0;
                if CheckTokenMembership(token.0, sid.as_ptr() as *mut _, &mut member) != 0
                    && member != 0
                {
                    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
                    let mut len = 0u32;
                    if GetTokenInformation(
                        token.0,
                        TokenElevation,
                        (&mut elevation as *mut TOKEN_ELEVATION).cast(),
                        std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                        &mut len,
                    ) != 0
                    {
                        info.elevated_admin = elevation.TokenIsElevated != 0;
                    }
                }
            }
            if let (Some(server), Some(client)) = (server_user, token_user(token.0)) {
                info.same_user =
                    EqualSid(server.as_ptr() as *mut _, client.as_ptr() as *mut _) != 0;
            }
            info
        }
    }

    fn create_instance(name: &[u16], first: bool, sa: &SECURITY_ATTRIBUTES) -> Result<Owned> {
        let mut mode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED;
        if first {
            mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
        }
        // SAFETY: name is NUL-terminated; sa outlives the call.
        let h = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                mode,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                MAX_ACTIVE as u32,
                64 * 1024,
                64 * 1024,
                0,
                sa,
            )
        };
        if h == INVALID_HANDLE_VALUE {
            return Err(os_err(if first {
                "CreateNamedPipeW (is another process already using the AegisGuard pipe name?)"
            } else {
                "CreateNamedPipeW"
            }));
        }
        Ok(Owned(h))
    }

    /// Wait up to `timeout` for a client; Ok(false) on timeout.
    fn wait_connect(pipe: HANDLE, timeout: Duration) -> Result<bool> {
        // SAFETY: event/overlapped outlive the operation (cancelled on timeout).
        unsafe {
            let event = Owned(CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()));
            let mut ov: OVERLAPPED = std::mem::zeroed();
            ov.hEvent = event.0;
            if ConnectNamedPipe(pipe, &mut ov) == 0 {
                match GetLastError() {
                    ERROR_PIPE_CONNECTED => return Ok(true),
                    ERROR_IO_PENDING => {}
                    _ => return Err(os_err("ConnectNamedPipe")),
                }
            } else {
                return Ok(true);
            }
            if WaitForSingleObject(event.0, timeout.as_millis() as u32) == WAIT_OBJECT_0 {
                let mut n = 0;
                return Ok(GetOverlappedResult(pipe, &ov, &mut n, 0) != 0);
            }
            CancelIoEx(pipe, &ov);
            let mut n = 0;
            GetOverlappedResult(pipe, &ov, &mut n, 1);
            Ok(false)
        }
    }

    /// Serve requests until `stop` is set. Fails if the pipe name is
    /// already taken (squatting), instead of serving next to an impostor.
    pub fn serve(layout: Layout, pipe_name: &str, stop: Arc<AtomicBool>) -> Result<()> {
        let name = wide(pipe_name);
        let sddl = wide(SDDL);
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: SDDL is NUL-terminated; sd is freed with LocalFree below.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut sd,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(os_err(
                "ConvertStringSecurityDescriptorToSecurityDescriptorW",
            ));
        }
        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd,
            bInheritHandle: 0,
        };
        let server_user = unsafe { process_user() };
        let layout = Arc::new(layout);
        let active = Arc::new(AtomicUsize::new(0));
        let result = (|| -> Result<()> {
            // The first instance is created before anything else so a name
            // already taken by another process fails immediately; an idle
            // instance is kept (not closed) so the name is never released.
            let mut idle = Some(create_instance(&name, true, &sa)?);
            while !stop.load(Ordering::SeqCst) {
                let pipe = match idle.take() {
                    Some(p) => p,
                    None => create_instance(&name, false, &sa)?,
                };
                if !wait_connect(pipe.0, Duration::from_millis(500))? {
                    idle = Some(pipe);
                    continue;
                }
                if active.load(Ordering::SeqCst) >= MAX_ACTIVE {
                    let _ = write_all(
                        pipe.0,
                        &encode(&Response::err("server busy"), MAX_RESPONSE_BYTES)?,
                        IO_TIMEOUT,
                    );
                    unsafe { DisconnectNamedPipe(pipe.0) };
                    continue;
                }
                active.fetch_add(1, Ordering::SeqCst);
                let info = client_info(pipe.0, &server_user);
                let layout = layout.clone();
                let active = active.clone();
                let raw = pipe.0 as usize;
                std::mem::forget(pipe);
                std::thread::spawn(move || {
                    let pipe = Owned(raw as HANDLE);
                    let response = match read_frame(pipe.0, MAX_REQUEST_BYTES) {
                        Ok(body) => handle(&body, &info, &layout),
                        Err(e) => Response::err(format!("bad request frame: {e}")),
                    };
                    if let Ok(bytes) = encode(&response, MAX_RESPONSE_BYTES).or_else(|_| {
                        encode(&Response::err("response too large"), MAX_RESPONSE_BYTES)
                    }) {
                        if write_all(pipe.0, &bytes, IO_TIMEOUT).is_ok() {
                            // DisconnectNamedPipe discards unread data, so
                            // wait (bounded) for the client to close first.
                            let mut probe = [0u8; 1];
                            let _ = io(pipe.0, probe.as_mut_ptr(), 1, false, IO_TIMEOUT);
                        }
                    }
                    // SAFETY: owned, connected pipe.
                    unsafe { DisconnectNamedPipe(pipe.0) };
                    active.fetch_sub(1, Ordering::SeqCst);
                });
            }
            Ok(())
        })();
        // SAFETY: allocated by ConvertStringSecurityDescriptor...
        unsafe { LocalFree(sd as _) };
        result
    }

    /// Who answered the pipe, as seen by the client.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
    #[serde(rename_all = "snake_case")]
    pub enum ServerIdentity {
        /// A Session 0 process: a Windows service.
        Service,
        /// Same session as the client (console mode).
        ConsoleSameSession,
    }

    /// Send one request. The server must be a service (session 0) or run in
    /// the caller's own session; anything else is refused, so a process that
    /// squats the pipe name in another session cannot feed the GUI.
    pub fn request(
        pipe_name: &str,
        method: &str,
        params: serde_json::Value,
        timeout: Duration,
    ) -> Result<(Response, ServerIdentity)> {
        let name = wide(pipe_name);
        let deadline = std::time::Instant::now() + timeout;
        let pipe = loop {
            // SAFETY: NUL-terminated name; identification-level SQOS.
            let h = unsafe {
                CreateFileW(
                    name.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    std::ptr::null(),
                    OPEN_EXISTING,
                    FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                    std::ptr::null_mut(),
                )
            };
            if h != INVALID_HANDLE_VALUE {
                break Owned(h);
            }
            let busy = unsafe { GetLastError() } == ERROR_PIPE_BUSY;
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if !busy || left.is_zero() {
                return Err(os_err("connect to the AegisGuard service"));
            }
            unsafe { WaitNamedPipeW(name.as_ptr(), left.as_millis().min(1000) as u32) };
        };
        let identity = unsafe {
            let mut server_session = u32::MAX;
            GetNamedPipeServerSessionId(pipe.0, &mut server_session);
            let mut own = u32::MAX;
            ProcessIdToSessionId(std::process::id(), &mut own);
            if server_session == 0 {
                ServerIdentity::Service
            } else if server_session == own && own != u32::MAX {
                ServerIdentity::ConsoleSameSession
            } else {
                return Err(format!("pipe server in session {server_session} is neither a service nor in this session; refusing it").into());
            }
        };
        let request = Request {
            v: PROTOCOL_VERSION,
            method: method.to_string(),
            params,
        };
        write_all(pipe.0, &encode(&request, MAX_REQUEST_BYTES)?, timeout)?;
        let body = read_frame(pipe.0, MAX_RESPONSE_BYTES)?;
        let response: Response = serde_json::from_slice(&body)?;
        Ok((response, identity))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::{RunMode, ServiceConfig};

    fn layout(name: &str) -> Layout {
        let d = std::env::temp_dir().join(format!("aegis-ipc-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        Layout::new(d)
    }

    fn client(session: u32, console: Option<u32>, admin: bool, same: bool) -> ClientInfo {
        ClientInfo {
            pid: 1,
            session,
            elevated_admin: admin,
            same_user: same,
            console_session: console,
        }
    }

    fn call(method: &str, c: &ClientInfo, l: &Layout) -> Response {
        let body = serde_json::to_vec(&Request {
            v: 1,
            method: method.into(),
            params: serde_json::json!({}),
        })
        .unwrap();
        handle(&body, c, l)
    }

    #[test]
    fn malformed_unknown_and_wrong_version_requests_are_rejected() {
        let l = layout("bad");
        let c = client(1, Some(1), false, false);
        assert!(!handle(b"{not json", &c, &l).ok);
        assert!(!handle(br#"{"v":2,"method":"hello"}"#, &c, &l).ok);
        let r = call("run_command", &c, &l);
        assert!(!r.ok && r.error.unwrap().contains("unknown method"));
    }

    #[test]
    fn status_reports_missing_and_present_state() {
        let l = layout("status");
        let c = client(1, Some(1), false, false);
        assert!(!call("status", &c, &l).ok);
        let state = ServiceState::new(RunMode::Service, ServiceConfig::default(), None);
        state.save(&l.state()).unwrap();
        let r = call("status", &c, &l);
        assert!(r.ok);
        assert_eq!(r.result["stale"], true);
    }

    #[test]
    fn findings_are_refused_across_sessions() {
        let l = layout("authz");
        assert!(client(2, Some(2), false, false).may_read_findings());
        assert!(client(3, Some(2), true, false).may_read_findings());
        assert!(client(3, Some(2), false, true).may_read_findings());
        let other = client(3, Some(2), false, false);
        assert!(!other.may_read_findings());
        let r = call("findings", &other, &l);
        assert!(!r.ok);
        let r = call("findings", &client(2, Some(2), false, false), &l);
        assert!(r.ok);
        assert_eq!(r.result["available"], false);
    }

    #[test]
    fn frames_are_bounded_before_allocation() {
        assert!(frame_len(0u32.to_le_bytes(), 10).is_err());
        assert!(frame_len(11u32.to_le_bytes(), 10).is_err());
        assert!(frame_len(u32::MAX.to_le_bytes(), MAX_REQUEST_BYTES).is_err());
        assert_eq!(frame_len(10u32.to_le_bytes(), 10).unwrap(), 10);
        let big = "x".repeat(MAX_REQUEST_BYTES);
        assert!(encode(&big, MAX_REQUEST_BYTES).is_err());
    }

    /// Real named pipe round trip in this session (console mode).
    #[cfg(windows)]
    #[test]
    fn pipe_round_trip_squatting_and_hostile_clients() {
        use std::io::Write;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        use std::time::Duration;
        let l = layout("pipe");
        ServiceState::new(RunMode::Console, ServiceConfig::default(), None)
            .save(&l.state())
            .unwrap();
        let name = format!(r"\\.\pipe\AegisGuard.test.{}", std::process::id());
        let stop = Arc::new(AtomicBool::new(false));
        let (n2, s2, d2) = (name.clone(), stop.clone(), l.data_dir.clone());
        let server = std::thread::spawn(move || serve(Layout::new(d2), &n2, s2));
        std::thread::sleep(Duration::from_millis(300));

        let (hello, identity) = request(
            &name,
            "hello",
            serde_json::json!({}),
            Duration::from_secs(5),
        )
        .unwrap();
        assert!(hello.ok);
        assert_eq!(identity, ServerIdentity::ConsoleSameSession);
        assert_eq!(hello.result["client"]["same_user"], true);
        let (status, _) = request(
            &name,
            "status",
            serde_json::json!({}),
            Duration::from_secs(5),
        )
        .unwrap();
        assert!(status.ok, "{status:?}");

        // A second server on the same name must fail (anti-squatting).
        let second = serve(
            Layout::new(l.data_dir.clone()),
            &name,
            Arc::new(AtomicBool::new(true)),
        );
        assert!(second.is_err());

        // Hostile clients: oversized frame header, garbage, silence.
        for payload in [
            u32::MAX.to_le_bytes().to_vec(),
            b"\x05\x00\x00\x00{oops".to_vec(),
            Vec::new(),
        ] {
            // Like a real client, retry while every instance is busy.
            let mut f = (0..100)
                .find_map(|_| {
                    match std::fs::OpenOptions::new()
                        .read(true)
                        .write(true)
                        .open(&name)
                    {
                        Ok(f) => Some(f),
                        Err(_) => {
                            std::thread::sleep(Duration::from_millis(50));
                            None
                        }
                    }
                })
                .expect("pipe never became available");
            let _ = f.write_all(&payload);
            drop(f);
        }
        // The server still answers afterwards.
        let (again, _) = request(
            &name,
            "hello",
            serde_json::json!({}),
            Duration::from_secs(10),
        )
        .unwrap();
        assert!(again.ok);

        stop.store(true, Ordering::SeqCst);
        server.join().unwrap().unwrap();
    }
}
