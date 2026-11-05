//! Service Control Manager integration (Windows): dispatcher, control
//! handler, status reporting, and install/uninstall of the service entry.
//!
//! Install creates the service as `NT AUTHORITY\LocalService` (no admin
//! rights), with an unrestricted service SID, only SeChangeNotifyPrivilege,
//! demand start unless asked otherwise, and restart-on-failure. Reading the
//! Sysmon channel needs LocalSystem or the Event Log Readers group; without
//! it the state shows `access_denied` instead of an empty, "quiet" log.
use super::{run, Layout, RunMode, TickWork, DISPLAY_NAME, SERVICE_NAME};
use crate::Result;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use windows_sys::Win32::System::Services::{
    ChangeServiceConfig2W, CloseServiceHandle, ControlService, CreateServiceW, DeleteService,
    OpenSCManagerW, OpenServiceW, QueryServiceStatus, RegisterServiceCtrlHandlerExW,
    SetServiceStatus, StartServiceCtrlDispatcherW, SC_ACTION, SC_ACTION_NONE, SC_ACTION_RESTART,
    SC_MANAGER_CONNECT, SC_MANAGER_CREATE_SERVICE, SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP,
    SERVICE_ALL_ACCESS, SERVICE_AUTO_START, SERVICE_CONFIG_DESCRIPTION,
    SERVICE_CONFIG_FAILURE_ACTIONS, SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO,
    SERVICE_CONFIG_SERVICE_SID_INFO, SERVICE_CONTROL_INTERROGATE, SERVICE_CONTROL_SHUTDOWN,
    SERVICE_CONTROL_STOP, SERVICE_DEMAND_START, SERVICE_DESCRIPTIONW, SERVICE_ERROR_NORMAL,
    SERVICE_FAILURE_ACTIONSW, SERVICE_QUERY_STATUS, SERVICE_REQUIRED_PRIVILEGES_INFOW,
    SERVICE_RUNNING, SERVICE_SID_INFO, SERVICE_SID_TYPE_UNRESTRICTED, SERVICE_START_PENDING,
    SERVICE_STATUS, SERVICE_STATUS_HANDLE, SERVICE_STOPPED, SERVICE_STOP_PENDING,
    SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS,
};

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn last_error(what: &str) -> crate::Error {
    format!("{what}: {}", std::io::Error::last_os_error()).into()
}

/// What the service main needs; set before the dispatcher starts.
struct Context {
    layout: Layout,
    make_work: fn() -> Box<dyn TickWork + Send>,
}

static CONTEXT: OnceLock<Context> = OnceLock::new();
static STOP: AtomicBool = AtomicBool::new(false);
static STATUS_HANDLE: Mutex<usize> = Mutex::new(0);
static OUTCOME: Mutex<Option<String>> = Mutex::new(None);

fn report(state: u32, exit_code: u32, wait_hint_ms: u32) {
    let handle = *STATUS_HANDLE.lock().unwrap_or_else(|e| e.into_inner()) as SERVICE_STATUS_HANDLE;
    if handle.is_null() {
        return;
    }
    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: if state == SERVICE_RUNNING {
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
        } else {
            0
        },
        dwWin32ExitCode: exit_code,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: 0,
        dwWaitHint: wait_hint_ms,
    };
    // SAFETY: handle came from RegisterServiceCtrlHandlerExW; status is valid.
    unsafe {
        SetServiceStatus(handle, &status);
    }
}

unsafe extern "system" fn control_handler(
    control: u32,
    _event_type: u32,
    _event_data: *mut core::ffi::c_void,
    _context: *mut core::ffi::c_void,
) -> u32 {
    match control {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            STOP.store(true, Ordering::SeqCst);
            report(SERVICE_STOP_PENDING, 0, 10_000);
            0
        }
        SERVICE_CONTROL_INTERROGATE => 0,
        // ERROR_CALL_NOT_IMPLEMENTED
        _ => 120,
    }
}

unsafe extern "system" fn service_main(_argc: u32, _argv: *mut windows_sys::core::PWSTR) {
    let name = wide(SERVICE_NAME);
    let handle =
        RegisterServiceCtrlHandlerExW(name.as_ptr(), Some(control_handler), std::ptr::null());
    if handle.is_null() {
        return;
    }
    *STATUS_HANDLE.lock().unwrap_or_else(|e| e.into_inner()) = handle as usize;
    report(SERVICE_START_PENDING, 0, 10_000);
    let Some(ctx) = CONTEXT.get() else {
        report(SERVICE_STOPPED, 1, 0);
        return;
    };
    let stop = std::sync::Arc::new(AtomicBool::new(false));
    let ipc_error = super::start_ipc(&ctx.layout, stop.clone());
    let mut work = super::WithIpc {
        inner: (ctx.make_work)(),
        ipc_error,
    };
    // Mirror the SCM stop flag into the IPC stop flag.
    let mirror = stop.clone();
    std::thread::spawn(move || {
        while !STOP.load(Ordering::SeqCst) {
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        mirror.store(true, Ordering::SeqCst);
    });
    let result = run(&ctx.layout, RunMode::Service, &STOP, &mut work, &mut || {
        report(SERVICE_RUNNING, 0, 0);
    });
    let exit = match result {
        Ok(_) => 0,
        Err(e) => {
            *OUTCOME.lock().unwrap_or_else(|e| e.into_inner()) = Some(e.to_string());
            // ERROR_SERVICE_SPECIFIC_ERROR so the SCM failure actions apply.
            1066
        }
    };
    report(SERVICE_STOPPED, exit, 0);
}

/// Called when the SCM started this process. Blocks until the service stops.
pub fn dispatch(layout: Layout, make_work: fn() -> Box<dyn TickWork + Send>) -> Result<()> {
    if CONTEXT.set(Context { layout, make_work }).is_err() {
        return Err("service already dispatched".into());
    }
    let mut name = wide(SERVICE_NAME);
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: name.as_mut_ptr(),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: std::ptr::null_mut(),
            lpServiceProc: None,
        },
    ];
    // SAFETY: the table is NUL-terminated and outlives the call.
    if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } == 0 {
        return Err(last_error(
            "StartServiceCtrlDispatcherW (use `service console` to run outside the SCM)",
        ));
    }
    match OUTCOME.lock().unwrap_or_else(|e| e.into_inner()).take() {
        Some(e) => Err(e.into()),
        None => Ok(()),
    }
}

struct Handle(windows_sys::Win32::System::Services::SC_HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: handle owned by this guard.
            unsafe {
                CloseServiceHandle(self.0);
            }
        }
    }
}

fn manager(access: u32) -> Result<Handle> {
    // SAFETY: null machine/database = local SCM.
    let h = unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), access) };
    if h.is_null() {
        return Err(last_error(
            "OpenSCManagerW (administrator rights are required to install)",
        ));
    }
    Ok(Handle(h))
}

/// Create the service entry (administrator rights required).
pub fn install(exe: &std::path::Path, data_dir: &std::path::Path, auto_start: bool) -> Result<()> {
    let scm = manager(SC_MANAGER_CREATE_SERVICE)?;
    let name = wide(SERVICE_NAME);
    let display = wide(DISPLAY_NAME);
    let command = wide(&format!(
        "\"{}\" service run --data-dir \"{}\"",
        exe.display(),
        data_dir.display()
    ));
    let account = wide("NT AUTHORITY\\LocalService");
    // SAFETY: all strings are NUL-terminated and outlive the call.
    let svc = unsafe {
        CreateServiceW(
            scm.0,
            name.as_ptr(),
            display.as_ptr(),
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            if auto_start {
                SERVICE_AUTO_START
            } else {
                SERVICE_DEMAND_START
            },
            SERVICE_ERROR_NORMAL,
            command.as_ptr(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null(),
            account.as_ptr(),
            std::ptr::null(),
        )
    };
    if svc.is_null() {
        return Err(last_error("CreateServiceW"));
    }
    let svc = Handle(svc);
    let mut desc_text = wide("Read-only Windows event collection and correlation. Never changes Defender, Firewall or other OS settings.");
    let desc = SERVICE_DESCRIPTIONW {
        lpDescription: desc_text.as_mut_ptr(),
    };
    // Only SeChangeNotifyPrivilege (double-NUL-terminated list).
    let mut privileges: Vec<u16> = "SeChangeNotifyPrivilege"
        .encode_utf16()
        .chain([0, 0])
        .collect();
    let privs = SERVICE_REQUIRED_PRIVILEGES_INFOW {
        pmszRequiredPrivileges: privileges.as_mut_ptr(),
    };
    let sid = SERVICE_SID_INFO {
        dwServiceSidType: SERVICE_SID_TYPE_UNRESTRICTED,
    };
    let mut actions = [
        SC_ACTION {
            Type: SC_ACTION_RESTART,
            Delay: 60_000,
        },
        SC_ACTION {
            Type: SC_ACTION_RESTART,
            Delay: 300_000,
        },
        SC_ACTION {
            Type: SC_ACTION_NONE,
            Delay: 0,
        },
    ];
    let failure = SERVICE_FAILURE_ACTIONSW {
        dwResetPeriod: 24 * 3600,
        lpRebootMsg: std::ptr::null_mut(),
        lpCommand: std::ptr::null_mut(),
        cActions: actions.len() as u32,
        lpsaActions: actions.as_mut_ptr(),
    };
    // SAFETY: each info struct matches its level and outlives the call.
    unsafe {
        ChangeServiceConfig2W(
            svc.0,
            SERVICE_CONFIG_DESCRIPTION,
            (&desc as *const SERVICE_DESCRIPTIONW).cast(),
        );
        ChangeServiceConfig2W(
            svc.0,
            SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO,
            (&privs as *const SERVICE_REQUIRED_PRIVILEGES_INFOW).cast(),
        );
        ChangeServiceConfig2W(
            svc.0,
            SERVICE_CONFIG_SERVICE_SID_INFO,
            (&sid as *const SERVICE_SID_INFO).cast(),
        );
        ChangeServiceConfig2W(
            svc.0,
            SERVICE_CONFIG_FAILURE_ACTIONS,
            (&failure as *const SERVICE_FAILURE_ACTIONSW).cast(),
        );
    }
    Ok(())
}

/// Stop (if running) and delete the service entry. Data is left in place.
pub fn uninstall() -> Result<()> {
    let scm = manager(SC_MANAGER_CONNECT)?;
    let name = wide(SERVICE_NAME);
    // SAFETY: valid SCM handle and name.
    let svc = unsafe { OpenServiceW(scm.0, name.as_ptr(), SERVICE_ALL_ACCESS) };
    if svc.is_null() {
        return Err(last_error("OpenServiceW"));
    }
    let svc = Handle(svc);
    let mut status = SERVICE_STATUS::default();
    // SAFETY: valid handle; failure (not running) is fine.
    unsafe {
        ControlService(svc.0, SERVICE_CONTROL_STOP, &mut status);
        if DeleteService(svc.0) == 0 {
            return Err(last_error("DeleteService"));
        }
    }
    Ok(())
}

/// Current SCM state of the service, without admin rights.
pub fn query() -> Result<&'static str> {
    let scm = manager(SC_MANAGER_CONNECT)?;
    let name = wide(SERVICE_NAME);
    // SAFETY: valid SCM handle and name.
    let svc = unsafe { OpenServiceW(scm.0, name.as_ptr(), SERVICE_QUERY_STATUS) };
    if svc.is_null() {
        return Ok("not_installed");
    }
    let svc = Handle(svc);
    let mut status = SERVICE_STATUS::default();
    // SAFETY: valid handle.
    if unsafe { QueryServiceStatus(svc.0, &mut status) } == 0 {
        return Err(last_error("QueryServiceStatus"));
    }
    Ok(match status.dwCurrentState {
        SERVICE_RUNNING => "running",
        SERVICE_STOPPED => "stopped",
        SERVICE_START_PENDING => "start_pending",
        SERVICE_STOP_PENDING => "stop_pending",
        _ => "other",
    })
}
