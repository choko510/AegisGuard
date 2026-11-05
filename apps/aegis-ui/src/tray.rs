//! Notification-area icon and balloon notifications (P9-04, Windows).
//!
//! The icon lives on its own thread with a message-only window. Its menu
//! offers "Open" and "Quit the GUI". Quitting only ends this GUI process:
//! the AegisGuard service (if installed) keeps monitoring, and the menu says
//! so. Notifications are plain balloons; nothing is clicked or acted on
//! automatically.
use std::sync::mpsc;

/// What the tray asks the app to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayEvent {
    Open,
    Quit,
}

/// Handle to the running tray icon.
pub struct Tray {
    #[cfg(windows)]
    hwnd: usize,
    pub events: mpsc::Receiver<TrayEvent>,
}

#[cfg(windows)]
mod win {
    use super::TrayEvent;
    use std::sync::mpsc;
    use std::sync::{Mutex, OnceLock};
    use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, POINT, WPARAM};
    use windows_sys::Win32::UI::Shell::{
        Shell_NotifyIconW, NIF_ICON, NIF_INFO, NIF_MESSAGE, NIF_TIP, NIIF_INFO, NIIF_WARNING,
        NIM_ADD, NIM_DELETE, NIM_MODIFY, NOTIFYICONDATAW,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        AppendMenuW, CreatePopupMenu, CreateWindowExW, DefWindowProcW, DestroyMenu, DestroyWindow,
        DispatchMessageW, GetCursorPos, GetMessageW, LoadIconW, PostQuitMessage, RegisterClassW,
        SetForegroundWindow, TrackPopupMenu, HWND_MESSAGE, IDI_SHIELD, MF_STRING, MSG,
        TPM_RETURNCMD, WM_APP, WM_CLOSE, WM_LBUTTONDBLCLK, WM_RBUTTONUP, WNDCLASSW,
    };

    const CALLBACK: u32 = WM_APP + 1;
    /// Posted by the app to show the queued balloon.
    pub const SHOW_BALLOON: u32 = WM_APP + 2;
    const CMD_OPEN: usize = 1;
    const CMD_QUIT: usize = 2;

    static SENDER: OnceLock<Mutex<mpsc::Sender<TrayEvent>>> = OnceLock::new();
    pub static BALLOON: Mutex<Option<(String, String, bool)>> = Mutex::new(None);

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn copy(dst: &mut [u16], text: &str) {
        let w: Vec<u16> = text.encode_utf16().take(dst.len() - 1).collect();
        dst[..w.len()].copy_from_slice(&w);
        dst[w.len()] = 0;
    }

    fn data(hwnd: HWND) -> NOTIFYICONDATAW {
        let mut d = NOTIFYICONDATAW {
            cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
            hWnd: hwnd,
            uID: 1,
            ..Default::default()
        };
        copy(&mut d.szTip, "AegisGuard（読み取り専用の監査）");
        d
    }

    fn send(event: TrayEvent) {
        if let Some(s) = SENDER.get() {
            let _ = s.lock().unwrap_or_else(|e| e.into_inner()).send(event);
        }
    }

    unsafe extern "system" fn proc(
        hwnd: HWND,
        msg: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        match msg {
            CALLBACK => {
                let event = (lparam & 0xffff) as u32;
                if event == WM_LBUTTONDBLCLK {
                    send(TrayEvent::Open);
                } else if event == WM_RBUTTONUP {
                    let menu = CreatePopupMenu();
                    let open = wide("AegisGuardを開く");
                    let quit = wide("GUIを終了（常駐サービスの監視は止まりません）");
                    AppendMenuW(menu, MF_STRING, CMD_OPEN, open.as_ptr());
                    AppendMenuW(menu, MF_STRING, CMD_QUIT, quit.as_ptr());
                    let mut pt = POINT { x: 0, y: 0 };
                    GetCursorPos(&mut pt);
                    SetForegroundWindow(hwnd);
                    let cmd =
                        TrackPopupMenu(menu, TPM_RETURNCMD, pt.x, pt.y, 0, hwnd, std::ptr::null())
                            as usize;
                    DestroyMenu(menu);
                    match cmd {
                        CMD_OPEN => send(TrayEvent::Open),
                        CMD_QUIT => send(TrayEvent::Quit),
                        _ => {}
                    }
                }
                0
            }
            SHOW_BALLOON => {
                let queued = BALLOON.lock().unwrap_or_else(|e| e.into_inner()).take();
                if let Some((title, text, warn)) = queued {
                    let mut d = data(hwnd);
                    d.uFlags = NIF_INFO;
                    copy(&mut d.szInfoTitle, &title);
                    copy(&mut d.szInfo, &text);
                    d.dwInfoFlags = if warn { NIIF_WARNING } else { NIIF_INFO };
                    Shell_NotifyIconW(NIM_MODIFY, &d);
                }
                0
            }
            WM_CLOSE => {
                let d = data(hwnd);
                Shell_NotifyIconW(NIM_DELETE, &d);
                DestroyWindow(hwnd);
                PostQuitMessage(0);
                0
            }
            _ => DefWindowProcW(hwnd, msg, wparam, lparam),
        }
    }

    /// Create the icon on a new thread; returns its window handle.
    pub fn start(tx: mpsc::Sender<TrayEvent>) -> Option<usize> {
        let _ = SENDER.set(Mutex::new(tx));
        let (htx, hrx) = mpsc::channel();
        std::thread::spawn(move || unsafe {
            let class = wide("AegisGuardTray");
            let wc = WNDCLASSW {
                lpfnWndProc: Some(proc),
                lpszClassName: class.as_ptr(),
                ..Default::default()
            };
            RegisterClassW(&wc);
            let hwnd = CreateWindowExW(
                0,
                class.as_ptr(),
                class.as_ptr(),
                0,
                0,
                0,
                0,
                0,
                HWND_MESSAGE,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null(),
            );
            if hwnd.is_null() {
                let _ = htx.send(None);
                return;
            }
            let mut d = data(hwnd);
            d.uFlags = NIF_ICON | NIF_TIP | NIF_MESSAGE;
            d.uCallbackMessage = CALLBACK;
            d.hIcon = LoadIconW(std::ptr::null_mut(), IDI_SHIELD);
            if Shell_NotifyIconW(NIM_ADD, &d) == 0 {
                DestroyWindow(hwnd);
                let _ = htx.send(None);
                return;
            }
            let _ = htx.send(Some(hwnd as usize));
            let mut msg: MSG = std::mem::zeroed();
            while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
                DispatchMessageW(&msg);
            }
        });
        hrx.recv().ok().flatten()
    }
}

impl Tray {
    /// Start the tray icon (Windows). `None` when it could not be created.
    #[cfg(windows)]
    pub fn start() -> Option<Self> {
        let (tx, rx) = mpsc::channel();
        win::start(tx).map(|hwnd| Self { hwnd, events: rx })
    }

    #[cfg(not(windows))]
    pub fn start() -> Option<Self> {
        None
    }

    /// Show a balloon notification.
    pub fn notify(&self, title: &str, text: &str, warning: bool) {
        #[cfg(windows)]
        {
            *win::BALLOON.lock().unwrap_or_else(|e| e.into_inner()) =
                Some((title.to_string(), text.to_string(), warning));
            // SAFETY: posting to our own message-only window.
            unsafe {
                windows_sys::Win32::UI::WindowsAndMessaging::PostMessageW(
                    self.hwnd as _,
                    win::SHOW_BALLOON,
                    0,
                    0,
                );
            }
        }
        #[cfg(not(windows))]
        let _ = (title, text, warning);
    }
}

impl Drop for Tray {
    fn drop(&mut self) {
        #[cfg(windows)]
        // SAFETY: closing our own window removes the icon and ends its thread.
        unsafe {
            windows_sys::Win32::UI::WindowsAndMessaging::PostMessageW(
                self.hwnd as _,
                windows_sys::Win32::UI::WindowsAndMessaging::WM_CLOSE,
                0,
                0,
            );
        }
    }
}
