//! Windows paste engine: put text on the clipboard (optionally hidden from
//! Win+V history and cloud sync), re-activate the window that was focused
//! before the palette opened, and send Ctrl+V or type the text directly.
//!
//! Policy borrowed from espanso (delays, clipboard preserve) and the paste
//! routine from PowerToys Advanced Paste (release modifiers, tagged SendInput).

use std::sync::atomic::{AtomicIsize, Ordering};
use std::thread;
use std::time::Duration;

/// HWND of the window that had focus when the hotkey fired.
static PREV_HWND: AtomicIsize = AtomicIsize::new(0);

/// Marker on our injected input so any hook of ours can ignore it.
const INJECT_TAG: usize = 0x5A56_5354;

pub const RESTORE_DELAY_MS: u64 = 500;
pub const SENSITIVE_CLEAR_SECS: u64 = 30;

#[allow(dead_code)]
#[derive(Debug, thiserror::Error)]
pub enum PasteError {
    #[error("could not open the clipboard")]
    ClipboardBusy,
    #[error("clipboard write failed")]
    ClipboardWrite,
    #[error("unsupported on this platform")]
    Unsupported,
}

#[cfg(windows)]
mod win {
    use super::*;
    use windows::core::{w, PCWSTR, PWSTR};
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::Foundation::{HANDLE, HGLOBAL, HWND};
    use windows::Win32::System::DataExchange::{
        CloseClipboard, EmptyClipboard, GetClipboardData, IsClipboardFormatAvailable,
        OpenClipboard, RegisterClipboardFormatW, SetClipboardData,
    };
    use windows::Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE};
    use windows::Win32::System::Threading::{
        AttachThreadInput, GetCurrentThreadId, OpenProcess, QueryFullProcessImageNameW,
        PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    use windows::Win32::UI::Input::KeyboardAndMouse::{
        SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, KEYBDINPUT, KEYEVENTF_KEYUP, KEYEVENTF_UNICODE,
        VIRTUAL_KEY, VK_CONTROL, VK_LCONTROL, VK_LMENU, VK_LSHIFT, VK_LWIN, VK_RCONTROL, VK_RETURN,
        VK_RMENU, VK_RSHIFT, VK_RWIN, VK_V,
    };
    use windows::Win32::UI::WindowsAndMessaging::{
        GetForegroundWindow, GetWindowThreadProcessId, SetForegroundWindow,
    };

    const CF_UNICODETEXT: u32 = 13;

    /// Private clipboard format stamped on everything we write, so the
    /// history listener can ignore our own pastes and restores.
    fn own_marker_format() -> u32 {
        unsafe { RegisterClipboardFormatW(w!("SnippetVaultInternal")) }
    }

    fn exclude_format() -> u32 {
        unsafe { RegisterClipboardFormatW(w!("ExcludeClipboardContentFromMonitorProcessing")) }
    }

    pub fn capture_foreground() {
        let hwnd = unsafe { GetForegroundWindow() };
        PREV_HWND.store(hwnd.0 as isize, Ordering::SeqCst);
    }

    fn prev_hwnd() -> Option<HWND> {
        let raw = PREV_HWND.load(Ordering::SeqCst);
        if raw == 0 {
            None
        } else {
            Some(HWND(raw as *mut _))
        }
    }

    /// Bring the previously focused window back. Windows refuses
    /// SetForegroundWindow unless our thread is allowed to; attaching to the
    /// target input thread is the standard workaround.
    pub fn activate_previous() -> bool {
        let Some(hwnd) = prev_hwnd() else {
            return false;
        };
        unsafe {
            if SetForegroundWindow(hwnd).as_bool() {
                return true;
            }
            let target_thread = GetWindowThreadProcessId(hwnd, None);
            let me = GetCurrentThreadId();
            if target_thread != 0 && target_thread != me {
                let _ = AttachThreadInput(me, target_thread, true);
                let ok = SetForegroundWindow(hwnd).as_bool();
                let _ = AttachThreadInput(me, target_thread, false);
                return ok;
            }
            false
        }
    }

    struct ClipboardGuard;
    impl Drop for ClipboardGuard {
        fn drop(&mut self) {
            unsafe {
                let _ = CloseClipboard();
            }
        }
    }

    fn open_clipboard_retry() -> Result<ClipboardGuard, PasteError> {
        for _ in 0..15 {
            if unsafe { OpenClipboard(None) }.is_ok() {
                return Ok(ClipboardGuard);
            }
            thread::sleep(Duration::from_millis(20));
        }
        Err(PasteError::ClipboardBusy)
    }

    unsafe fn put_hglobal(format: u32, bytes: &[u8]) -> Result<(), PasteError> {
        let h: HGLOBAL =
            GlobalAlloc(GMEM_MOVEABLE, bytes.len()).map_err(|_| PasteError::ClipboardWrite)?;
        let p = GlobalLock(h) as *mut u8;
        if p.is_null() {
            return Err(PasteError::ClipboardWrite);
        }
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), p, bytes.len());
        let _ = GlobalUnlock(h);
        SetClipboardData(format, Some(HANDLE(h.0))).map_err(|_| PasteError::ClipboardWrite)?;
        Ok(())
    }

    /// Write text. `exclude_from_history` keeps it out of Win+V and cloud clipboard.
    pub fn set_text(text: &str, exclude_from_history: bool) -> Result<(), PasteError> {
        let _guard = open_clipboard_retry()?;
        unsafe {
            EmptyClipboard().map_err(|_| PasteError::ClipboardWrite)?;
            let mut wide: Vec<u16> = text.encode_utf16().collect();
            wide.push(0);
            let bytes = std::slice::from_raw_parts(wide.as_ptr() as *const u8, wide.len() * 2);
            put_hglobal(CF_UNICODETEXT, bytes)?;
            let marker = own_marker_format();
            if marker != 0 {
                let _ = put_hglobal(marker, &1u32.to_le_bytes());
            }
            if exclude_from_history {
                let zero = 0u32.to_le_bytes();
                let names: [PCWSTR; 3] = [
                    w!("ExcludeClipboardContentFromMonitorProcessing"),
                    w!("CanIncludeInClipboardHistory"),
                    w!("CanUploadToCloudClipboard"),
                ];
                for name in names {
                    let fmt = RegisterClipboardFormatW(name);
                    if fmt != 0 {
                        let _ = put_hglobal(fmt, &zero);
                    }
                }
            }
        }
        Ok(())
    }

    pub fn get_text() -> Option<String> {
        let _guard = open_clipboard_retry().ok()?;
        unsafe {
            IsClipboardFormatAvailable(CF_UNICODETEXT).ok()?;
            let h = GetClipboardData(CF_UNICODETEXT).ok()?;
            let hg = HGLOBAL(h.0);
            let p = GlobalLock(hg) as *const u16;
            if p.is_null() {
                return None;
            }
            let mut len = 0usize;
            while *p.add(len) != 0 {
                len += 1;
            }
            let s = String::from_utf16_lossy(std::slice::from_raw_parts(p, len));
            let _ = GlobalUnlock(hg);
            Some(s)
        }
    }

    /// Clipboard text for the history recorder. None when the clipboard has no
    /// text, when we wrote it ourselves, or when the writing app asked
    /// clipboard managers to stay away.
    pub fn read_for_capture() -> Option<String> {
        let _guard = open_clipboard_retry().ok()?;
        unsafe {
            IsClipboardFormatAvailable(CF_UNICODETEXT).ok()?;
            let marker = own_marker_format();
            if marker != 0 && IsClipboardFormatAvailable(marker).is_ok() {
                return None;
            }
            let excl = exclude_format();
            if excl != 0 && IsClipboardFormatAvailable(excl).is_ok() {
                return None;
            }
            let h = GetClipboardData(CF_UNICODETEXT).ok()?;
            let hg = HGLOBAL(h.0);
            let p = GlobalLock(hg) as *const u16;
            if p.is_null() {
                return None;
            }
            let mut len = 0usize;
            while *p.add(len) != 0 {
                len += 1;
            }
            let s = String::from_utf16_lossy(std::slice::from_raw_parts(p, len));
            let _ = GlobalUnlock(hg);
            Some(s)
        }
    }

    /// Executable name (lowercase, e.g. "chrome.exe") of the foreground window.
    pub fn foreground_app_name() -> Option<String> {
        unsafe {
            let hwnd = GetForegroundWindow();
            let mut pid = 0u32;
            GetWindowThreadProcessId(hwnd, Some(&mut pid));
            if pid == 0 {
                return None;
            }
            let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
            let mut buf = vec![0u16; 1024];
            let mut len = buf.len() as u32;
            let ok = QueryFullProcessImageNameW(
                h,
                PROCESS_NAME_WIN32,
                PWSTR(buf.as_mut_ptr()),
                &mut len,
            );
            let _ = CloseHandle(h);
            ok.ok()?;
            let full = String::from_utf16_lossy(&buf[..len as usize]);
            full.rsplit(['\\', '/']).next().map(|n| n.to_lowercase())
        }
    }

    fn key(vk: VIRTUAL_KEY, up: bool) -> INPUT {
        INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT {
                    wVk: vk,
                    wScan: 0,
                    dwFlags: if up {
                        KEYEVENTF_KEYUP
                    } else {
                        Default::default()
                    },
                    time: 0,
                    dwExtraInfo: INJECT_TAG,
                },
            },
        }
    }

    fn unicode(unit: u16, up: bool) -> INPUT {
        INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT {
                    wVk: VIRTUAL_KEY(0),
                    wScan: unit,
                    dwFlags: if up {
                        KEYEVENTF_UNICODE | KEYEVENTF_KEYUP
                    } else {
                        KEYEVENTF_UNICODE
                    },
                    time: 0,
                    dwExtraInfo: INJECT_TAG,
                },
            },
        }
    }

    fn send(inputs: &[INPUT]) {
        unsafe {
            SendInput(inputs, std::mem::size_of::<INPUT>() as i32);
        }
    }

    /// The user is usually still holding the hotkey modifiers when we paste.
    pub fn release_modifiers() {
        let ups: Vec<INPUT> = [
            VK_LCONTROL,
            VK_RCONTROL,
            VK_LSHIFT,
            VK_RSHIFT,
            VK_LMENU,
            VK_RMENU,
            VK_LWIN,
            VK_RWIN,
        ]
        .into_iter()
        .map(|vk| key(vk, true))
        .collect();
        send(&ups);
    }

    /// Delete n characters to the left of the caret.
    pub fn send_backspaces(n: usize) {
        use windows::Win32::UI::Input::KeyboardAndMouse::VK_BACK;
        let mut batch: Vec<INPUT> = Vec::with_capacity(n * 2);
        for _ in 0..n {
            batch.push(key(VK_BACK, false));
            batch.push(key(VK_BACK, true));
        }
        if !batch.is_empty() {
            send(&batch);
        }
    }

    pub fn send_ctrl_v() {
        send(&[
            key(VK_CONTROL, false),
            key(VK_V, false),
            key(VK_V, true),
            key(VK_CONTROL, true),
        ]);
    }

    /// Type text as Unicode key events. Slower, but works where paste is blocked.
    pub fn type_text(text: &str) {
        let mut batch: Vec<INPUT> = Vec::with_capacity(64);
        for ch in text.chars() {
            if ch == '\r' {
                continue;
            }
            if ch == '\n' {
                batch.push(key(VK_RETURN, false));
                batch.push(key(VK_RETURN, true));
            } else {
                let mut units = [0u16; 2];
                for u in ch.encode_utf16(&mut units) {
                    batch.push(unicode(*u, false));
                    batch.push(unicode(*u, true));
                }
            }
            if batch.len() >= 60 {
                send(&batch);
                batch.clear();
                thread::sleep(Duration::from_millis(5));
            }
        }
        if !batch.is_empty() {
            send(&batch);
        }
    }
}

#[cfg(windows)]
pub use win::*;

#[cfg(not(windows))]
mod other {
    use super::*;
    pub fn capture_foreground() {}
    pub fn activate_previous() -> bool {
        false
    }
    pub fn set_text(_: &str, _: bool) -> Result<(), PasteError> {
        Err(PasteError::Unsupported)
    }
    pub fn get_text() -> Option<String> {
        None
    }
    pub fn read_for_capture() -> Option<String> {
        None
    }
    pub fn foreground_app_name() -> Option<String> {
        None
    }
    pub fn release_modifiers() {}
    pub fn send_backspaces(_: usize) {}
    pub fn send_ctrl_v() {}
    pub fn type_text(_: &str) {}
}
#[cfg(not(windows))]
pub use other::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    /// Clipboard + Ctrl+V into the previous window, then restore old clipboard.
    Paste,
    /// Keystroke injection into the previous window (never for secrets).
    Type,
    /// Leave on clipboard only.
    Copy,
}

/// Deliver `text`. Call after the palette window has been hidden.
pub fn deliver(text: &str, mode: Delivery, sensitive: bool) -> Result<(), PasteError> {
    match mode {
        Delivery::Copy => {
            set_text(text, sensitive)?;
            if sensitive {
                schedule_clear(text.to_string(), Duration::from_secs(SENSITIVE_CLEAR_SECS));
            }
            Ok(())
        }
        Delivery::Type => {
            activate_previous();
            thread::sleep(Duration::from_millis(80));
            release_modifiers();
            type_text(text);
            Ok(())
        }
        Delivery::Paste => {
            let backup = get_text();
            activate_previous();
            thread::sleep(Duration::from_millis(80));
            set_text(text, sensitive)?;
            release_modifiers();
            thread::sleep(Duration::from_millis(30));
            send_ctrl_v();
            let ours = text.to_string();
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(RESTORE_DELAY_MS));
                // Only touch the clipboard if it still holds what we put there.
                if get_text().as_deref() == Some(ours.as_str()) {
                    match backup {
                        Some(prev) => {
                            let _ = set_text(&prev, false);
                        }
                        None => {
                            let _ = set_text("", true);
                        }
                    }
                }
            });
            Ok(())
        }
    }
}

/// Like deliver, but for the window that already has focus (text expansion).
pub fn deliver_in_place(text: &str, mode: Delivery, sensitive: bool) -> Result<(), PasteError> {
    match mode {
        Delivery::Type if !sensitive => {
            release_modifiers();
            type_text(text);
            Ok(())
        }
        _ => {
            let backup = get_text();
            set_text(text, sensitive)?;
            release_modifiers();
            thread::sleep(Duration::from_millis(20));
            send_ctrl_v();
            let ours = text.to_string();
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(RESTORE_DELAY_MS));
                if get_text().as_deref() == Some(ours.as_str()) {
                    match backup {
                        Some(prev) => {
                            let _ = set_text(&prev, false);
                        }
                        None => {
                            let _ = set_text("", true);
                        }
                    }
                }
            });
            Ok(())
        }
    }
}

fn schedule_clear(ours: String, after: Duration) {
    thread::spawn(move || {
        thread::sleep(after);
        if get_text().as_deref() == Some(ours.as_str()) {
            let _ = set_text("", true);
        }
    });
}
