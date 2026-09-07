//! Text expansion: type a trigger such as `;sig` in any app and it is replaced
//! by the item body. A low-level keyboard hook (the Beeftext / espanso idea)
//! keeps a small rolling buffer of typed characters and fires when the buffer
//! ends with a known trigger. Injected keys (ours or other tools') are ignored.

use crate::commands::AppState;
use crate::paste::{self, Delivery};
use crate::vault::{has_variables, PasteMode};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Mutex, OnceLock, RwLock};
use std::time::Duration;
use tauri::{AppHandle, Emitter, Manager};

pub static ENABLED: AtomicBool = AtomicBool::new(true);

/// (trigger chars, item id), longest trigger first.
static TRIGGERS: RwLock<Vec<(Vec<char>, String)>> = RwLock::new(Vec::new());

struct Fire {
    trigger_len: usize,
    item_id: String,
}

static TX: OnceLock<Mutex<mpsc::Sender<Fire>>> = OnceLock::new();

pub fn set_triggers(list: Vec<(String, String)>) {
    let mut v: Vec<(Vec<char>, String)> =
        list.into_iter().map(|(t, id)| (t.chars().collect(), id)).collect();
    v.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
    if let Ok(mut g) = TRIGGERS.write() {
        *g = v;
    }
}

pub fn clear() {
    if let Ok(mut g) = TRIGGERS.write() {
        g.clear();
    }
}

fn fire(f: Fire) {
    if let Some(tx) = TX.get() {
        if let Ok(tx) = tx.lock() {
            let _ = tx.send(f);
        }
    }
}

/// Runs on the worker thread: delete the trigger, then deliver the body.
fn perform(app: &AppHandle, f: Fire) {
    let Some(state) = app.try_state::<AppState>() else {
        return;
    };
    let (text, delivery, sensitive, vars) = {
        let Ok(mut v) = state.vault.lock() else {
            return;
        };
        let Ok(item) = v.get(&f.item_id) else {
            return;
        };
        let sensitive = item.sensitive;
        let delivery = match item.paste_mode {
            PasteMode::Type if !sensitive => Delivery::Type,
            _ => Delivery::Paste,
        };
        let vars = has_variables(&item.body);
        let text = zeroize::Zeroizing::new(item.body.clone());
        let _ = v.touch_used(&f.item_id);
        (text, delivery, sensitive, vars)
    };

    std::thread::sleep(Duration::from_millis(25));
    paste::send_backspaces(f.trigger_len);
    std::thread::sleep(Duration::from_millis(40));

    if vars {
        // Blanks to fill: hand over to the palette, which pastes on submit.
        crate::show_palette(app);
        let _ = app.emit("expand-with-vars", f.item_id.clone());
        return;
    }
    if let Err(e) = paste::deliver_in_place(&text, delivery, sensitive) {
        log::error!("expansion delivery failed: {e}");
    }
}

#[cfg(windows)]
mod win {
    use super::*;
    use std::sync::Mutex;
    use windows::Win32::Foundation::{LPARAM, LRESULT, WPARAM};
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows::Win32::System::Threading::GetCurrentProcessId;
    use windows::Win32::UI::Input::KeyboardAndMouse::{
        GetAsyncKeyState, GetKeyState, GetKeyboardLayout, ToUnicodeEx, VIRTUAL_KEY, VK_BACK,
        VK_CAPITAL, VK_CONTROL, VK_DELETE, VK_DOWN, VK_END, VK_ESCAPE, VK_HOME, VK_LEFT,
        VK_LWIN, VK_MENU, VK_NEXT, VK_PRIOR, VK_RETURN, VK_RIGHT, VK_RWIN, VK_SHIFT, VK_TAB,
        VK_UP,
    };
    use windows::Win32::UI::WindowsAndMessaging::{
        CallNextHookEx, DispatchMessageW, GetForegroundWindow, GetMessageW,
        GetWindowThreadProcessId, SetWindowsHookExW, TranslateMessage, KBDLLHOOKSTRUCT, MSG,
        WH_KEYBOARD_LL, WM_KEYDOWN, WM_SYSKEYDOWN,
    };

    const LLKHF_INJECTED: u32 = 0x10;
    const BUFFER_MAX: usize = 64;
    /// ToUnicodeEx flag: do not change keyboard state (Win10 1607+), so dead keys survive.
    const TOUNICODE_NO_STATE_CHANGE: u32 = 0x4;

    static BUFFER: Mutex<Vec<char>> = Mutex::new(Vec::new());

    fn pressed(vk: VIRTUAL_KEY) -> bool {
        unsafe { (GetAsyncKeyState(vk.0 as i32) as u16) & 0x8000 != 0 }
    }

    fn foreground_is_us() -> bool {
        unsafe {
            let hwnd = GetForegroundWindow();
            let mut pid = 0u32;
            GetWindowThreadProcessId(hwnd, Some(&mut pid));
            pid == GetCurrentProcessId()
        }
    }

    fn handle_key(vk: u32, scan: u32) {
        let Ok(mut buf) = BUFFER.lock() else { return };
        if foreground_is_us() {
            buf.clear();
            return;
        }
        let vk16 = VIRTUAL_KEY(vk as u16);
        match vk16 {
            VK_BACK => {
                buf.pop();
                return;
            }
            VK_RETURN | VK_TAB | VK_ESCAPE | VK_LEFT | VK_RIGHT | VK_UP | VK_DOWN | VK_HOME
            | VK_END | VK_PRIOR | VK_NEXT | VK_DELETE => {
                buf.clear();
                return;
            }
            VK_SHIFT | VK_CONTROL | VK_MENU | VK_CAPITAL | VK_LWIN | VK_RWIN => return,
            _ => {}
        }
        // 0xA0..=0xA5 are the left/right shift/ctrl/alt variants.
        if (0xA0..=0xA5).contains(&vk) {
            return;
        }
        let ctrl = pressed(VK_CONTROL);
        let alt = pressed(VK_MENU);
        if pressed(VK_LWIN) || pressed(VK_RWIN) || (ctrl && !alt) || (alt && !ctrl) {
            buf.clear(); // a shortcut, not typing
            return;
        }

        let mut state = [0u8; 256];
        if pressed(VK_SHIFT) {
            state[VK_SHIFT.0 as usize] = 0x80;
        }
        if unsafe { GetKeyState(VK_CAPITAL.0 as i32) } & 1 != 0 {
            state[VK_CAPITAL.0 as usize] = 0x01;
        }
        if ctrl && alt {
            state[VK_CONTROL.0 as usize] = 0x80;
            state[VK_MENU.0 as usize] = 0x80;
        }
        let layout = unsafe {
            let tid = GetWindowThreadProcessId(GetForegroundWindow(), None);
            GetKeyboardLayout(tid)
        };
        let mut out = [0u16; 8];
        let n = unsafe {
            ToUnicodeEx(vk, scan, &state, &mut out, TOUNICODE_NO_STATE_CHANGE, Some(layout))
        };
        if n <= 0 {
            return; // dead key or no character
        }
        for ch in char::decode_utf16(out[..n as usize].iter().copied()).flatten() {
            if ch.is_control() {
                continue;
            }
            buf.push(ch);
        }
        if buf.len() > BUFFER_MAX {
            let cut = buf.len() - BUFFER_MAX;
            buf.drain(..cut);
        }

        if let Ok(triggers) = TRIGGERS.read() {
            for (t, id) in triggers.iter() {
                if buf.len() >= t.len() && buf[buf.len() - t.len()..] == t[..] {
                    let f = Fire { trigger_len: t.len(), item_id: id.clone() };
                    buf.clear();
                    drop(triggers);
                    fire(f);
                    return;
                }
            }
        }
    }

    unsafe extern "system" fn hook_proc(code: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
        if code >= 0 && ENABLED.load(Ordering::Relaxed) {
            let kb = &*(lparam.0 as *const KBDLLHOOKSTRUCT);
            let injected = kb.flags.0 & LLKHF_INJECTED != 0;
            let msg = wparam.0 as u32;
            if !injected && (msg == WM_KEYDOWN || msg == WM_SYSKEYDOWN) {
                handle_key(kb.vkCode, kb.scanCode);
            }
        }
        CallNextHookEx(None, code, wparam, lparam)
    }

    /// Blocks forever: installs the hook and pumps messages. Own thread.
    pub fn run_hook_thread() {
        unsafe {
            let hinst = GetModuleHandleW(None).ok();
            match SetWindowsHookExW(WH_KEYBOARD_LL, Some(hook_proc), hinst.map(Into::into), 0) {
                Ok(_) => log::info!("text expansion hook installed"),
                Err(e) => {
                    log::error!("could not install keyboard hook: {e}");
                    return;
                }
            }
            let mut msg = MSG::default();
            while GetMessageW(&mut msg, None, 0, 0).as_bool() {
                let _ = TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
    }
}

#[cfg(not(windows))]
mod win {
    pub fn run_hook_thread() {}
}

/// Start the hook thread and the delivery worker.
pub fn start(app: AppHandle) {
    let (tx, rx) = mpsc::channel::<Fire>();
    if TX.set(Mutex::new(tx)).is_err() {
        return;
    }
    std::thread::Builder::new()
        .name("expansion-hook".into())
        .spawn(win::run_hook_thread)
        .ok();
    std::thread::Builder::new()
        .name("expansion-worker".into())
        .spawn(move || {
            while let Ok(f) = rx.recv() {
                perform(&app, f);
            }
        })
        .ok();
}
