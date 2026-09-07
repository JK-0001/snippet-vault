//! Windows-specific security helpers:
//!   * DPAPI wrap/unwrap for the quick-unlock key cache
//!   * "verify this is the logged-in user" via the Windows credential prompt
//!   * session lock / sleep notifications and idle time for auto-lock
//!
//! Threat note: DPAPI data can be read by any process running as the same
//! user, so quick unlock is a convenience gate against people at the keyboard,
//! not against malware. The master password remains the real secret.

use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEvent {
    /// Windows lock screen shown (Win+L, timeout, switch user).
    Locked,
    /// Machine is about to sleep or hibernate.
    Suspend,
    /// Something new is on the clipboard.
    ClipboardChanged,
}

#[allow(dead_code)]
#[derive(Debug, thiserror::Error)]
pub enum WinSecError {
    #[error("Windows data protection failed: {0}")]
    Dpapi(String),
    #[error("credential prompt failed: {0}")]
    Prompt(String),
    #[error("that is not the password of the signed-in Windows account")]
    WrongUser,
    #[error("unsupported on this platform")]
    Unsupported,
}

#[cfg(windows)]
mod win {
    use super::*;
    use std::ffi::c_void;
    use std::sync::OnceLock;
    use windows::core::{w, PCWSTR, PWSTR};
    use windows::Win32::Foundation::{
        CloseHandle, LocalFree, HANDLE, HLOCAL, HWND, LPARAM, LRESULT, WPARAM,
    };
    use windows::Win32::Security::Credentials::{
        CredUIPromptForWindowsCredentialsW, CredUnPackAuthenticationBufferW, CREDUIWIN_FLAGS,
        CREDUI_INFOW, CRED_PACK_PROTECTED_CREDENTIALS,
    };
    use windows::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPT_INTEGER_BLOB,
    };
    use windows::Win32::Security::{
        EqualSid, GetTokenInformation, LogonUserW, TokenUser, LOGON32_LOGON_INTERACTIVE,
        LOGON32_PROVIDER_DEFAULT, PSID, TOKEN_QUERY, TOKEN_USER,
    };
    use windows::Win32::System::Com::CoTaskMemFree;
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows::Win32::System::DataExchange::AddClipboardFormatListener;
    use windows::Win32::System::RemoteDesktop::WTSRegisterSessionNotification;
    use windows::Win32::System::SystemInformation::GetTickCount;
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};
    use windows::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DefWindowProcW, DispatchMessageW, GetMessageW, RegisterClassW,
        TranslateMessage, MSG, WINDOW_EX_STYLE, WNDCLASSW, WS_OVERLAPPED,
    };

    const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x1;
    const WM_WTSSESSION_CHANGE: u32 = 0x02B1;
    const WTS_SESSION_LOCK: usize = 0x7;
    const WM_POWERBROADCAST: u32 = 0x0218;
    const PBT_APMSUSPEND: usize = 0x4;
    const WM_CLIPBOARDUPDATE: u32 = 0x031D;
    const NOTIFY_FOR_THIS_SESSION: u32 = 0;
    const CREDUIWIN_GENERIC: u32 = 0x1;
    const CREDUIWIN_ENUMERATE_CURRENT_USER: u32 = 0x200;
    const ERROR_CANCELLED: u32 = 1223;

    // ---------- DPAPI ----------

    fn blob_of(bytes: &[u8]) -> CRYPT_INTEGER_BLOB {
        CRYPT_INTEGER_BLOB {
            cbData: bytes.len() as u32,
            pbData: bytes.as_ptr() as *mut u8,
        }
    }

    unsafe fn take_blob(out: &CRYPT_INTEGER_BLOB) -> Vec<u8> {
        let v = std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
        let _ = LocalFree(Some(HLOCAL(out.pbData as *mut c_void)));
        v
    }

    pub fn dpapi_protect(plain: &[u8]) -> Result<Vec<u8>, WinSecError> {
        let entropy = b"snippet-vault-quick-unlock-v1";
        let mut out = CRYPT_INTEGER_BLOB::default();
        unsafe {
            CryptProtectData(
                &blob_of(plain),
                w!("Snippet Vault quick unlock"),
                Some(&blob_of(entropy)),
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
            .map_err(|e| WinSecError::Dpapi(e.to_string()))?;
            Ok(take_blob(&out))
        }
    }

    pub fn dpapi_unprotect(cipher: &[u8]) -> Result<Zeroizing<Vec<u8>>, WinSecError> {
        let entropy = b"snippet-vault-quick-unlock-v1";
        let mut out = CRYPT_INTEGER_BLOB::default();
        unsafe {
            CryptUnprotectData(
                &blob_of(cipher),
                None,
                Some(&blob_of(entropy)),
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
            .map_err(|e| WinSecError::Dpapi(e.to_string()))?;
            Ok(Zeroizing::new(take_blob(&out)))
        }
    }

    // ---------- "prove you are the signed-in user" ----------

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    struct TokenGuard(HANDLE);
    impl Drop for TokenGuard {
        fn drop(&mut self) {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }

    unsafe fn token_user_sid(token: HANDLE) -> Result<Vec<u8>, WinSecError> {
        let mut needed = 0u32;
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut needed);
        let mut buf = vec![0u8; needed as usize];
        GetTokenInformation(
            token,
            TokenUser,
            Some(buf.as_mut_ptr() as *mut c_void),
            needed,
            &mut needed,
        )
        .map_err(|e| WinSecError::Prompt(e.to_string()))?;
        Ok(buf)
    }

    unsafe fn sid_of(buf: &[u8]) -> PSID {
        (*(buf.as_ptr() as *const TOKEN_USER)).User.Sid
    }

    /// Shows the standard Windows credential dialog for the current user and
    /// checks the entered password against Windows. Returns Ok(false) if the
    /// user cancelled.
    pub fn verify_current_user_password(
        caption: &str,
        message: &str,
        parent: Option<isize>,
    ) -> Result<bool, WinSecError> {
        let caption_w = wide(caption);
        let message_w = wide(message);
        let info = CREDUI_INFOW {
            cbSize: std::mem::size_of::<CREDUI_INFOW>() as u32,
            hwndParent: parent.map(|h| HWND(h as *mut c_void)).unwrap_or_default(),
            pszMessageText: PCWSTR(message_w.as_ptr()),
            pszCaptionText: PCWSTR(caption_w.as_ptr()),
            hbmBanner: Default::default(),
        };

        let mut auth_package = 0u32;
        let mut out_buf: *mut c_void = std::ptr::null_mut();
        let mut out_len = 0u32;

        let rc = unsafe {
            CredUIPromptForWindowsCredentialsW(
                Some(&info),
                0,
                &mut auth_package,
                None,
                0,
                &mut out_buf,
                &mut out_len,
                None,
                CREDUIWIN_FLAGS(CREDUIWIN_GENERIC | CREDUIWIN_ENUMERATE_CURRENT_USER),
            )
        };
        if rc == ERROR_CANCELLED {
            return Ok(false);
        }
        if rc != 0 {
            return Err(WinSecError::Prompt(format!("error code {rc}")));
        }

        // Unpack user + password, zeroizing the password afterwards.
        let mut user = Zeroizing::new(vec![0u16; 512]);
        let mut domain = Zeroizing::new(vec![0u16; 512]);
        let mut pass = Zeroizing::new(vec![0u16; 512]);
        let (mut ul, mut dl, mut pl) = (512u32, 512u32, 512u32);
        let unpack = unsafe {
            CredUnPackAuthenticationBufferW(
                CRED_PACK_PROTECTED_CREDENTIALS,
                out_buf,
                out_len,
                Some(PWSTR(user.as_mut_ptr())),
                &mut ul,
                Some(PWSTR(domain.as_mut_ptr())),
                Some(&mut dl),
                Some(PWSTR(pass.as_mut_ptr())),
                &mut pl,
            )
        };
        unsafe {
            // Scrub and free the packed buffer.
            std::ptr::write_bytes(out_buf as *mut u8, 0, out_len as usize);
            CoTaskMemFree(Some(out_buf));
        }
        unpack.map_err(|e| WinSecError::Prompt(e.to_string()))?;

        // Split "DOMAIN\user" if the domain came back empty.
        let user_str =
            String::from_utf16_lossy(&user[..user.iter().position(|&c| c == 0).unwrap_or(0)]);
        let domain_str =
            String::from_utf16_lossy(&domain[..domain.iter().position(|&c| c == 0).unwrap_or(0)]);
        let (u, d) = match (user_str.split_once('\\'), domain_str.is_empty()) {
            (Some((d, u)), true) => (u.to_string(), d.to_string()),
            _ => (user_str.clone(), domain_str.clone()),
        };
        let u_w = wide(&u);
        let d_w = wide(&d);

        let mut token = HANDLE::default();
        let logon = unsafe {
            LogonUserW(
                PCWSTR(u_w.as_ptr()),
                if d.is_empty() {
                    PCWSTR::null()
                } else {
                    PCWSTR(d_w.as_ptr())
                },
                PCWSTR(pass.as_ptr()),
                LOGON32_LOGON_INTERACTIVE,
                LOGON32_PROVIDER_DEFAULT,
                &mut token,
            )
        };
        if logon.is_err() {
            return Err(WinSecError::WrongUser);
        }
        let logon_token = TokenGuard(token);

        // The password was valid for *some* account; make sure it is ours.
        unsafe {
            let mut me = HANDLE::default();
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut me)
                .map_err(|e| WinSecError::Prompt(e.to_string()))?;
            let me = TokenGuard(me);
            let a = token_user_sid(logon_token.0)?;
            let b = token_user_sid(me.0)?;
            if EqualSid(sid_of(&a), sid_of(&b)).is_ok() {
                Ok(true)
            } else {
                Err(WinSecError::WrongUser)
            }
        }
    }

    // ---------- session / power notifications ----------

    type Callback = Box<dyn Fn(SessionEvent) + Send + Sync + 'static>;
    static CALLBACK: OnceLock<Callback> = OnceLock::new();

    unsafe extern "system" fn wndproc(
        hwnd: HWND,
        msg: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        match msg {
            WM_WTSSESSION_CHANGE if wparam.0 == WTS_SESSION_LOCK => {
                if let Some(cb) = CALLBACK.get() {
                    cb(SessionEvent::Locked);
                }
                LRESULT(0)
            }
            WM_POWERBROADCAST if wparam.0 == PBT_APMSUSPEND => {
                if let Some(cb) = CALLBACK.get() {
                    cb(SessionEvent::Suspend);
                }
                LRESULT(1)
            }
            WM_CLIPBOARDUPDATE => {
                if let Some(cb) = CALLBACK.get() {
                    cb(SessionEvent::ClipboardChanged);
                }
                LRESULT(0)
            }
            _ => DefWindowProcW(hwnd, msg, wparam, lparam),
        }
    }

    /// Blocks forever running a hidden window that receives lock/sleep events.
    /// Call from a dedicated thread.
    pub fn run_session_watcher(cb: impl Fn(SessionEvent) + Send + Sync + 'static) {
        if CALLBACK.set(Box::new(cb)).is_err() {
            return;
        }
        unsafe {
            let Ok(hinst) = GetModuleHandleW(None) else {
                return;
            };
            let class_name = w!("SnippetVaultSessionWatcher");
            let wc = WNDCLASSW {
                lpfnWndProc: Some(wndproc),
                hInstance: hinst.into(),
                lpszClassName: class_name,
                ..Default::default()
            };
            if RegisterClassW(&wc) == 0 {
                return;
            }
            // A real (never shown) top-level window: message-only windows do
            // not receive WM_POWERBROADCAST.
            let Ok(hwnd) = CreateWindowExW(
                WINDOW_EX_STYLE(0),
                class_name,
                w!("Snippet Vault watcher"),
                WS_OVERLAPPED,
                0,
                0,
                0,
                0,
                None,
                None,
                Some(hinst.into()),
                None,
            ) else {
                return;
            };
            if let Err(e) = WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION) {
                log::error!("WTSRegisterSessionNotification failed: {e}");
            }
            if let Err(e) = AddClipboardFormatListener(hwnd) {
                log::error!("AddClipboardFormatListener failed: {e}");
            }
            let mut msg = MSG::default();
            while GetMessageW(&mut msg, None, 0, 0).as_bool() {
                let _ = TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
    }

    /// Seconds since the last keyboard or mouse input.
    pub fn idle_seconds() -> u64 {
        let mut li = LASTINPUTINFO {
            cbSize: std::mem::size_of::<LASTINPUTINFO>() as u32,
            dwTime: 0,
        };
        unsafe {
            if !GetLastInputInfo(&mut li).as_bool() {
                return 0;
            }
            let now = GetTickCount();
            (now.wrapping_sub(li.dwTime) as u64) / 1000
        }
    }
}

#[cfg(windows)]
pub use win::*;

#[cfg(not(windows))]
mod other {
    use super::*;
    pub fn dpapi_protect(_: &[u8]) -> Result<Vec<u8>, WinSecError> {
        Err(WinSecError::Unsupported)
    }
    pub fn dpapi_unprotect(_: &[u8]) -> Result<Zeroizing<Vec<u8>>, WinSecError> {
        Err(WinSecError::Unsupported)
    }
    pub fn verify_current_user_password(_: &str, _: &str, _: Option<isize>) -> Result<bool, WinSecError> {
        Err(WinSecError::Unsupported)
    }
    pub fn run_session_watcher(_: impl Fn(SessionEvent) + Send + Sync + 'static) {}
    pub fn idle_seconds() -> u64 {
        0
    }
}
#[cfg(not(windows))]
pub use other::*;
