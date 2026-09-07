mod backup;
mod commands;
mod crypto;
mod paste;
mod settings;
mod vault;
mod winsec;

use commands::AppState;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Duration;
use tauri::{
    menu::{CheckMenuItem, Menu, MenuItem, PredefinedMenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    AppHandle, Emitter, Manager, WindowEvent,
};
use tauri_plugin_autostart::ManagerExt;
use tauri_plugin_global_shortcut::{Code, GlobalShortcutExt, Modifiers, Shortcut, ShortcutState};

pub const HOTKEY_LABEL: &str = "Ctrl+Shift+Space";

/// While true, losing focus does not hide the palette (native dialogs open).
pub static SUPPRESS_HIDE: AtomicBool = AtomicBool::new(false);

/// Run `f` with auto-hide suspended, e.g. around a file or credential dialog.
pub fn with_dialog<T>(f: impl FnOnce() -> T) -> T {
    SUPPRESS_HIDE.store(true, Ordering::SeqCst);
    let out = f();
    SUPPRESS_HIDE.store(false, Ordering::SeqCst);
    out
}

fn hotkey() -> Shortcut {
    Shortcut::new(Some(Modifiers::CONTROL | Modifiers::SHIFT), Code::Space)
}

fn data_dir(app: &AppHandle) -> std::path::PathBuf {
    app.path()
        .app_data_dir()
        .unwrap_or_else(|_| std::env::temp_dir().join("SnippetVault"))
}

/// Show the palette near the cursor and tell the UI to reset.
pub fn show_palette(app: &AppHandle) {
    paste::capture_foreground();
    let Some(w) = app.get_webview_window("main") else {
        return;
    };
    position_near_cursor(app, &w);
    let _ = w.show();
    let _ = w.unminimize();
    let _ = w.set_focus();
    let _ = app.emit("palette-shown", ());
}

pub fn hide_palette(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.hide();
    }
}

pub fn toggle_palette(app: &AppHandle) {
    let visible = app
        .get_webview_window("main")
        .and_then(|w| w.is_visible().ok())
        .unwrap_or(false);
    if visible {
        hide_palette(app);
    } else {
        show_palette(app);
    }
}

fn position_near_cursor(app: &AppHandle, w: &tauri::WebviewWindow) {
    let Ok(cursor) = app.cursor_position() else {
        return;
    };
    let Ok(Some(monitor)) = w.monitor_from_point(cursor.x, cursor.y) else {
        return;
    };
    let Ok(size) = w.outer_size() else {
        return;
    };
    let area = monitor.work_area();
    let (mx, my) = (area.position.x as f64, area.position.y as f64);
    let (mw, mh) = (area.size.width as f64, area.size.height as f64);
    let (ww, wh) = (size.width as f64, size.height as f64);
    // Centered horizontally on the cursor, a bit below it, clamped to the work area.
    let x = (cursor.x - ww / 2.0).clamp(mx, (mx + mw - ww).max(mx));
    let y = (cursor.y + 24.0).clamp(my, (my + mh - wh).max(my));
    let _ = w.set_position(tauri::PhysicalPosition::new(x as i32, y as i32));
}

/// Lock the vault (if unlocked), hide the palette, tell the UI. Safe from any thread.
pub fn lock_vault(app: &AppHandle, reason: &str) {
    let mut did_lock = false;
    if let Some(state) = app.try_state::<AppState>() {
        if let Ok(mut v) = state.vault.lock() {
            if v.is_unlocked() {
                v.lock();
                did_lock = true;
            }
        }
    }
    if did_lock {
        log::info!("vault locked: {reason}");
    }
    hide_palette(app);
    let _ = app.emit("vault-locked", ());
}

fn build_tray(app: &AppHandle) -> tauri::Result<()> {
    let open = MenuItem::with_id(
        app,
        "open",
        format!("Open ({HOTKEY_LABEL})"),
        true,
        None::<&str>,
    )?;
    let lock = MenuItem::with_id(app, "lock", "Lock vault", true, None::<&str>)?;
    let settings = MenuItem::with_id(app, "settings", "Settings…", true, None::<&str>)?;
    let autostart_on = app.autolaunch().is_enabled().unwrap_or(false);
    let autostart = CheckMenuItem::with_id(
        app,
        "autostart",
        "Start with Windows",
        true,
        autostart_on,
        None::<&str>,
    )?;
    let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
    let sep = PredefinedMenuItem::separator(app)?;
    let menu = Menu::with_items(
        app,
        &[&open, &lock, &sep, &settings, &autostart, &sep, &quit],
    )?;
    let autostart_item = autostart.clone();

    let mut builder = TrayIconBuilder::with_id("main-tray")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .tooltip("Snippet Vault")
        .on_menu_event(move |app, event| match event.id().as_ref() {
            "open" => show_palette(app),
            "lock" => lock_vault(app, "tray menu"),
            "settings" => {
                show_palette(app);
                let _ = app.emit("open-settings", ());
            }
            "autostart" => {
                let al = app.autolaunch();
                let now_on = al.is_enabled().unwrap_or(false);
                let result = if now_on { al.disable() } else { al.enable() };
                if let Err(e) = result {
                    log::error!("autostart toggle failed: {e}");
                }
                let _ = autostart_item.set_checked(al.is_enabled().unwrap_or(false));
            }
            "quit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                toggle_palette(tray.app_handle());
            }
        });
    if let Some(icon) = app.default_window_icon() {
        builder = builder.icon(icon.clone());
    }
    builder.build(app)?;
    Ok(())
}

/// Background watchers: Windows lock screen, sleep, and idle time.
fn start_auto_lock(app: &AppHandle) {
    let h = app.clone();
    std::thread::Builder::new()
        .name("session-watch".into())
        .spawn(move || {
            winsec::run_session_watcher(move |ev| {
                let Some(state) = h.try_state::<AppState>() else {
                    return;
                };
                let s = state.settings();
                match ev {
                    winsec::SessionEvent::Locked if s.lock_on_windows_lock => {
                        lock_vault(&h, "Windows locked")
                    }
                    winsec::SessionEvent::Suspend if s.lock_on_sleep => lock_vault(&h, "sleep"),
                    _ => {}
                }
            });
        })
        .ok();

    let h = app.clone();
    std::thread::Builder::new()
        .name("idle-watch".into())
        .spawn(move || loop {
            std::thread::sleep(Duration::from_secs(10));
            let Some(state) = h.try_state::<AppState>() else {
                continue;
            };
            let minutes = state.settings().auto_lock_minutes;
            if minutes == 0 {
                continue;
            }
            let unlocked = state.vault.lock().map(|v| v.is_unlocked()).unwrap_or(false);
            if unlocked && winsec::idle_seconds() >= u64::from(minutes) * 60 {
                lock_vault(&h, "idle");
            }
        })
        .ok();
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            show_palette(app);
        }))
        .plugin(tauri_plugin_autostart::Builder::new().build())
        .plugin(tauri_plugin_positioner::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(
            tauri_plugin_global_shortcut::Builder::new()
                .with_handler(|app, shortcut, event| {
                    if shortcut == &hotkey() && event.state() == ShortcutState::Pressed {
                        toggle_palette(app);
                    }
                })
                .build(),
        )
        .setup(|app| {
            let dir = data_dir(app.handle());
            let vault_path = dir.join("vault.db");
            log::info!("data dir: {}", dir.display());
            let first_run = !vault_path.exists();
            let settings = settings::Settings::load(&dir.join("settings.json"));
            app.manage(AppState {
                vault: Mutex::new(vault::Vault::new(vault_path)),
                settings: Mutex::new(settings),
                data_dir: dir,
            });

            if let Err(e) = app.global_shortcut().register(hotkey()) {
                log::error!("could not register {HOTKEY_LABEL}: {e}");
            }
            // Start with Windows by default; the tray menu can turn it off.
            let al = app.handle().autolaunch();
            if !al.is_enabled().unwrap_or(false) {
                if let Err(e) = al.enable() {
                    log::error!("could not enable autostart: {e}");
                }
            }
            build_tray(app.handle())?;
            start_auto_lock(app.handle());

            // Only pop up on the very first run (to create the vault). After that,
            // including when Windows starts it, it stays quietly in the tray.
            if first_run {
                show_palette(app.handle());
            }
            Ok(())
        })
        .on_window_event(|window, event| match event {
            // Closing the window just hides it; the tray keeps the app alive.
            WindowEvent::CloseRequested { api, .. } => {
                api.prevent_close();
                let _ = window.hide();
            }
            WindowEvent::Focused(false) => {
                if !SUPPRESS_HIDE.load(Ordering::SeqCst) {
                    let _ = window.hide();
                }
            }
            _ => {}
        })
        .invoke_handler(tauri::generate_handler![
            commands::vault_status,
            commands::vault_create,
            commands::vault_unlock,
            commands::vault_quick_unlock,
            commands::vault_lock,
            commands::settings_get,
            commands::settings_set,
            commands::autostart_get,
            commands::autostart_set,
            commands::items_search,
            commands::item_get,
            commands::item_save,
            commands::item_delete,
            commands::item_set_pinned,
            commands::vault_taxonomy,
            commands::item_use,
            commands::clipboard_read,
            commands::palette_hide,
            commands::palette_show,
            commands::app_quit,
            commands::backup_export_encrypted,
            commands::backup_export_plain,
            commands::backup_pick_import,
            commands::backup_import,
            commands::open_data_folder,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Snippet Vault");
}
