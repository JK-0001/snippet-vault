//! Tauri commands: the only surface the webview can call.

use crate::paste::{self, Delivery};
use crate::settings::Settings;
use crate::vault::{Item, ItemInput, ItemKind, ItemSummary, PasteMode, Vault};
use crate::winsec;
use serde::Serialize;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;
use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_autostart::ManagerExt;

pub struct AppState {
    pub vault: Mutex<Vault>,
    pub settings: Mutex<Settings>,
    pub data_dir: PathBuf,
}

impl AppState {
    pub fn quick_key_path(&self) -> PathBuf {
        self.data_dir.join("quick.key")
    }
    pub fn settings_path(&self) -> PathBuf {
        self.data_dir.join("settings.json")
    }
    pub fn settings(&self) -> Settings {
        self.settings.lock().map(|s| s.clone()).unwrap_or_default()
    }
}

type CmdResult<T> = Result<T, String>;

fn err<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

#[cfg(windows)]
fn main_hwnd(app: &AppHandle) -> Option<isize> {
    app.get_webview_window("main")
        .and_then(|w| w.hwnd().ok())
        .map(|h| h.0 as isize)
}
#[cfg(not(windows))]
fn main_hwnd(_app: &AppHandle) -> Option<isize> {
    None
}

fn hide_main(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.hide();
    }
}

/// Store the vault key wrapped with DPAPI so the Windows password can unlock later.
fn write_quick_key(state: &AppState, v: &Vault) {
    match v
        .vault_key_bytes()
        .map_err(err)
        .and_then(|kb| winsec::dpapi_protect(&kb).map_err(err))
    {
        Ok(blob) => {
            if let Err(e) = std::fs::write(state.quick_key_path(), blob) {
                log::error!("could not write quick-unlock cache: {e}");
            }
        }
        Err(e) => log::error!("could not create quick-unlock cache: {e}"),
    }
}

#[derive(Serialize)]
pub struct VaultStatus {
    pub exists: bool,
    pub unlocked: bool,
    pub item_count: usize,
    pub path: String,
    pub quick_unlock_available: bool,
}

#[tauri::command]
pub fn vault_status(state: State<AppState>) -> CmdResult<VaultStatus> {
    let v = state.vault.lock().map_err(err)?;
    let quick = state.settings().quick_unlock && state.quick_key_path().exists();
    Ok(VaultStatus {
        exists: v.exists(),
        unlocked: v.is_unlocked(),
        item_count: v.item_count(),
        path: v.path().display().to_string(),
        quick_unlock_available: quick,
    })
}

#[tauri::command]
pub fn vault_create(state: State<AppState>, password: String) -> CmdResult<()> {
    let mut v = state.vault.lock().map_err(err)?;
    let pw = zeroize::Zeroizing::new(password);
    v.create(pw.as_bytes()).map_err(err)?;
    if state.settings().quick_unlock {
        write_quick_key(&state, &v);
    }
    Ok(())
}

#[tauri::command]
pub fn vault_unlock(state: State<AppState>, password: String) -> CmdResult<usize> {
    let mut v = state.vault.lock().map_err(err)?;
    let pw = zeroize::Zeroizing::new(password);
    v.unlock(pw.as_bytes()).map_err(err)?;
    if state.settings().quick_unlock {
        write_quick_key(&state, &v);
    }
    Ok(v.item_count())
}

/// Unlock by proving the Windows account password (no master password typed).
#[tauri::command]
pub fn vault_quick_unlock(app: AppHandle, state: State<AppState>) -> CmdResult<usize> {
    if !state.settings().quick_unlock {
        return Err("Quick unlock is turned off in settings.".into());
    }
    let path = state.quick_key_path();
    if !path.exists() {
        return Err("Unlock with your master password once to enable quick unlock.".into());
    }
    let parent = main_hwnd(&app);
    let ok = crate::with_dialog(|| {
        winsec::verify_current_user_password(
            "Snippet Vault",
            "Enter your Windows password to unlock the vault.",
            parent,
        )
    })
    .map_err(err)?;
    if !ok {
        return Err("cancelled".into());
    }
    let blob = std::fs::read(&path).map_err(err)?;
    let key = winsec::dpapi_unprotect(&blob).map_err(err)?;
    let mut v = state.vault.lock().map_err(err)?;
    v.unlock_with_key(&key).map_err(|e| {
        // A stale cache (e.g. vault recreated) is useless; drop it.
        let _ = std::fs::remove_file(&path);
        err(e)
    })?;
    Ok(v.item_count())
}

#[tauri::command]
pub fn vault_lock(app: AppHandle, state: State<AppState>) -> CmdResult<()> {
    let mut v = state.vault.lock().map_err(err)?;
    v.lock();
    let _ = app.emit("vault-locked", ());
    Ok(())
}

// ---------- settings ----------

#[tauri::command]
pub fn settings_get(state: State<AppState>) -> CmdResult<Settings> {
    Ok(state.settings())
}

#[tauri::command]
pub fn settings_set(state: State<AppState>, settings: Settings) -> CmdResult<Settings> {
    settings.save(&state.settings_path()).map_err(err)?;
    {
        let mut s = state.settings.lock().map_err(err)?;
        *s = settings.clone();
    }
    let path = state.quick_key_path();
    if !settings.quick_unlock {
        let _ = std::fs::remove_file(&path);
    } else if !path.exists() {
        if let Ok(v) = state.vault.lock() {
            if v.is_unlocked() {
                write_quick_key(&state, &v);
            }
        }
    }
    Ok(settings)
}

#[tauri::command]
pub fn autostart_get(app: AppHandle) -> CmdResult<bool> {
    app.autolaunch().is_enabled().map_err(err)
}

#[tauri::command]
pub fn autostart_set(app: AppHandle, enabled: bool) -> CmdResult<bool> {
    let al = app.autolaunch();
    if enabled { al.enable() } else { al.disable() }.map_err(err)?;
    al.is_enabled().map_err(err)
}

// ---------- items ----------

#[tauri::command]
pub fn items_search(
    state: State<AppState>,
    query: String,
    kind: Option<ItemKind>,
    limit: Option<usize>,
) -> CmdResult<Vec<ItemSummary>> {
    let mut v = state.vault.lock().map_err(err)?;
    v.search(&query, kind, limit.unwrap_or(50)).map_err(err)
}

/// Full item. For sensitive items the body is blank unless `reveal` is true.
#[tauri::command]
pub fn item_get(state: State<AppState>, id: String, reveal: Option<bool>) -> CmdResult<Item> {
    let v = state.vault.lock().map_err(err)?;
    let mut item = v.get(&id).map_err(err)?.clone();
    if item.sensitive && !reveal.unwrap_or(false) {
        item.body = String::new();
    }
    Ok(item)
}

#[tauri::command]
pub fn item_save(state: State<AppState>, input: ItemInput) -> CmdResult<Item> {
    let mut v = state.vault.lock().map_err(err)?;
    let mut item = v.save(input).map_err(err)?;
    if item.sensitive {
        item.body = String::new();
    }
    Ok(item)
}

#[tauri::command]
pub fn item_delete(state: State<AppState>, id: String) -> CmdResult<()> {
    let mut v = state.vault.lock().map_err(err)?;
    v.delete(&id).map_err(err)
}

#[tauri::command]
pub fn item_set_pinned(state: State<AppState>, id: String, pinned: bool) -> CmdResult<()> {
    let mut v = state.vault.lock().map_err(err)?;
    v.set_pinned(&id, pinned).map_err(err)
}

#[tauri::command]
pub fn vault_taxonomy(state: State<AppState>) -> CmdResult<(Vec<String>, Vec<String>)> {
    let v = state.vault.lock().map_err(err)?;
    v.folders_and_tags().map_err(err)
}

/// Fill `{{var}}` placeholders. Unfilled ones are left as-is.
fn fill_vars(body: &str, vars: &Option<HashMap<String, String>>) -> String {
    let Some(vars) = vars else {
        return body.to_string();
    };
    let mut out = body.to_string();
    for (k, v) in vars {
        out = out.replace(&format!("{{{{{}}}}}", k), v);
    }
    out
}

/// Use an item: hide the palette, then paste / type / copy it.
/// `mode` overrides the item default when given ("paste" | "type" | "copy").
#[tauri::command]
pub fn item_use(
    app: AppHandle,
    state: State<AppState>,
    id: String,
    mode: Option<String>,
    vars: Option<HashMap<String, String>>,
) -> CmdResult<()> {
    let (text, delivery, sensitive) = {
        let mut v = state.vault.lock().map_err(err)?;
        let item = v.get(&id).map_err(err)?;
        let sensitive = item.sensitive;
        let default = match item.paste_mode {
            PasteMode::Paste => Delivery::Paste,
            PasteMode::Type => Delivery::Type,
            PasteMode::CopyOnly => Delivery::Copy,
        };
        let delivery = match mode.as_deref() {
            Some("paste") => Delivery::Paste,
            Some("type") if !sensitive => Delivery::Type,
            Some("type") => Delivery::Paste,
            Some("copy") => Delivery::Copy,
            _ => default,
        };
        let text = fill_vars(&item.body, &vars);
        v.touch_used(&id).map_err(err)?;
        (text, delivery, sensitive)
    };

    hide_main(&app);
    // Give the window manager a moment to move focus back.
    std::thread::sleep(std::time::Duration::from_millis(60));
    let text = zeroize::Zeroizing::new(text);
    paste::deliver(&text, delivery, sensitive).map_err(err)
}

#[tauri::command]
pub fn clipboard_read() -> Option<String> {
    paste::get_text()
}

#[tauri::command]
pub fn palette_hide(app: AppHandle) {
    hide_main(&app);
}

#[tauri::command]
pub fn palette_show(app: AppHandle) {
    crate::show_palette(&app);
}

#[tauri::command]
pub fn app_quit(app: AppHandle) {
    app.exit(0);
}

// ---------- backup / restore ----------

use crate::backup;
use tauri_plugin_dialog::DialogExt;

#[derive(Serialize)]
pub struct ImportPick {
    pub path: String,
    pub encrypted: bool,
}

#[derive(Serialize)]
pub struct ImportResult {
    pub added: usize,
    pub updated: usize,
    pub skipped: usize,
}

fn save_dialog(app: &AppHandle, filter: (&str, &[&str]), name: &str) -> Option<PathBuf> {
    let mut d = app.dialog().file().add_filter(filter.0, filter.1).set_file_name(name);
    if let Some(w) = app.get_webview_window("main") {
        d = d.set_parent(&w);
    }
    crate::with_dialog(|| d.blocking_save_file()).and_then(|p| p.into_path().ok())
}

fn write_private(path: &PathBuf, bytes: &[u8]) -> CmdResult<()> {
    std::fs::write(path, bytes).map_err(err)
}

/// Encrypted `.svault` backup protected by `password` (may equal the master password).
#[tauri::command(async)]
pub fn backup_export_encrypted(
    app: AppHandle,
    state: State<AppState>,
    password: String,
) -> CmdResult<Option<String>> {
    let pw = zeroize::Zeroizing::new(password);
    let items = state.vault.lock().map_err(err)?.export_items().map_err(err)?;
    let bytes = backup::encrypt(&items, pw.as_bytes()).map_err(err)?;
    let name = format!("snippet-vault-backup-{}.svault", backup::today_stamp());
    let Some(path) = save_dialog(&app, ("Snippet Vault backup", &["svault"]), &name) else {
        return Ok(None);
    };
    write_private(&path, &bytes)?;
    Ok(Some(path.display().to_string()))
}

/// Plain JSON export. The UI shows a warning before calling this.
#[tauri::command(async)]
pub fn backup_export_plain(app: AppHandle, state: State<AppState>) -> CmdResult<Option<String>> {
    let items = state.vault.lock().map_err(err)?.export_items().map_err(err)?;
    let bytes = backup::to_plain_json(&items).map_err(err)?;
    let name = format!("snippet-vault-export-{}.json", backup::today_stamp());
    let Some(path) = save_dialog(&app, ("JSON", &["json"]), &name) else {
        return Ok(None);
    };
    write_private(&path, &bytes)?;
    Ok(Some(path.display().to_string()))
}

/// Step 1 of import: pick a file and say whether it needs a password.
#[tauri::command(async)]
pub fn backup_pick_import(app: AppHandle) -> CmdResult<Option<ImportPick>> {
    let mut d = app
        .dialog()
        .file()
        .add_filter("Snippet Vault files", &["svault", "json"]);
    if let Some(w) = app.get_webview_window("main") {
        d = d.set_parent(&w);
    }
    let Some(path) = crate::with_dialog(|| d.blocking_pick_file()).and_then(|p| p.into_path().ok())
    else {
        return Ok(None);
    };
    let bytes = std::fs::read(&path).map_err(err)?;
    Ok(Some(ImportPick {
        path: path.display().to_string(),
        encrypted: backup::is_encrypted(&bytes),
    }))
}

/// Step 2 of import: read, decrypt if needed, merge.
#[tauri::command(async)]
pub fn backup_import(
    state: State<AppState>,
    path: String,
    password: Option<String>,
) -> CmdResult<ImportResult> {
    let bytes = std::fs::read(&path).map_err(err)?;
    let items = if backup::is_encrypted(&bytes) {
        let pw = zeroize::Zeroizing::new(password.unwrap_or_default());
        backup::decrypt(&bytes, pw.as_bytes()).map_err(err)?
    } else {
        backup::from_plain_json(&bytes).map_err(err)?
    };
    let mut v = state.vault.lock().map_err(err)?;
    let (added, updated, skipped) = v.import_items(items).map_err(err)?;
    Ok(ImportResult { added, updated, skipped })
}

#[tauri::command]
pub fn open_data_folder(app: AppHandle, state: State<AppState>) -> CmdResult<()> {
    use tauri_plugin_opener::OpenerExt;
    app.opener()
        .reveal_item_in_dir(state.data_dir.join("vault.db"))
        .map_err(err)
}

#[tauri::command]
pub fn clips_clear(app: AppHandle, state: State<AppState>) -> CmdResult<usize> {
    let n = state.vault.lock().map_err(err)?.clear_clips().map_err(err)?;
    let _ = app.emit("clips-changed", ());
    Ok(n)
}
