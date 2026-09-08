//! Auto-update via GitHub Releases. Each release carries a `latest.json`
//! (written by scripts/release.py) plus a signed installer; the updater
//! plugin verifies the signature against the public key in tauri.conf.json.

use serde::Serialize;
use std::time::Duration;
use tauri::{AppHandle, Emitter};
use tauri_plugin_updater::UpdaterExt;

#[derive(Serialize, Clone, Debug)]
pub struct UpdateInfo {
    pub version: String,
    pub notes: String,
    pub date: String,
}

fn err<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

pub async fn check(app: &AppHandle) -> Result<Option<UpdateInfo>, String> {
    let updater = app.updater().map_err(err)?;
    match updater.check().await.map_err(err)? {
        Some(u) => Ok(Some(UpdateInfo {
            version: u.version.clone(),
            notes: u.body.clone().unwrap_or_default(),
            date: u.date.map(|d| d.to_string()).unwrap_or_default(),
        })),
        None => Ok(None),
    }
}

/// Manual check from Settings. Emits `update-available` when there is one.
#[tauri::command]
pub async fn update_check(app: AppHandle) -> Result<Option<UpdateInfo>, String> {
    let info = check(&app).await?;
    if let Some(i) = &info {
        let _ = app.emit("update-available", i.clone());
    }
    Ok(info)
}

/// Download, verify, install, restart. Progress goes out as `update-progress`.
#[tauri::command]
pub async fn update_install(app: AppHandle) -> Result<(), String> {
    let updater = app.updater().map_err(err)?;
    let Some(update) = updater.check().await.map_err(err)? else {
        return Err("No update available.".into());
    };
    let mut downloaded: u64 = 0;
    let progress_app = app.clone();
    let done_app = app.clone();
    update
        .download_and_install(
            move |chunk, total| {
                downloaded += chunk as u64;
                let _ = progress_app.emit("update-progress", (downloaded, total));
            },
            move || {
                let _ = done_app.emit("update-progress", (u64::MAX, None::<u64>));
            },
        )
        .await
        .map_err(err)?;
    app.restart();
}

/// Background: first check shortly after launch, then every 6 hours.
pub fn start_background(app: AppHandle) {
    std::thread::Builder::new()
        .name("update-check".into())
        .spawn(move || {
            std::thread::sleep(Duration::from_secs(45));
            loop {
                match tauri::async_runtime::block_on(check(&app)) {
                    Ok(Some(info)) => {
                        log::info!("update available: {}", info.version);
                        let _ = app.emit("update-available", info);
                    }
                    Ok(None) => log::info!("no update available"),
                    Err(e) => log::warn!("update check failed: {e}"),
                }
                std::thread::sleep(Duration::from_secs(6 * 60 * 60));
            }
        })
        .ok();
}
