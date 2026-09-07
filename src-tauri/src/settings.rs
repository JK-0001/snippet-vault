//! User settings, stored as plain JSON next to the vault (nothing secret in here).

use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Settings {
    /// Lock after this many minutes without keyboard/mouse input. 0 = never.
    pub auto_lock_minutes: u32,
    /// Lock when the Windows lock screen appears (Win+L, timeout).
    pub lock_on_windows_lock: bool,
    /// Lock when the machine goes to sleep / hibernates.
    pub lock_on_sleep: bool,
    /// Allow unlocking with the Windows account password (DPAPI-cached key).
    pub quick_unlock: bool,
    /// Record text copied anywhere as encrypted "clip" items (only while unlocked).
    pub clip_history_enabled: bool,
    /// Keep at most this many unpinned clips.
    pub clip_max_items: usize,
    /// Process names (e.g. "keepassxc.exe") whose copies are never recorded.
    pub clip_ignore_apps: Vec<String>,
    /// What to do when a copied text looks like a password or API key: "mask" or "skip".
    pub clip_secret_policy: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            auto_lock_minutes: 15,
            lock_on_windows_lock: true,
            lock_on_sleep: true,
            quick_unlock: true,
            clip_history_enabled: true,
            clip_max_items: 200,
            clip_ignore_apps: vec![
                "keepassxc.exe".into(),
                "keepass.exe".into(),
                "bitwarden.exe".into(),
                "1password.exe".into(),
                "snippet-vault.exe".into(),
            ],
            clip_secret_policy: "mask".into(),
        }
    }
}

impl Settings {
    pub fn load(path: &Path) -> Self {
        std::fs::read(path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let json = serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?;
        std::fs::write(path, json)
    }
}
