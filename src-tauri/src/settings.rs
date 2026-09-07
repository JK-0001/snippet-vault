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
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            auto_lock_minutes: 15,
            lock_on_windows_lock: true,
            lock_on_sleep: true,
            quick_unlock: true,
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
