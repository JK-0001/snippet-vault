//! Encrypted item store. SQLite holds only ciphertext; while unlocked, a
//! decrypted copy of every item lives in memory (a personal vault is small)
//! so search never needs plaintext on disk.

use crate::crypto::{self, KdfParams, SecretKey, SALT_LEN};
use nucleo_matcher::{
    pattern::{CaseMatching, Normalization, Pattern},
    Config, Matcher, Utf32Str,
};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, Zeroizing};

const FORMAT_VERSION: i64 = 1;

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("vault is locked")]
    Locked,
    #[error("a vault already exists at this location")]
    AlreadyExists,
    #[error("no vault exists yet")]
    Missing,
    #[error("wrong master password")]
    WrongPassword,
    #[error("item not found")]
    NotFound,
    #[error("vault file is corrupted: {0}")]
    Corrupt(String),
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("{0}")]
    Crypto(#[from] crypto::CryptoError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Invalid(String),
}

pub type Result<T> = std::result::Result<T, VaultError>;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ItemKind {
    Text,
    Prompt,
    Secret,
    Clip,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PasteMode {
    Paste,
    Type,
    CopyOnly,
}

/// Full decrypted item. Only ever handed to the webview one at a time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Item {
    pub id: String,
    pub kind: ItemKind,
    pub title: String,
    pub body: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub folder: String,
    #[serde(default)]
    pub pinned: bool,
    #[serde(default)]
    pub sensitive: bool,
    #[serde(default = "default_paste_mode")]
    pub paste_mode: PasteMode,
    /// Optional text-expansion trigger such as ";sig". Empty = none.
    #[serde(default)]
    pub trigger: String,
    #[serde(default)]
    pub use_count: u64,
    #[serde(default)]
    pub last_used: i64,
    pub created_at: i64,
    pub updated_at: i64,
}

fn default_paste_mode() -> PasteMode {
    PasteMode::Paste
}

/// What the list view gets: no body for sensitive items, short preview otherwise.
#[derive(Debug, Clone, Serialize)]
pub struct ItemSummary {
    pub id: String,
    pub kind: ItemKind,
    pub title: String,
    pub preview: String,
    pub tags: Vec<String>,
    pub folder: String,
    pub pinned: bool,
    pub sensitive: bool,
    pub paste_mode: PasteMode,
    pub trigger: String,
    pub use_count: u64,
    pub last_used: i64,
    pub has_variables: bool,
}

/// Fields the UI is allowed to set.
#[derive(Debug, Clone, Deserialize)]
pub struct ItemInput {
    pub id: Option<String>,
    pub kind: ItemKind,
    pub title: String,
    pub body: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub folder: String,
    #[serde(default)]
    pub pinned: bool,
    #[serde(default)]
    pub sensitive: bool,
    #[serde(default = "default_paste_mode")]
    pub paste_mode: PasteMode,
    #[serde(default)]
    pub trigger: String,
}

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn has_variables(body: &str) -> bool {
    body.contains("{{") && body.contains("}}")
}

pub struct Vault {
    path: PathBuf,
    conn: Option<Connection>,
    key: Option<SecretKey>,
    items: Vec<Item>,
    matcher: Matcher,
}

impl Vault {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            conn: None,
            key: None,
            items: Vec::new(),
            matcher: Matcher::new(Config::DEFAULT),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    pub fn is_unlocked(&self) -> bool {
        self.key.is_some() && self.conn.is_some()
    }

    pub fn item_count(&self) -> usize {
        self.items.len()
    }

    // ---------- lifecycle ----------

    pub fn create(&mut self, password: &[u8]) -> Result<()> {
        if self.exists() {
            return Err(VaultError::AlreadyExists);
        }
        if password.len() < 8 {
            return Err(VaultError::Invalid(
                "master password must be at least 8 characters".into(),
            ));
        }
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let conn = Connection::open(&self.path)?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA secure_delete=ON;
             CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value BLOB NOT NULL);
             CREATE TABLE IF NOT EXISTS items (
               id TEXT PRIMARY KEY,
               blob BLOB NOT NULL,
               updated_at INTEGER NOT NULL
             );",
        )?;

        let kdf = KdfParams::default();
        let salt = crypto::random_bytes::<SALT_LEN>();
        let master = crypto::derive_master_key(password, &salt, kdf)?;
        let vault_key = crypto::random_key();
        let wrapped = crypto::wrap_key(&master, &vault_key)?;

        let tx = conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO meta VALUES ('version', ?1)",
            params![FORMAT_VERSION.to_le_bytes().to_vec()],
        )?;
        tx.execute(
            "INSERT INTO meta VALUES ('kdf', ?1)",
            params![serde_json::to_vec(&kdf).unwrap()],
        )?;
        tx.execute(
            "INSERT INTO meta VALUES ('salt', ?1)",
            params![salt.to_vec()],
        )?;
        tx.execute(
            "INSERT INTO meta VALUES ('wrapped_key', ?1)",
            params![wrapped],
        )?;
        let verifier = crypto::seal(&vault_key, b"verify-v1", b"snippet-vault")?;
        tx.execute(
            "INSERT INTO meta VALUES ('verifier', ?1)",
            params![verifier],
        )?;
        tx.commit()?;

        self.conn = Some(conn);
        self.key = Some(vault_key);
        self.items.clear();
        Ok(())
    }

    fn open_conn(&self) -> Result<Connection> {
        if !self.exists() {
            return Err(VaultError::Missing);
        }
        let conn = Connection::open(&self.path)?;
        conn.execute_batch("PRAGMA secure_delete=ON;")?;
        Ok(conn)
    }

    fn meta(conn: &Connection, k: &str) -> Result<Option<Vec<u8>>> {
        Ok(conn
            .query_row("SELECT value FROM meta WHERE key=?1", params![k], |r| {
                r.get::<_, Vec<u8>>(0)
            })
            .optional()?)
    }

    fn meta_required(conn: &Connection, k: &str) -> Result<Vec<u8>> {
        Self::meta(conn, k)?.ok_or_else(|| VaultError::Corrupt(format!("missing meta {k}")))
    }

    /// Unlock with the master password.
    pub fn unlock(&mut self, password: &[u8]) -> Result<()> {
        let conn = self.open_conn()?;
        let kdf: KdfParams = serde_json::from_slice(&Self::meta_required(&conn, "kdf")?)
            .map_err(|e| VaultError::Corrupt(format!("bad kdf params: {e}")))?;
        let salt = Self::meta_required(&conn, "salt")?;
        let wrapped = Self::meta_required(&conn, "wrapped_key")?;

        let master = crypto::derive_master_key(password, &salt, kdf)?;
        let vault_key =
            crypto::unwrap_key(&master, &wrapped).map_err(|_| VaultError::WrongPassword)?;

        // Older vaults have no verifier; add one so cached-key unlock can be checked.
        if Self::meta(&conn, "verifier")?.is_none() {
            let v = crypto::seal(&vault_key, b"verify-v1", b"snippet-vault")?;
            conn.execute("INSERT INTO meta VALUES ('verifier', ?1)", params![v])?;
        }
        self.finish_unlock(conn, vault_key)
    }

    /// Unlock with the raw 32-byte vault key (from the DPAPI quick-unlock cache).
    pub fn unlock_with_key(&mut self, key_bytes: &[u8]) -> Result<()> {
        if key_bytes.len() != crypto::KEY_LEN {
            return Err(VaultError::Invalid("cached key has the wrong size".into()));
        }
        let conn = self.open_conn()?;
        let mut k = Box::new([0u8; crypto::KEY_LEN]);
        k.copy_from_slice(key_bytes);
        let vault_key: SecretKey = secrecy::SecretBox::new(k);
        let verifier = Self::meta(&conn, "verifier")?.ok_or_else(|| {
            VaultError::Invalid(
                "vault has no verifier yet; unlock with the master password once".into(),
            )
        })?;
        crypto::open(&vault_key, b"verify-v1", &verifier).map_err(|_| VaultError::WrongPassword)?;
        self.finish_unlock(conn, vault_key)
    }

    /// Raw vault key bytes, for wrapping with DPAPI. Zeroized on drop.
    pub fn vault_key_bytes(&self) -> Result<Zeroizing<Vec<u8>>> {
        use secrecy::ExposeSecret;
        Ok(Zeroizing::new(self.key()?.expose_secret().to_vec()))
    }

    fn finish_unlock(&mut self, conn: Connection, vault_key: SecretKey) -> Result<()> {
        // Decrypt everything into memory.
        let mut items = Vec::new();
        {
            let mut stmt = conn.prepare("SELECT id, blob FROM items")?;
            let rows = stmt.query_map([], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
            })?;
            for row in rows {
                let (id, blob) = row?;
                let pt = crypto::open(&vault_key, id.as_bytes(), &blob)
                    .map_err(|_| VaultError::Corrupt(format!("item {id} failed to decrypt")))?;
                let item: Item = serde_json::from_slice(&pt)
                    .map_err(|e| VaultError::Corrupt(format!("item {id} bad json: {e}")))?;
                items.push(item);
            }
        }

        self.conn = Some(conn);
        self.key = Some(vault_key);
        self.items = items;
        Ok(())
    }

    /// Drop keys and plaintext. Safe to call when already locked.
    pub fn lock(&mut self) {
        self.key = None; // SecretBox zeroizes on drop
        for it in self.items.iter_mut() {
            it.body.zeroize();
            it.title.zeroize();
        }
        self.items.clear();
        self.items.shrink_to_fit();
        self.conn = None;
    }

    fn key(&self) -> Result<&SecretKey> {
        self.key.as_ref().ok_or(VaultError::Locked)
    }

    fn conn(&self) -> Result<&Connection> {
        self.conn.as_ref().ok_or(VaultError::Locked)
    }

    // ---------- items ----------

    fn persist(&self, item: &Item) -> Result<()> {
        let json = Zeroizing::new(
            serde_json::to_vec(item).map_err(|e| VaultError::Invalid(e.to_string()))?,
        );
        let blob = crypto::seal(self.key()?, item.id.as_bytes(), &json)?;
        self.conn()?.execute(
            "INSERT INTO items (id, blob, updated_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(id) DO UPDATE SET blob=excluded.blob, updated_at=excluded.updated_at",
            params![item.id, blob, item.updated_at],
        )?;
        Ok(())
    }

    pub fn save(&mut self, input: ItemInput) -> Result<Item> {
        self.key()?;
        let title = input.title.trim().to_string();
        if title.is_empty() {
            return Err(VaultError::Invalid("title is required".into()));
        }
        let tags: Vec<String> = input
            .tags
            .into_iter()
            .map(|t| t.trim().to_lowercase())
            .filter(|t| !t.is_empty())
            .collect();
        let ts = now();
        let sensitive = input.sensitive || input.kind == ItemKind::Secret;
        let trigger = input.trigger.trim().to_string();
        if !trigger.is_empty() {
            let n = trigger.chars().count();
            if !(2..=32).contains(&n) || trigger.contains(char::is_whitespace) {
                return Err(VaultError::Invalid(
                    "trigger must be 2 to 32 characters with no spaces".into(),
                ));
            }
            let clash = self
                .items
                .iter()
                .any(|i| i.trigger == trigger && input.id.as_deref() != Some(i.id.as_str()));
            if clash {
                return Err(VaultError::Invalid(format!(
                    "another item already uses the trigger {trigger}"
                )));
            }
        }
        let paste_mode = if sensitive && input.paste_mode == PasteMode::Type {
            PasteMode::Paste // never keystroke-inject secrets
        } else {
            input.paste_mode
        };

        let existing_idx = input
            .id
            .as_deref()
            .and_then(|id| self.items.iter().position(|i| i.id == id));

        let item = match existing_idx {
            Some(idx) => {
                let existing = &mut self.items[idx];
                existing.kind = input.kind;
                existing.title = title;
                existing.body = input.body;
                existing.tags = tags;
                existing.folder = input.folder.trim().to_string();
                existing.pinned = input.pinned;
                existing.sensitive = sensitive;
                existing.paste_mode = paste_mode;
                existing.trigger = trigger;
                existing.updated_at = ts;
                existing.clone()
            }
            None => {
                let item = Item {
                    id: uuid::Uuid::new_v4().to_string(),
                    kind: input.kind,
                    title,
                    body: input.body,
                    tags,
                    folder: input.folder.trim().to_string(),
                    pinned: input.pinned,
                    sensitive,
                    paste_mode,
                    trigger,
                    use_count: 0,
                    last_used: 0,
                    created_at: ts,
                    updated_at: ts,
                };
                self.items.push(item.clone());
                item
            }
        };
        self.persist(&item)?;
        Ok(item)
    }

    pub fn get(&self, id: &str) -> Result<&Item> {
        self.key()?;
        self.items
            .iter()
            .find(|i| i.id == id)
            .ok_or(VaultError::NotFound)
    }

    pub fn delete(&mut self, id: &str) -> Result<()> {
        self.key()?;
        let idx = self
            .items
            .iter()
            .position(|i| i.id == id)
            .ok_or(VaultError::NotFound)?;
        self.conn()?
            .execute("DELETE FROM items WHERE id=?1", params![id])?;
        let mut removed = self.items.remove(idx);
        removed.body.zeroize();
        Ok(())
    }

    pub fn set_pinned(&mut self, id: &str, pinned: bool) -> Result<()> {
        self.key()?;
        let item = self
            .items
            .iter_mut()
            .find(|i| i.id == id)
            .ok_or(VaultError::NotFound)?;
        item.pinned = pinned;
        item.updated_at = now();
        let snapshot = item.clone();
        self.persist(&snapshot)
    }

    pub fn touch_used(&mut self, id: &str) -> Result<()> {
        self.key()?;
        let item = self
            .items
            .iter_mut()
            .find(|i| i.id == id)
            .ok_or(VaultError::NotFound)?;
        item.use_count += 1;
        item.last_used = now();
        let snapshot = item.clone();
        self.persist(&snapshot)
    }

    /// (trigger, id) for every item with a trigger. Empty when locked.
    pub fn triggers(&self) -> Vec<(String, String)> {
        if !self.is_unlocked() {
            return Vec::new();
        }
        self.items
            .iter()
            .filter(|i| !i.trigger.is_empty() && i.kind != ItemKind::Clip)
            .map(|i| (i.trigger.clone(), i.id.clone()))
            .collect()
    }

    // ---------- clipboard history ----------

    /// Record a copied text. Same text already in history: move it to the top.
    /// Returns true when a new clip was created.
    pub fn add_clip(
        &mut self,
        text: String,
        source_app: String,
        sensitive: bool,
        max_items: usize,
    ) -> Result<bool> {
        self.key()?;
        let ts = now();
        if let Some(idx) = self
            .items
            .iter()
            .position(|i| i.kind == ItemKind::Clip && i.body == text)
        {
            let mut it = self.items.remove(idx);
            it.created_at = ts;
            it.updated_at = ts;
            it.last_used = ts;
            if !source_app.is_empty() {
                it.folder = source_app;
            }
            self.persist(&it)?;
            self.items.push(it);
            return Ok(false);
        }
        let first_line = text
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty())
            .unwrap_or("");
        let mut title: String = first_line.chars().take(80).collect();
        if title.is_empty() {
            title = "(blank)".into();
        }
        let item = Item {
            id: uuid::Uuid::new_v4().to_string(),
            kind: ItemKind::Clip,
            title,
            body: text,
            tags: Vec::new(),
            folder: source_app,
            pinned: false,
            sensitive,
            paste_mode: PasteMode::Paste,
            trigger: String::new(),
            use_count: 0,
            last_used: ts,
            created_at: ts,
            updated_at: ts,
        };
        self.persist(&item)?;
        self.items.push(item);
        self.trim_clips(max_items)?;
        Ok(true)
    }

    fn trim_clips(&mut self, max_items: usize) -> Result<()> {
        let mut clips: Vec<(i64, usize, String)> = self
            .items
            .iter()
            .enumerate()
            .filter(|(_, i)| i.kind == ItemKind::Clip && !i.pinned)
            .map(|(pos, i)| (i.created_at, pos, i.id.clone()))
            .collect();
        if clips.len() <= max_items {
            return Ok(());
        }
        clips.sort();
        let excess = clips.len() - max_items;
        for (_, _, id) in clips.into_iter().take(excess) {
            self.delete(&id)?;
        }
        Ok(())
    }

    /// Delete all unpinned clips. Returns how many were removed.
    pub fn clear_clips(&mut self) -> Result<usize> {
        self.key()?;
        let ids: Vec<String> = self
            .items
            .iter()
            .filter(|i| i.kind == ItemKind::Clip && !i.pinned)
            .map(|i| i.id.clone())
            .collect();
        for id in &ids {
            self.delete(id)?;
        }
        Ok(ids.len())
    }

    // ---------- backup ----------

    pub fn export_items(&self) -> Result<Vec<Item>> {
        self.key()?;
        Ok(self.items.clone())
    }

    /// Merge items in. Same id: keep whichever was updated last. Returns
    /// (added, updated, skipped).
    pub fn import_items(&mut self, incoming: Vec<Item>) -> Result<(usize, usize, usize)> {
        self.key()?;
        let (mut added, mut updated, mut skipped) = (0, 0, 0);
        for mut it in incoming {
            if it.title.trim().is_empty() {
                skipped += 1;
                continue;
            }
            if it.id.trim().is_empty() {
                it.id = uuid::Uuid::new_v4().to_string();
            }
            if it.kind == ItemKind::Secret {
                it.sensitive = true;
            }
            match self.items.iter().position(|x| x.id == it.id) {
                Some(idx) if self.items[idx].updated_at >= it.updated_at => skipped += 1,
                Some(idx) => {
                    self.items[idx] = it.clone();
                    self.persist(&it)?;
                    updated += 1;
                }
                None => {
                    self.persist(&it)?;
                    self.items.push(it);
                    added += 1;
                }
            }
        }
        Ok((added, updated, skipped))
    }

    // ---------- search ----------

    pub fn search(
        &mut self,
        query: &str,
        kind: Option<ItemKind>,
        limit: usize,
    ) -> Result<Vec<ItemSummary>> {
        self.key()?;
        let q = query.trim();
        // With no kind filter, clips stay out of the way (they have their own tab).
        let matches_kind = |i: &Item| match kind {
            Some(k) => i.kind == k,
            None => i.kind != ItemKind::Clip,
        };
        let mut scored: Vec<(u32, &Item)> = Vec::new();

        if q.is_empty() {
            for (pos, it) in self
                .items
                .iter()
                .enumerate()
                .filter(|(_, i)| matches_kind(i))
            {
                scored.push((pos as u32, it));
            }
            // Ties (same second) fall back to position: later in the list = newer.
            scored.sort_by(|a, b| {
                b.1.pinned
                    .cmp(&a.1.pinned)
                    .then(b.1.last_used.cmp(&a.1.last_used))
                    .then(b.1.updated_at.cmp(&a.1.updated_at))
                    .then(b.0.cmp(&a.0))
            });
        } else {
            let pattern = Pattern::parse(q, CaseMatching::Ignore, Normalization::Smart);
            let mut buf = Vec::new();
            for it in self.items.iter().filter(|i| matches_kind(i)) {
                let mut best: Option<u32> = None;
                let title_hay = format!("{} {} {}", it.title, it.tags.join(" "), it.folder);
                if let Some(s) =
                    pattern.score(Utf32Str::new(&title_hay, &mut buf), &mut self.matcher)
                {
                    best = Some(s.saturating_mul(3));
                }
                if !it.sensitive {
                    let body_snip: String = it.body.chars().take(600).collect();
                    if let Some(s) =
                        pattern.score(Utf32Str::new(&body_snip, &mut buf), &mut self.matcher)
                    {
                        best = Some(best.map_or(s, |b| b.max(s)));
                    }
                }
                if let Some(score) = best {
                    // light frecency boost
                    let boost = (it.use_count.min(50) as u32) * 2 + if it.pinned { 40 } else { 0 };
                    scored.push((score + boost, it));
                }
            }
            scored.sort_by(|a, b| b.0.cmp(&a.0).then(b.1.last_used.cmp(&a.1.last_used)));
        }

        Ok(scored
            .into_iter()
            .take(limit)
            .map(|(_, it)| summarize(it))
            .collect())
    }

    pub fn folders_and_tags(&self) -> Result<(Vec<String>, Vec<String>)> {
        self.key()?;
        let mut folders: Vec<String> = self
            .items
            .iter()
            .map(|i| i.folder.clone())
            .filter(|f| !f.is_empty())
            .collect();
        let mut tags: Vec<String> = self.items.iter().flat_map(|i| i.tags.clone()).collect();
        folders.sort();
        folders.dedup();
        tags.sort();
        tags.dedup();
        Ok((folders, tags))
    }
}

fn summarize(it: &Item) -> ItemSummary {
    let preview = if it.sensitive {
        "••••••••".to_string()
    } else {
        let one_line: String = it.body.split_whitespace().collect::<Vec<_>>().join(" ");
        one_line.chars().take(120).collect()
    };
    ItemSummary {
        id: it.id.clone(),
        kind: it.kind,
        title: it.title.clone(),
        preview,
        tags: it.tags.clone(),
        folder: it.folder.clone(),
        pinned: it.pinned,
        sensitive: it.sensitive,
        paste_mode: it.paste_mode,
        trigger: it.trigger.clone(),
        use_count: it.use_count,
        last_used: it.last_used,
        has_variables: has_variables(&it.body),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDirGuard(std::path::PathBuf);
    impl Drop for TempDirGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn tmp_vault() -> (Vault, TempDirGuard) {
        let dir = std::env::temp_dir().join(format!("sv-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        (Vault::new(dir.join("vault.db")), TempDirGuard(dir))
    }

    fn input(title: &str, body: &str, kind: ItemKind) -> ItemInput {
        ItemInput {
            id: None,
            kind,
            title: title.into(),
            body: body.into(),
            tags: vec!["Work".into()],
            folder: "".into(),
            pinned: false,
            sensitive: false,
            paste_mode: PasteMode::Paste,
            trigger: String::new(),
        }
    }

    #[test]
    fn create_save_lock_unlock_roundtrip() {
        let (mut v, _g) = tmp_vault();
        v.create(b"correct horse battery").unwrap();
        let a = v
            .save(input("Gmail password", "hunter22", ItemKind::Secret))
            .unwrap();
        v.save(input(
            "Claude summarizer",
            "Summarize {{text}} in 3 bullets",
            ItemKind::Prompt,
        ))
        .unwrap();
        assert!(a.sensitive, "secrets are always sensitive");
        v.lock();
        assert!(!v.is_unlocked());
        assert!(matches!(
            v.unlock(b"wrong password!").unwrap_err(),
            VaultError::WrongPassword
        ));
        v.unlock(b"correct horse battery").unwrap();
        assert_eq!(v.item_count(), 2);
        let got = v.get(&a.id).unwrap();
        assert_eq!(got.body, "hunter22");
        assert_eq!(got.tags, vec!["work"]);

        let res = v.search("claude", None, 10).unwrap();
        assert_eq!(res.len(), 1);
        assert!(res[0].has_variables);
        let res = v.search("hunter", None, 10).unwrap();
        assert!(res.is_empty(), "sensitive bodies are not searchable");
        let res = v.search("", Some(ItemKind::Secret), 10).unwrap();
        assert_eq!(res[0].preview, "••••••••");

        v.delete(&a.id).unwrap();
        assert_eq!(v.item_count(), 1);
    }

    #[test]
    fn cached_key_unlock_roundtrip() {
        let (mut v, _g) = tmp_vault();
        v.create(b"password-123").unwrap();
        v.save(input("Note", "hello", ItemKind::Text)).unwrap();
        let key = v.vault_key_bytes().unwrap();
        v.lock();
        let mut wrong = key.clone();
        wrong[0] ^= 0xff;
        assert!(matches!(
            v.unlock_with_key(&wrong).unwrap_err(),
            VaultError::WrongPassword
        ));
        assert!(v.unlock_with_key(&key[..5]).is_err());
        v.unlock_with_key(&key).unwrap();
        assert_eq!(v.item_count(), 1);
        assert_eq!(v.search("hello", None, 5).unwrap().len(), 1);
    }

    #[test]
    fn clips_dedupe_trim_and_stay_out_of_all() {
        let (mut v, _g) = tmp_vault();
        v.create(b"password-123").unwrap();
        v.save(input("Snippet", "keep me", ItemKind::Text)).unwrap();
        assert!(v.add_clip("one".into(), "a.exe".into(), false, 3).unwrap());
        assert!(v.add_clip("two".into(), "a.exe".into(), false, 3).unwrap());
        assert!(v
            .add_clip("three".into(), "a.exe".into(), false, 3)
            .unwrap());
        assert!(
            !v.add_clip("one".into(), "b.exe".into(), false, 3).unwrap(),
            "dedupe"
        );
        assert!(v.add_clip("four".into(), "a.exe".into(), true, 3).unwrap());
        let clips = v.search("", Some(ItemKind::Clip), 50).unwrap();
        assert_eq!(clips.len(), 3, "trimmed to max");
        assert_eq!(clips[0].title, "four");
        assert!(clips[0].sensitive);
        assert!(!clips.iter().any(|c| c.title == "two"), "oldest dropped");
        let all = v.search("", None, 50).unwrap();
        assert_eq!(all.len(), 1, "All hides clips");
        assert_eq!(v.clear_clips().unwrap(), 3);
        assert_eq!(v.item_count(), 1);
    }

    #[test]
    fn triggers_validate_and_list() {
        let (mut v, _g) = tmp_vault();
        v.create(b"password-123").unwrap();
        let mut a = input("Sig", "Regards, J", ItemKind::Text);
        a.trigger = ";sig".into();
        let saved = v.save(a).unwrap();
        assert_eq!(v.triggers(), vec![(";sig".to_string(), saved.id.clone())]);
        let mut dup = input("Other", "x", ItemKind::Text);
        dup.trigger = ";sig".into();
        assert!(v.save(dup).is_err(), "duplicate trigger rejected");
        let mut bad = input("Bad", "x", ItemKind::Text);
        bad.trigger = "a b".into();
        assert!(v.save(bad).is_err(), "whitespace rejected");
        v.lock();
        assert!(v.triggers().is_empty());
    }

    #[test]
    fn ciphertext_on_disk_has_no_plaintext() {
        let (mut v, _g) = tmp_vault();
        v.create(b"password-123").unwrap();
        v.save(input("Needle title", "needle-body-xyz", ItemKind::Text))
            .unwrap();
        let path = v.path().to_path_buf();
        v.lock();
        let bytes = std::fs::read(&path).unwrap();
        let hay = String::from_utf8_lossy(&bytes);
        assert!(!hay.contains("needle-body-xyz"));
        assert!(!hay.contains("Needle title"));
    }
}
