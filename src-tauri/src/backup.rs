//! Backup files.
//!
//! `.svault` (encrypted): JSON envelope with Argon2id params + salt, and the
//! item list sealed with XChaCha20-Poly1305 under a password the user picks.
//! `.json` (plain): readable by anyone; only offered behind a warning.

use crate::crypto::{self, KdfParams, SALT_LEN};
use crate::vault::{now, Item};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const ENCRYPTED_FORMAT: &str = "snippet-vault-backup";
pub const PLAIN_FORMAT: &str = "snippet-vault-export";

#[derive(Debug, thiserror::Error)]
pub enum BackupError {
    #[error("this is not a Snippet Vault backup file")]
    NotABackup,
    #[error("wrong backup password (or the file is damaged)")]
    WrongPassword,
    #[error("backup password must be at least 8 characters")]
    WeakPassword,
    #[error("{0}")]
    Crypto(#[from] crypto::CryptoError),
    #[error("could not read backup: {0}")]
    Parse(String),
}

#[derive(Serialize, Deserialize)]
struct EncryptedEnvelope {
    format: String,
    version: u32,
    created_at: i64,
    kdf: KdfParams,
    salt: String,
    blob: String,
}

#[derive(Serialize, Deserialize)]
struct PlainEnvelope {
    format: String,
    version: u32,
    exported_at: i64,
    items: Vec<Item>,
}

pub fn encrypt(items: &[Item], password: &[u8]) -> Result<Vec<u8>, BackupError> {
    if password.len() < 8 {
        return Err(BackupError::WeakPassword);
    }
    let kdf = KdfParams::default();
    let salt = crypto::random_bytes::<SALT_LEN>();
    let key = crypto::derive_master_key(password, &salt, kdf)?;
    let json = Zeroizing::new(serde_json::to_vec(items).map_err(|e| BackupError::Parse(e.to_string()))?);
    let blob = crypto::seal(&key, b"backup-v1", &json)?;
    let env = EncryptedEnvelope {
        format: ENCRYPTED_FORMAT.into(),
        version: 1,
        created_at: now(),
        kdf,
        salt: B64.encode(salt),
        blob: B64.encode(blob),
    };
    serde_json::to_vec_pretty(&env).map_err(|e| BackupError::Parse(e.to_string()))
}

pub fn decrypt(bytes: &[u8], password: &[u8]) -> Result<Vec<Item>, BackupError> {
    let env: EncryptedEnvelope =
        serde_json::from_slice(bytes).map_err(|_| BackupError::NotABackup)?;
    if env.format != ENCRYPTED_FORMAT {
        return Err(BackupError::NotABackup);
    }
    let salt = B64.decode(env.salt).map_err(|e| BackupError::Parse(e.to_string()))?;
    let blob = B64.decode(env.blob).map_err(|e| BackupError::Parse(e.to_string()))?;
    let key = crypto::derive_master_key(password, &salt, env.kdf)?;
    let json = crypto::open(&key, b"backup-v1", &blob).map_err(|_| BackupError::WrongPassword)?;
    serde_json::from_slice(&json).map_err(|e| BackupError::Parse(e.to_string()))
}

pub fn to_plain_json(items: &[Item]) -> Result<Vec<u8>, BackupError> {
    let env = PlainEnvelope {
        format: PLAIN_FORMAT.into(),
        version: 1,
        exported_at: now(),
        items: items.to_vec(),
    };
    serde_json::to_vec_pretty(&env).map_err(|e| BackupError::Parse(e.to_string()))
}

pub fn from_plain_json(bytes: &[u8]) -> Result<Vec<Item>, BackupError> {
    // Accept our envelope or a bare array of items.
    if let Ok(env) = serde_json::from_slice::<PlainEnvelope>(bytes) {
        if env.format == PLAIN_FORMAT {
            return Ok(env.items);
        }
    }
    serde_json::from_slice::<Vec<Item>>(bytes).map_err(|_| BackupError::NotABackup)
}

/// True if the file looks like an encrypted `.svault` envelope.
pub fn is_encrypted(bytes: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(bytes)
        .ok()
        .and_then(|v| v.get("format").and_then(|f| f.as_str()).map(|f| f == ENCRYPTED_FORMAT))
        .unwrap_or(false)
}

/// `YYYY-MM-DD` for file names, without pulling in a date crate.
pub fn today_stamp() -> String {
    let secs = now();
    let days = secs.div_euclid(86_400);
    // Howard Hinnant's civil-from-days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{ItemKind, PasteMode};

    fn item(title: &str) -> Item {
        Item {
            id: uuid::Uuid::new_v4().to_string(),
            kind: ItemKind::Text,
            title: title.into(),
            body: "body".into(),
            tags: vec![],
            folder: String::new(),
            pinned: false,
            sensitive: false,
            paste_mode: PasteMode::Paste,
            use_count: 0,
            last_used: 0,
            created_at: 1,
            updated_at: 1,
        }
    }

    #[test]
    fn encrypted_roundtrip_and_wrong_password() {
        let items = vec![item("a"), item("b")];
        let bytes = encrypt(&items, b"backup-pass-1").unwrap();
        assert!(is_encrypted(&bytes));
        assert!(!String::from_utf8_lossy(&bytes).contains("\"title\""));
        let back = decrypt(&bytes, b"backup-pass-1").unwrap();
        assert_eq!(back.len(), 2);
        assert!(matches!(decrypt(&bytes, b"nope-nope-nope").unwrap_err(), BackupError::WrongPassword));
        assert!(matches!(encrypt(&items, b"short").unwrap_err(), BackupError::WeakPassword));
    }

    #[test]
    fn plain_roundtrip() {
        let items = vec![item("x")];
        let bytes = to_plain_json(&items).unwrap();
        assert!(!is_encrypted(&bytes));
        assert_eq!(from_plain_json(&bytes).unwrap()[0].title, "x");
        assert!(from_plain_json(b"{\"hello\":1}").is_err());
    }

    #[test]
    fn date_stamp_shape() {
        let s = today_stamp();
        assert_eq!(s.len(), 10);
        assert_eq!(&s[4..5], "-");
    }
}
