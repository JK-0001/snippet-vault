//! All cryptography lives here. Nothing in the webview ever touches keys.
//!
//! Design (see PLAN.md):
//!   master key  = Argon2id(password, salt, params)            -> 32 bytes
//!   vault key   = random 32 bytes, stored wrapped:
//!                 XChaCha20-Poly1305(master key, aad="wrap-v1", vault key)
//!   each record = XChaCha20-Poly1305(vault key, aad=item id, json)
//! Blobs are `nonce(24) || ciphertext+tag`.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{rand_core::RngCore, Aead, KeyInit, OsRng, Payload},
    XChaCha20Poly1305, XNonce,
};
use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const KEY_LEN: usize = 32;
pub const SALT_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;

/// A 32-byte key that is zeroized on drop and never printed.
pub type SecretKey = SecretBox<[u8; KEY_LEN]>;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("key derivation failed")]
    Kdf,
    #[error("decryption failed (wrong password or corrupted data)")]
    Open,
    #[error("encryption failed")]
    Seal,
    #[error("malformed ciphertext")]
    Malformed,
}

/// Argon2id cost parameters, stored in the vault header so they can be raised later.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct KdfParams {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Default for KdfParams {
    /// 64 MiB, 3 passes, 4 lanes: same class as KeePassXC / Bitwarden defaults.
    fn default() -> Self {
        Self {
            m_cost_kib: 64 * 1024,
            t_cost: 3,
            p_cost: 4,
        }
    }
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    OsRng.fill_bytes(&mut out);
    out
}

pub fn random_key() -> SecretKey {
    SecretBox::new(Box::new(random_bytes::<KEY_LEN>()))
}

pub fn derive_master_key(
    password: &[u8],
    salt: &[u8],
    params: KdfParams,
) -> Result<SecretKey, CryptoError> {
    let p = Params::new(
        params.m_cost_kib,
        params.t_cost,
        params.p_cost,
        Some(KEY_LEN),
    )
    .map_err(|_| CryptoError::Kdf)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
    let mut out = Box::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(password, salt, out.as_mut_slice())
        .map_err(|_| CryptoError::Kdf)?;
    Ok(SecretBox::new(out))
}

/// Encrypt `plaintext` under `key`, binding `aad`. Output: nonce || ciphertext.
pub fn seal(key: &SecretKey, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(key.expose_secret().into());
    let nonce_bytes = random_bytes::<NONCE_LEN>();
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Seal)?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Inverse of [`seal`]. The returned buffer is zeroized on drop.
pub fn open(key: &SecretKey, aad: &[u8], blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if blob.len() < NONCE_LEN + 16 {
        return Err(CryptoError::Malformed);
    }
    let (nonce_bytes, ct) = blob.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new(key.expose_secret().into());
    let pt = cipher
        .decrypt(XNonce::from_slice(nonce_bytes), Payload { msg: ct, aad })
        .map_err(|_| CryptoError::Open)?;
    Ok(Zeroizing::new(pt))
}

/// Wrap the vault key under the master key.
pub fn wrap_key(master: &SecretKey, vault_key: &SecretKey) -> Result<Vec<u8>, CryptoError> {
    seal(master, b"wrap-v1", vault_key.expose_secret())
}

pub fn unwrap_key(master: &SecretKey, wrapped: &[u8]) -> Result<SecretKey, CryptoError> {
    let pt = open(master, b"wrap-v1", wrapped)?;
    if pt.len() != KEY_LEN {
        return Err(CryptoError::Malformed);
    }
    let mut k = Box::new([0u8; KEY_LEN]);
    k.copy_from_slice(&pt);
    Ok(SecretBox::new(k))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fast() -> KdfParams {
        KdfParams {
            m_cost_kib: 1024,
            t_cost: 1,
            p_cost: 1,
        }
    }

    #[test]
    fn roundtrip_seal_open() {
        let k = random_key();
        let blob = seal(&k, b"id-1", b"hello").unwrap();
        assert_eq!(open(&k, b"id-1", &blob).unwrap().as_slice(), b"hello");
    }

    #[test]
    fn wrong_aad_fails() {
        let k = random_key();
        let blob = seal(&k, b"id-1", b"hello").unwrap();
        assert!(open(&k, b"id-2", &blob).is_err());
    }

    #[test]
    fn tampering_fails() {
        let k = random_key();
        let mut blob = seal(&k, b"x", b"hello").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 1;
        assert!(open(&k, b"x", &blob).is_err());
    }

    #[test]
    fn kdf_is_deterministic_and_wrap_roundtrips() {
        let salt = random_bytes::<SALT_LEN>();
        let m1 = derive_master_key(b"pw", &salt, fast()).unwrap();
        let m2 = derive_master_key(b"pw", &salt, fast()).unwrap();
        assert_eq!(m1.expose_secret(), m2.expose_secret());
        let vk = random_key();
        let wrapped = wrap_key(&m1, &vk).unwrap();
        let back = unwrap_key(&m2, &wrapped).unwrap();
        assert_eq!(back.expose_secret(), vk.expose_secret());
        let bad = derive_master_key(b"pw2", &salt, fast()).unwrap();
        assert!(unwrap_key(&bad, &wrapped).is_err());
    }
}
