//! Per-salt decryption key cache for restore/prune/manifest reads.
//!
//! `crypto::decrypt_data` runs 600k PBKDF2 iterations for *every* blob,
//! which makes restoring many files extremely slow. Blobs written by one
//! backup session share the same salt (`EncryptionKey` is derived once per
//! session), so caching the derived key per salt removes almost all KDF work.
//!
//! The blob format and KDF parameters below mirror `crypto::EncryptionKey`
//! / `crypto::decrypt_data` exactly:
//! `salt(16) || nonce(12) || ciphertext || tag(16)`, PBKDF2-HMAC-SHA256,
//! 600_000 iterations, AES-256-GCM, empty AAD.
//!
//! TODO(crypto): once `crypto/` exposes a key-cache / `decrypt_with_key`
//! API, replace the local ring calls here with it so the format lives in a
//! single place.

use ring::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use ring::pbkdf2;
use std::collections::HashMap;
use std::io::{self, ErrorKind};
use std::num::NonZeroU32;
use std::sync::{Arc, Mutex};
use zeroize::{Zeroize, Zeroizing};

const SALT_LEN: usize = 16;
const TAG_LEN: usize = 16;
const PBKDF2_ITERATIONS: u32 = 600_000;

/// Caches one derived AES key per salt for a given password.
pub struct DecryptionKeyCache {
    password: Zeroizing<Vec<u8>>,
    keys: Mutex<HashMap<[u8; SALT_LEN], Arc<LessSafeKey>>>,
}

impl DecryptionKeyCache {
    pub fn new(password: &[u8]) -> Self {
        Self {
            password: Zeroizing::new(password.to_vec()),
            keys: Mutex::new(HashMap::new()),
        }
    }

    fn key_for_salt(&self, salt: &[u8; SALT_LEN]) -> io::Result<Arc<LessSafeKey>> {
        if let Some(k) = self.keys.lock().unwrap_or_else(|p| p.into_inner()).get(salt) {
            return Ok(k.clone());
        }
        let mut derived = [0u8; 32];
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            NonZeroU32::new(PBKDF2_ITERATIONS).expect("non-zero"),
            salt,
            &self.password,
            &mut derived,
        );
        let unbound = UnboundKey::new(&AES_256_GCM, &derived);
        derived.zeroize();
        let key = Arc::new(LessSafeKey::new(unbound.map_err(|_| {
            io::Error::new(ErrorKind::InvalidInput, "Failed to create decryption key")
        })?));
        self.keys
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(*salt, key.clone());
        Ok(key)
    }

    /// Decrypts a blob produced by `crypto::EncryptionKey::encrypt` /
    /// `crypto::encrypt_data`, deriving the key at most once per salt.
    pub fn decrypt(&self, encrypted: &[u8]) -> io::Result<Vec<u8>> {
        let min_len = SALT_LEN + NONCE_LEN + TAG_LEN;
        if encrypted.len() < min_len {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                format!(
                    "Invalid encrypted data size: {} bytes (minimum: {})",
                    encrypted.len(),
                    min_len
                ),
            ));
        }
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&encrypted[..SALT_LEN]);
        let mut nonce_arr = [0u8; NONCE_LEN];
        nonce_arr.copy_from_slice(&encrypted[SALT_LEN..SALT_LEN + NONCE_LEN]);

        let key = self.key_for_salt(&salt)?;
        let mut in_out = encrypted[SALT_LEN + NONCE_LEN..].to_vec();
        let plain_len = key
            .open_in_place(Nonce::assume_unique_for_key(nonce_arr), Aad::empty(), &mut in_out)
            .map_err(|_| {
                io::Error::new(
                    ErrorKind::InvalidData,
                    "Decryption failed: wrong password, corrupted data or invalid format",
                )
            })?
            .len();
        in_out.truncate(plain_len);
        Ok(in_out)
    }

    /// Number of distinct derived keys (for tests/diagnostics).
    pub fn derived_keys(&self) -> usize {
        self.keys.lock().unwrap_or_else(|p| p.into_inner()).len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{EncryptionKey, encrypt_data_with_key};

    #[test]
    fn decrypts_crypto_blobs_and_derives_once_per_salt() {
        let key = EncryptionKey::new(b"pw").unwrap();
        let a = encrypt_data_with_key(b"alpha", &key).unwrap();
        let b = encrypt_data_with_key(b"beta", &key).unwrap();
        let cache = DecryptionKeyCache::new(b"pw");
        assert_eq!(cache.decrypt(&a).unwrap(), b"alpha");
        assert_eq!(cache.decrypt(&b).unwrap(), b"beta");
        assert_eq!(cache.derived_keys(), 1);
        let wrong = DecryptionKeyCache::new(b"nope");
        assert!(wrong.decrypt(&a).is_err());
    }
}
