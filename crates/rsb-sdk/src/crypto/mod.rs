// src/crypto/mod.rs
//
// Encrypted blob formats
// ----------------------
// * Legacy (v1, no header):
//     salt(16) | nonce(12) | ciphertext | tag(16)
//   PBKDF2-HMAC-SHA256 with `LEGACY_PBKDF2_ITERATIONS`, empty AAD.
// * Versioned (v2, written by this version):
//     magic "RSBENCv2"(8) | iterations u32 BE (4) | salt(16) | nonce(12) | ciphertext | tag(16)
//   The 12-byte header (magic + iterations) is authenticated as AAD.
//
// Readers accept both formats. A legacy blob starts with a random salt, so it
// is misdetected as v2 only if that salt starts with the 8-byte magic AND the
// next 4 bytes fall in the accepted iteration range (probability < 2^-64).
// We deliberately do not retry as legacy on failure, so a wrong password costs
// a single PBKDF2 run.

use ring::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use ring::pbkdf2;
use ring::rand::{SecureRandom, SystemRandom};
use std::collections::HashMap;
use std::fmt;
use std::io::{self, ErrorKind};
use std::num::NonZeroU32;
use std::sync::{Arc, Mutex};
use tracing::{debug, error, warn};
use zeroize::Zeroizing;

const SALT_LEN: usize = 16;
const TAG_LEN: usize = 16;

/// Magic marker for the versioned (v2) blob format.
pub const BLOB_MAGIC_V2: &[u8; 8] = b"RSBENCv2";
/// Header length of a v2 blob: magic(8) + iterations(4).
const V2_HEADER_LEN: usize = 8 + 4;

/// PBKDF2 iterations used for new blobs.
pub const PBKDF2_ITERATIONS: u32 = 600_000;
/// PBKDF2 iterations used by legacy (header-less) blobs.
pub const LEGACY_PBKDF2_ITERATIONS: u32 = 600_000;
/// Bounds accepted from a v2 header (protects against DoS via huge counts).
const MIN_PBKDF2_ITERATIONS: u32 = 100_000;
const MAX_PBKDF2_ITERATIONS: u32 = 10_000_000;

/// Typed crypto errors. They are wrapped in `io::Error` (kind `InvalidData`)
/// so existing `io::Result` signatures are unchanged; use
/// [`is_authentication_error`] to detect them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    /// AEAD tag verification failed: wrong password/key or tampered data.
    AuthenticationFailed,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // Keep the words "authentication" and "tag": callers (e.g.
            // core/manifest.rs) match on them to report a wrong password.
            CryptoError::AuthenticationFailed => write!(
                f,
                "Decryption failed: authentication tag mismatch (wrong password or tampered data)"
            ),
        }
    }
}

impl std::error::Error for CryptoError {}

impl From<CryptoError> for io::Error {
    fn from(e: CryptoError) -> Self {
        io::Error::new(ErrorKind::InvalidData, e)
    }
}

/// Returns true if `err` is an AEAD authentication failure (wrong password
/// or tampered data), as opposed to a format/size error.
pub fn is_authentication_error(err: &io::Error) -> bool {
    err.get_ref()
        .and_then(|inner| inner.downcast_ref::<CryptoError>())
        .is_some_and(|e| *e == CryptoError::AuthenticationFailed)
}

/// Derive an AES-256-GCM key with PBKDF2-HMAC-SHA256.
/// The intermediate key bytes are wiped on every path (Zeroizing).
fn derive_key(password: &[u8], salt: &[u8], iterations: u32) -> io::Result<LessSafeKey> {
    let iterations = NonZeroU32::new(iterations)
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidInput, "PBKDF2 iterations must be > 0"))?;
    let mut derived_key = Zeroizing::new([0u8; 32]);
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        iterations,
        salt,
        password,
        &mut derived_key[..],
    );
    let unbound_key = UnboundKey::new(&AES_256_GCM, &derived_key[..])
        .map_err(|_| io::Error::new(ErrorKind::InvalidInput, "Failed to create encryption key"))?;
    Ok(LessSafeKey::new(unbound_key))
}

/// Cached encryption key - derived only once per backup session
#[derive(Clone)]
pub struct EncryptionKey {
    key: LessSafeKey,
    salt: [u8; 16],
}

impl Drop for EncryptionKey {
    fn drop(&mut self) {
        // LessSafeKey não expõe zeroize; limpamos o salt e deixamos o resto
        // sair de escopo. O segredo principal (password) deve ser envolto em
        // SecureString/zeroize no chamador — ver credentials_manager.
        use zeroize::Zeroize;
        self.salt.zeroize();
    }
}

impl EncryptionKey {
    /// Derive the encryption key **only once** from the password
    pub fn new(password: &[u8]) -> io::Result<Self> {
        let rand = SystemRandom::new();

        let mut salt = [0u8; 16];
        rand.fill(&mut salt)
            .map_err(|_| io::Error::other("Failed to generate salt"))?;

        let key = derive_key(password, &salt, PBKDF2_ITERATIONS)?;

        debug!("🔑 Encryption key derived successfully (PBKDF2 executed only once)");

        Ok(EncryptionKey { key, salt })
    }

    /// Encrypt data using the pre-derived key (very fast).
    /// Output is the versioned v2 format (see module docs).
    pub fn encrypt(&self, data: &[u8]) -> io::Result<Vec<u8>> {
        let rand = SystemRandom::new();

        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand.fill(&mut nonce_bytes)
            .map_err(|_| io::Error::other("Failed to generate nonce"))?;

        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        let mut header = [0u8; V2_HEADER_LEN];
        header[..8].copy_from_slice(BLOB_MAGIC_V2);
        header[8..].copy_from_slice(&PBKDF2_ITERATIONS.to_be_bytes());

        let mut result =
            Vec::with_capacity(V2_HEADER_LEN + SALT_LEN + NONCE_LEN + data.len() + TAG_LEN);
        result.extend_from_slice(&header);
        result.extend_from_slice(&self.salt);
        result.extend_from_slice(&nonce_bytes);
        let body_start = result.len();
        result.extend_from_slice(data);

        let tag = self
            .key
            .seal_in_place_separate_tag(nonce, Aad::from(&header[..]), &mut result[body_start..])
            .map_err(|e| io::Error::other(format!("Encryption failed: {:?}", e)))?;
        result.extend_from_slice(tag.as_ref());

        Ok(result)
    }
}

/// Legacy function - kept for backward compatibility (slow)
pub fn encrypt_data(data: &[u8], password: &[u8]) -> io::Result<Vec<u8>> {
    warn!(
        "Using legacy encrypt_data (per-file key derivation). Use EncryptionKey for better performance."
    );
    let key = EncryptionKey::new(password)?;
    key.encrypt(data)
}

/// Optimized: Encrypt data with pre-derived key (reuse for multiple files)
pub fn encrypt_data_with_key(data: &[u8], key: &EncryptionKey) -> io::Result<Vec<u8>> {
    key.encrypt(data)
}

/// Parsed view over an encrypted blob.
struct BlobParts<'a> {
    aad: &'a [u8],
    iterations: u32,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
    body: &'a [u8],
}

fn parse_legacy(encrypted: &[u8]) -> Option<BlobParts<'_>> {
    if encrypted.len() < SALT_LEN + NONCE_LEN + TAG_LEN {
        return None;
    }
    Some(BlobParts {
        aad: &[],
        iterations: LEGACY_PBKDF2_ITERATIONS,
        salt: encrypted[..SALT_LEN].try_into().ok()?,
        nonce: encrypted[SALT_LEN..SALT_LEN + NONCE_LEN].try_into().ok()?,
        body: &encrypted[SALT_LEN + NONCE_LEN..],
    })
}

fn parse_v2(encrypted: &[u8]) -> Option<BlobParts<'_>> {
    if encrypted.len() < V2_HEADER_LEN + SALT_LEN + NONCE_LEN + TAG_LEN
        || !encrypted.starts_with(BLOB_MAGIC_V2)
    {
        return None;
    }
    let iterations = u32::from_be_bytes(encrypted[8..V2_HEADER_LEN].try_into().ok()?);
    if !(MIN_PBKDF2_ITERATIONS..=MAX_PBKDF2_ITERATIONS).contains(&iterations) {
        return None;
    }
    let rest = &encrypted[V2_HEADER_LEN..];
    Some(BlobParts {
        aad: &encrypted[..V2_HEADER_LEN],
        iterations,
        salt: rest[..SALT_LEN].try_into().ok()?,
        nonce: rest[SALT_LEN..SALT_LEN + NONCE_LEN].try_into().ok()?,
        body: &rest[SALT_LEN + NONCE_LEN..],
    })
}

fn open_parts(key: &LessSafeKey, parts: &BlobParts<'_>) -> io::Result<Vec<u8>> {
    let nonce = Nonce::assume_unique_for_key(parts.nonce);
    let mut in_out = parts.body.to_vec();
    let len = key
        .open_in_place(nonce, Aad::from(parts.aad), &mut in_out)
        .map_err(|_| io::Error::from(CryptoError::AuthenticationFailed))?
        .len();
    in_out.truncate(len);
    Ok(in_out)
}

/// Shared decryption logic; `key_for(salt, iterations)` supplies the key
/// (freshly derived or from a [`KeyCache`]).
fn decrypt_with<F>(encrypted: &[u8], key_for: F) -> io::Result<Vec<u8>>
where
    F: Fn(&[u8; SALT_LEN], u32) -> io::Result<Arc<LessSafeKey>>,
{
    let result = match (parse_v2(encrypted), parse_legacy(encrypted)) {
        (Some(v2), _) => {
            let key = key_for(&v2.salt, v2.iterations)?;
            open_parts(&key, &v2)
        }
        (None, Some(l)) => {
            let key = key_for(&l.salt, l.iterations)?;
            open_parts(&key, &l)
        }
        (None, None) => {
            let min_len = SALT_LEN + NONCE_LEN + TAG_LEN;
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                format!(
                    "Invalid encrypted data size: {} bytes (minimum: {})",
                    encrypted.len(),
                    min_len
                ),
            ));
        }
    };

    match &result {
        Ok(p) => debug!("Decrypted {} bytes successfully", p.len()),
        // Mensagem genérica: não registamos detalhes para não virar oráculo.
        Err(_) => error!("Decryption failed (authentication tag mismatch)"),
    }
    result
}

/// Decrypt data (accepts both the legacy and the versioned v2 format).
/// Runs PBKDF2 on every call; for many blobs prefer [`KeyCache`].
pub fn decrypt_data(encrypted: &[u8], password: &[u8]) -> io::Result<Vec<u8>> {
    decrypt_with(encrypted, |salt, iterations| {
        derive_key(password, salt, iterations).map(Arc::new)
    })
}

/// Maximum number of derived keys kept by a [`KeyCache`].
const KEY_CACHE_MAX_ENTRIES: usize = 1024;

/// Thread-safe cache of PBKDF2-derived keys for decrypting many blobs that
/// share a password (e.g. a restore). Keys are cached by (salt, iterations);
/// all blobs from one backup session share a salt, so PBKDF2 runs once per
/// session instead of once per blob. The password is bound at construction
/// and wiped on drop.
pub struct KeyCache {
    password: Zeroizing<Vec<u8>>,
    keys: Mutex<HashMap<([u8; SALT_LEN], u32), Arc<LessSafeKey>>>,
}

impl KeyCache {
    /// Create a cache bound to `password`.
    pub fn new(password: &[u8]) -> Self {
        KeyCache {
            password: Zeroizing::new(password.to_vec()),
            keys: Mutex::new(HashMap::new()),
        }
    }

    fn key_for(&self, salt: &[u8; SALT_LEN], iterations: u32) -> io::Result<Arc<LessSafeKey>> {
        let id = (*salt, iterations);
        if let Some(k) = self.keys.lock().ok().and_then(|m| m.get(&id).cloned()) {
            return Ok(k);
        }
        // Derive outside the lock so parallel restores aren't serialized.
        let key = Arc::new(derive_key(&self.password, salt, iterations)?);
        if let Ok(mut map) = self.keys.lock() {
            if map.len() >= KEY_CACHE_MAX_ENTRIES {
                map.clear();
            }
            map.insert(id, key.clone());
        }
        Ok(key)
    }

    /// Decrypt a blob (legacy or v2 format) using cached keys.
    pub fn decrypt(&self, encrypted: &[u8]) -> io::Result<Vec<u8>> {
        decrypt_with(encrypted, |salt, iterations| self.key_for(salt, iterations))
    }

    /// Like [`KeyCache::decrypt`] but decrypts in place inside `blob`'s own
    /// allocation and returns it trimmed to the plaintext, so peak memory is
    /// one copy of the blob instead of two.
    pub fn decrypt_owned(&self, mut blob: Vec<u8>) -> io::Result<Vec<u8>> {
        // (aad bytes, salt, nonce, iterations, body offset)
        let (aad, salt, nonce, iterations, body_start) = match parse_v2(&blob) {
            Some(p) => (
                p.aad.to_vec(),
                p.salt,
                p.nonce,
                p.iterations,
                V2_HEADER_LEN + SALT_LEN + NONCE_LEN,
            ),
            None => match parse_legacy(&blob) {
                Some(p) => (Vec::new(), p.salt, p.nonce, p.iterations, SALT_LEN + NONCE_LEN),
                None => {
                    return Err(io::Error::new(
                        ErrorKind::InvalidData,
                        format!(
                            "Invalid encrypted data size: {} bytes (minimum: {})",
                            blob.len(),
                            SALT_LEN + NONCE_LEN + TAG_LEN
                        ),
                    ));
                }
            },
        };
        let key = self.key_for(&salt, iterations)?;
        let len = match key.open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(&aad[..]),
            &mut blob[body_start..],
        ) {
            Ok(plain) => plain.len(),
            Err(_) => {
                error!("Decryption failed (authentication tag mismatch)");
                return Err(CryptoError::AuthenticationFailed.into());
            }
        };
        blob.truncate(body_start + len);
        blob.drain(..body_start);
        debug!("Decrypted {} bytes successfully (in place)", blob.len());
        Ok(blob)
    }
}

/// Same as [`decrypt_data`] but reuses keys derived by `cache`.
pub fn decrypt_data_with_cache(encrypted: &[u8], cache: &KeyCache) -> io::Result<Vec<u8>> {
    cache.decrypt(encrypted)
}

/// Fast Blake3 hash (used for deduplication)
pub fn hash_file_content(content: &[u8]) -> io::Result<String> {
    Ok(blake3::hash(content).to_hex().to_string())
}

/// Hash entire file (less used)
pub fn hash_file(path: &std::path::Path) -> io::Result<String> {
    let content = std::fs::read(path)?;
    hash_file_content(&content)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a legacy (header-less) blob exactly as the previous version did.
    fn legacy_encrypt(data: &[u8], password: &[u8]) -> Vec<u8> {
        let salt = [7u8; SALT_LEN];
        let nonce_bytes = [9u8; NONCE_LEN];
        let key = derive_key(password, &salt, LEGACY_PBKDF2_ITERATIONS).unwrap();
        let mut in_out = data.to_vec();
        let tag = key
            .seal_in_place_separate_tag(
                Nonce::assume_unique_for_key(nonce_bytes),
                Aad::empty(),
                &mut in_out,
            )
            .unwrap();
        let mut out = Vec::new();
        out.extend_from_slice(&salt);
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&in_out);
        out.extend_from_slice(tag.as_ref());
        out
    }

    #[test]
    fn legacy_blob_still_decrypts() {
        let blob = legacy_encrypt(b"old backup", b"pw");
        assert_eq!(decrypt_data(&blob, b"pw").unwrap(), b"old backup");
        let cache = KeyCache::new(b"pw");
        assert_eq!(cache.decrypt(&blob).unwrap(), b"old backup");
    }

    #[test]
    fn v2_blob_has_header_and_roundtrips() {
        let key = EncryptionKey::new(b"pw").unwrap();
        let blob = key.encrypt(b"hello").unwrap();
        assert!(blob.starts_with(BLOB_MAGIC_V2));
        assert_eq!(decrypt_data(&blob, b"pw").unwrap(), b"hello");
    }

    #[test]
    fn wrong_password_is_authentication_error() {
        let key = EncryptionKey::new(b"pw").unwrap();
        let blob = key.encrypt(b"hello").unwrap();
        let err = decrypt_data(&blob, b"other").unwrap_err();
        assert!(is_authentication_error(&err));
        let msg = err.to_string().to_lowercase();
        assert!(msg.contains("authentication"));
        assert!(!msg.contains("corrupt") && !msg.contains("invalid"));
    }

    #[test]
    fn tampered_header_fails() {
        let key = EncryptionKey::new(b"pw").unwrap();
        let mut blob = key.encrypt(b"hello").unwrap();
        blob[11] ^= 1; // change iteration count
        assert!(decrypt_data(&blob, b"pw").is_err());
    }

    #[test]
    fn key_cache_reuses_key_across_blobs() {
        let key = EncryptionKey::new(b"pw").unwrap();
        let a = key.encrypt(b"a").unwrap();
        let b = key.encrypt(b"b").unwrap();
        let cache = KeyCache::new(b"pw");
        assert_eq!(decrypt_data_with_cache(&a, &cache).unwrap(), b"a");
        assert_eq!(decrypt_data_with_cache(&b, &cache).unwrap(), b"b");
        assert_eq!(cache.keys.lock().unwrap().len(), 1);
    }

    #[test]
    fn decrypt_owned_matches_decrypt() {
        let cache = KeyCache::new(b"pw");
        let key = EncryptionKey::new(b"pw").unwrap();
        let blob = key.encrypt(b"hello world").unwrap();
        assert_eq!(cache.decrypt_owned(blob.clone()).unwrap(), b"hello world");
        let legacy = legacy_encrypt(b"old", b"pw");
        assert_eq!(cache.decrypt_owned(legacy).unwrap(), b"old");
        let mut bad = blob;
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(is_authentication_error(&cache.decrypt_owned(bad).unwrap_err()));
        assert!(cache.decrypt_owned(vec![0u8; 3]).is_err());
    }
}
