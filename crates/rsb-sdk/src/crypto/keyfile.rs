//! Repository key file (`keys/repo.key`): envelope encryption for format v3.
//!
//! A random 32-byte data encryption key (DEK) encrypts every v3 blob of the
//! repository (through a per-blob HKDF subkey, see [`super::stream`]). The
//! DEK is stored wrapped with AES-256-GCM under a key-encryption key (KEK)
//! derived from the password with Argon2id. Changing the password only
//! rewraps the DEK; no blob is rewritten.
//!
//! The file is JSON (see `docs/FORMAT.md`):
//!
//! ```json
//! {
//!   "format": "rsb-repo-key", "version": 3,
//!   "kdf": { "algorithm": "argon2id", "version": 19, "m_cost_kib": 65536,
//!            "t_cost": 3, "p_cost": 1, "salt": "<base64, 16 bytes>" },
//!   "wrapped_dek": { "algorithm": "aes-256-gcm", "nonce": "<base64, 12>",
//!                    "ciphertext": "<base64, 32 + 16>" },
//!   "legacy_secret": { ... optional, same shape ... },
//!   "created_at": "<RFC 3339>"
//! }
//! ```
//!
//! The DEK wrap uses as AAD a canonical binary encoding of the KDF
//! parameters ([`kdf_aad`]), so tampering with the stored parameters (e.g.
//! to weaken them before a password change) makes the unwrap fail.
//!
//! `legacy_secret` is only present in repositories migrated from v1/v2: it
//! holds the password that encrypted the pre-v3 objects, encrypted under a
//! DEK-derived subkey, so those objects stay readable after a password
//! change (their keys are PBKDF2(password, per-session salt) and cannot be
//! rewrapped).

use super::CryptoError;
use crate::error::{CryptoErrorKind, RsbError};
use crate::storage::{LockKind, RepoLock, Storage};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use ring::hkdf;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::io::{self, ErrorKind};
use std::sync::Arc;
use tracing::{info, warn};
use zeroize::Zeroizing;

pub use super::stream::DEK_LEN;

/// Storage key of the repository key file.
pub const REPO_KEY_PATH: &str = "keys/repo.key";
/// Prefix of the temporary backup copy kept during a password change.
pub const REPO_KEY_BACKUP_PREFIX: &str = "keys/repo.key.bak-";
/// `format` field value.
pub const KEY_FILE_FORMAT: &str = "rsb-repo-key";
/// `version` field value (matches the blob format version).
pub const KEY_FILE_VERSION: u32 = 3;
/// Argon2 version 1.3 (0x13).
const ARGON2_VERSION: u32 = 0x13;
const KDF_SALT_LEN: usize = 16;
const TAG_LEN: usize = 16;
/// HKDF info of the subkey that encrypts `legacy_secret`.
const LEGACY_SECRET_INFO: &[u8] = b"rsb v3 legacy secret";
const LEGACY_SECRET_AAD: &[u8] = b"RSBKEYv3 legacy secret";

/// Argon2id cost parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub m_cost_kib: u32,
    /// Number of passes.
    pub t_cost: u32,
    /// Lanes (parallelism).
    pub p_cost: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl KdfParams {
    /// Defaults for new key files: 64 MiB, 3 passes, 1 lane.
    pub const DEFAULT: KdfParams = KdfParams {
        m_cost_kib: 64 * 1024,
        t_cost: 3,
        p_cost: 1,
    };
    /// Minimum accepted when creating/rewrapping (OWASP: 19 MiB, t=2, p=1).
    pub const MIN_CREATE: KdfParams = KdfParams {
        m_cost_kib: 19 * 1024,
        t_cost: 2,
        p_cost: 1,
    };
    /// Upper bounds accepted from a stored file (DoS protection).
    pub const MAX_M_COST_KIB: u32 = 4 * 1024 * 1024;
    pub const MAX_T_COST: u32 = 10;
    pub const MAX_P_COST: u32 = 16;

    /// Bounds checked for parameters read from storage: generous lower
    /// bound (we must open what older/tuned versions wrote) and strict
    /// upper bounds so a malicious file cannot make us allocate 100s of GiB.
    pub fn validate_for_read(&self) -> Result<(), RsbError> {
        let ok = (1..=Self::MAX_T_COST).contains(&self.t_cost)
            && (1..=Self::MAX_P_COST).contains(&self.p_cost)
            && self.m_cost_kib >= 8 * self.p_cost
            && self.m_cost_kib <= Self::MAX_M_COST_KIB;
        if ok {
            Ok(())
        } else {
            Err(RsbError::crypto(
                CryptoErrorKind::Corrupt,
                format!(
                    "Repository key file has unsupported Argon2 parameters ({:?}); accepted: \
                     m_cost <= {} KiB, 1 <= t_cost <= {}, 1 <= p_cost <= {}",
                    self,
                    Self::MAX_M_COST_KIB,
                    Self::MAX_T_COST,
                    Self::MAX_P_COST
                ),
            ))
        }
    }

    /// Bounds checked for new key files: at least [`Self::MIN_CREATE`].
    pub fn validate_for_create(&self) -> Result<(), RsbError> {
        self.validate_for_read()
            .map_err(|e| RsbError::InvalidInput(e.to_string()))?;
        if self.m_cost_kib < Self::MIN_CREATE.m_cost_kib || self.t_cost < Self::MIN_CREATE.t_cost {
            return Err(RsbError::InvalidInput(format!(
                "Argon2 parameters too weak ({:?}): need m_cost >= {} KiB and t_cost >= {}",
                self,
                Self::MIN_CREATE.m_cost_kib,
                Self::MIN_CREATE.t_cost
            )));
        }
        Ok(())
    }
}

/// Canonical AAD of the DEK wrap:
/// `"RSBKEYv3" | argon2 version u32 BE | m_cost_kib u32 BE | t_cost u32 BE |
/// p_cost u32 BE | salt (16)` (40 bytes).
pub fn kdf_aad(params: &KdfParams, salt: &[u8; KDF_SALT_LEN]) -> [u8; 40] {
    let mut aad = [0u8; 40];
    aad[..8].copy_from_slice(b"RSBKEYv3");
    aad[8..12].copy_from_slice(&ARGON2_VERSION.to_be_bytes());
    aad[12..16].copy_from_slice(&params.m_cost_kib.to_be_bytes());
    aad[16..20].copy_from_slice(&params.t_cost.to_be_bytes());
    aad[20..24].copy_from_slice(&params.p_cost.to_be_bytes());
    aad[24..].copy_from_slice(salt);
    aad
}

/// Argon2id(password, salt, params) → 32-byte KEK (wiped on drop).
pub fn derive_kek(
    password: &[u8],
    salt: &[u8],
    params: &KdfParams,
) -> Result<Zeroizing<[u8; 32]>, RsbError> {
    use argon2::{Algorithm, Argon2, Params, Version};
    let p = Params::new(params.m_cost_kib, params.t_cost, params.p_cost, Some(32))
        .map_err(|e| RsbError::crypto(CryptoErrorKind::Other, format!("Argon2 params: {e}")))?;
    let mut kek = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, p)
        .hash_password_into(password, salt, &mut kek[..])
        .map_err(|e| RsbError::crypto(CryptoErrorKind::Other, format!("Argon2: {e}")))?;
    Ok(kek)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct KdfSection {
    algorithm: String,
    version: u32,
    #[serde(flatten)]
    params: KdfParams,
    salt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct SealedSection {
    algorithm: String,
    nonce: String,
    ciphertext: String,
}

/// Serialized form of `keys/repo.key`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RepoKeyFile {
    format: String,
    version: u32,
    kdf: KdfSection,
    wrapped_dek: SealedSection,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    legacy_secret: Option<SealedSection>,
    created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    updated_at: Option<String>,
}

fn corrupt(msg: impl Into<String>) -> RsbError {
    RsbError::crypto(CryptoErrorKind::Corrupt, msg)
}

fn wrong_password() -> RsbError {
    RsbError::crypto(
        CryptoErrorKind::AuthenticationFailed,
        format!(
            "❌ Decryption failed (wrong key)\n\n\
             The repository key ({}) could not be unlocked with the password provided.\n\
             Use the SAME encryption key that was used when creating this backup \
             (or the new one after `rsb key change-password`).\n\n\
             Technical: {}",
            REPO_KEY_PATH,
            CryptoError::AuthenticationFailed
        ),
    )
}

fn random<const N: usize>() -> Result<[u8; N], RsbError> {
    let mut b = [0u8; N];
    SystemRandom::new()
        .fill(&mut b)
        .map_err(|_| RsbError::crypto(CryptoErrorKind::Other, "RNG failure"))?;
    Ok(b)
}

fn b64_fixed<const N: usize>(s: &str, what: &str) -> Result<[u8; N], RsbError> {
    let v = B64
        .decode(s)
        .map_err(|_| corrupt(format!("Repository key file: invalid base64 in {what}")))?;
    v.try_into()
        .map_err(|_| corrupt(format!("Repository key file: wrong length for {what}")))
}

fn seal(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Result<SealedSection, RsbError> {
    let nonce: [u8; NONCE_LEN] = random()?;
    let k = LessSafeKey::new(
        UnboundKey::new(&AES_256_GCM, key)
            .map_err(|_| RsbError::crypto(CryptoErrorKind::Other, "bad key"))?,
    );
    let mut buf = Zeroizing::new(plaintext.to_vec());
    let tag = k
        .seal_in_place_separate_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(aad),
            &mut buf[..],
        )
        .map_err(|_| RsbError::crypto(CryptoErrorKind::Other, "encryption failed"))?;
    let mut ct = buf.to_vec();
    ct.extend_from_slice(tag.as_ref());
    Ok(SealedSection {
        algorithm: "aes-256-gcm".into(),
        nonce: B64.encode(nonce),
        ciphertext: B64.encode(ct),
    })
}

/// Opens a sealed section; `None` on authentication failure.
fn open(
    key: &[u8; 32],
    aad: &[u8],
    s: &SealedSection,
) -> Result<Option<Zeroizing<Vec<u8>>>, RsbError> {
    if s.algorithm != "aes-256-gcm" {
        return Err(corrupt(format!(
            "Repository key file: unsupported cipher '{}'",
            s.algorithm
        )));
    }
    let nonce: [u8; NONCE_LEN] = b64_fixed(&s.nonce, "nonce")?;
    let mut ct = Zeroizing::new(
        B64.decode(&s.ciphertext)
            .map_err(|_| corrupt("Repository key file: invalid base64 in ciphertext"))?,
    );
    if ct.len() < TAG_LEN {
        return Err(corrupt("Repository key file: ciphertext too short"));
    }
    let k = LessSafeKey::new(
        UnboundKey::new(&AES_256_GCM, key)
            .map_err(|_| RsbError::crypto(CryptoErrorKind::Other, "bad key"))?,
    );
    match k.open_in_place(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(aad),
        &mut ct[..],
    ) {
        Ok(p) => Ok(Some(Zeroizing::new(p.to_vec()))),
        Err(_) => Ok(None),
    }
}

fn legacy_subkey(dek: &[u8; DEK_LEN]) -> Result<Zeroizing<[u8; 32]>, RsbError> {
    struct Len32;
    impl hkdf::KeyType for Len32 {
        fn len(&self) -> usize {
            32
        }
    }
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]).extract(dek);
    let mut out = Zeroizing::new([0u8; 32]);
    prk.expand(&[LEGACY_SECRET_INFO], Len32)
        .and_then(|okm| okm.fill(&mut out[..]))
        .map_err(|_| RsbError::crypto(CryptoErrorKind::Other, "HKDF failure"))?;
    Ok(out)
}

/// The unlocked repository key: the DEK (and, for migrated repositories,
/// the password of the pre-v3 objects). Secrets are wiped on drop and never
/// shown in `Debug`.
pub struct RepoKey {
    dek: Zeroizing<[u8; DEK_LEN]>,
    legacy_password: Option<Zeroizing<Vec<u8>>>,
}

impl fmt::Debug for RepoKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RepoKey")
            .field("dek", &"***REDACTED***")
            .field("has_legacy_password", &self.legacy_password.is_some())
            .finish()
    }
}

impl RepoKey {
    /// Generates a new random DEK.
    pub fn generate() -> Result<Self, RsbError> {
        Ok(Self {
            dek: Zeroizing::new(random()?),
            legacy_password: None,
        })
    }

    /// Builds a key from raw DEK bytes (tests, recovery tooling).
    pub fn from_dek(dek: [u8; DEK_LEN]) -> Self {
        Self {
            dek: Zeroizing::new(dek),
            legacy_password: None,
        }
    }

    /// Password that encrypted the pre-v3 (v1/v2) objects, if this
    /// repository was migrated.
    pub fn legacy_password(&self) -> Option<&[u8]> {
        self.legacy_password.as_deref().map(|v| &v[..])
    }

    /// Encrypts an in-memory payload as a v3 blob bound to `object_id`.
    pub fn encrypt_object(&self, object_id: &str, data: &[u8]) -> io::Result<Vec<u8>> {
        super::stream::encrypt_v3(&self.dek, object_id, data)
    }

    /// Streaming v3 encryptor writing into `inner`.
    pub fn encryptor<W: io::Write>(
        &self,
        object_id: &str,
        inner: W,
    ) -> io::Result<super::stream::StreamEncryptor<W>> {
        super::stream::StreamEncryptor::new(&self.dek, object_id, inner)
    }

    /// Streaming v3 decryptor over `reader`; `prefix` are bytes already
    /// consumed from it (e.g. the magic used to detect the format).
    pub async fn stream_decryptor<R: tokio::io::AsyncRead + Unpin>(
        &self,
        object_id: &str,
        prefix: &[u8],
        reader: R,
    ) -> io::Result<super::stream::StreamDecryptor<R>> {
        super::stream::StreamDecryptor::new(&self.dek, object_id, prefix, reader).await
    }

    /// Decrypts a v3 blob held in memory.
    pub fn decrypt_object(&self, object_id: &str, blob: &[u8]) -> io::Result<Vec<u8>> {
        super::stream::decrypt_v3(&self.dek, object_id, blob)
    }

    /// Wraps this key under `password` (fresh salt and nonce).
    pub fn wrap(&self, password: &[u8], params: KdfParams) -> Result<RepoKeyFile, RsbError> {
        params.validate_for_create()?;
        let salt: [u8; KDF_SALT_LEN] = random()?;
        let kek = derive_kek(password, &salt, &params)?;
        let wrapped_dek = seal(&kek, &kdf_aad(&params, &salt), &self.dek[..])?;
        let legacy_secret = match &self.legacy_password {
            Some(pw) => Some(seal(&*legacy_subkey(&self.dek)?, LEGACY_SECRET_AAD, pw)?),
            None => None,
        };
        Ok(RepoKeyFile {
            format: KEY_FILE_FORMAT.into(),
            version: KEY_FILE_VERSION,
            kdf: KdfSection {
                algorithm: "argon2id".into(),
                version: ARGON2_VERSION,
                params,
                salt: B64.encode(salt),
            },
            wrapped_dek,
            legacy_secret,
            created_at: chrono::Utc::now().to_rfc3339(),
            updated_at: None,
        })
    }

    fn same_key(&self, other: &RepoKey) -> bool {
        // Not secret-dependent timing in any useful way (both are ours).
        self.dek[..] == other.dek[..] && self.legacy_password() == other.legacy_password()
    }
}

impl RepoKeyFile {
    pub fn to_bytes(&self) -> Result<Vec<u8>, RsbError> {
        serde_json::to_vec_pretty(self)
            .map_err(|e| RsbError::Other(format!("serialize key file: {e}")))
    }

    pub fn from_bytes(raw: &[u8]) -> Result<Self, RsbError> {
        let f: RepoKeyFile = serde_json::from_slice(raw)
            .map_err(|e| corrupt(format!("Repository key file is unreadable: {e}")))?;
        if f.format != KEY_FILE_FORMAT || f.version != KEY_FILE_VERSION {
            return Err(corrupt(format!(
                "Repository key file has unsupported format '{}' version {}",
                f.format, f.version
            )));
        }
        if f.kdf.algorithm != "argon2id" || f.kdf.version != ARGON2_VERSION {
            return Err(corrupt(format!(
                "Repository key file uses unsupported KDF '{}' v{}",
                f.kdf.algorithm, f.kdf.version
            )));
        }
        f.kdf.params.validate_for_read()?;
        Ok(f)
    }

    /// Stored Argon2 parameters.
    pub fn params(&self) -> KdfParams {
        self.kdf.params
    }

    /// Unlocks the DEK with `password`. A wrong password yields
    /// `RsbError::Crypto { kind: AuthenticationFailed, .. }`.
    pub fn unwrap_key(&self, password: &[u8]) -> Result<RepoKey, RsbError> {
        let salt: [u8; KDF_SALT_LEN] = b64_fixed(&self.kdf.salt, "kdf salt")?;
        let kek = derive_kek(password, &salt, &self.kdf.params)?;
        let dek = open(&kek, &kdf_aad(&self.kdf.params, &salt), &self.wrapped_dek)?
            .ok_or_else(wrong_password)?;
        let dek: [u8; DEK_LEN] = dek[..]
            .try_into()
            .map_err(|_| corrupt("Repository key file: wrapped key has wrong length"))?;
        let mut key = RepoKey::from_dek(dek);
        if let Some(s) = &self.legacy_secret {
            let pw = open(&*legacy_subkey(&key.dek)?, LEGACY_SECRET_AAD, s)?.ok_or_else(|| {
                corrupt("Repository key file: legacy secret failed authentication")
            })?;
            key.legacy_password = Some(pw);
        }
        Ok(key)
    }
}

/// Runs Argon2 on the blocking pool (it is CPU and memory heavy).
async fn unwrap_blocking(file: RepoKeyFile, password: &[u8]) -> Result<RepoKey, RsbError> {
    let pw = Zeroizing::new(password.to_vec());
    tokio::task::spawn_blocking(move || file.unwrap_key(&pw)).await?
}

async fn wrap_blocking(
    key: Arc<RepoKey>,
    password: &[u8],
    params: KdfParams,
) -> Result<RepoKeyFile, RsbError> {
    let pw = Zeroizing::new(password.to_vec());
    tokio::task::spawn_blocking(move || key.wrap(&pw, params)).await?
}

/// Reads `keys/repo.key`; `None` if the repository has no key file.
pub async fn read_key_file(storage: &dyn Storage) -> Result<Option<RepoKeyFile>, RsbError> {
    match storage.read(REPO_KEY_PATH).await {
        Ok(raw) => RepoKeyFile::from_bytes(&raw).map(Some),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// True if the repository has a key file (format v3 enabled).
pub async fn repo_key_exists(storage: &dyn Storage) -> Result<bool, RsbError> {
    Ok(storage.size(REPO_KEY_PATH).await?.is_some())
}

/// Loads and unlocks the repository key. `Ok(None)` if the repository has
/// no key file (pre-v3 repository); wrong password → `AuthenticationFailed`.
pub async fn load_repo_key(
    storage: &dyn Storage,
    password: &[u8],
) -> Result<Option<RepoKey>, RsbError> {
    match read_key_file(storage).await? {
        Some(f) => unwrap_blocking(f, password).await.map(Some),
        None => Ok(None),
    }
}

/// Exclusive repository lock, retried briefly (concurrent backups hold a
/// shared lock only for their duration).
async fn lock_exclusive(storage: &Arc<dyn Storage>, op: &str) -> Result<RepoLock, RsbError> {
    let mut last = None;
    for attempt in 0..5u32 {
        match RepoLock::acquire(storage.clone(), LockKind::Exclusive, op).await {
            Ok(l) => return Ok(l),
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                last = Some(e);
                tokio::time::sleep(std::time::Duration::from_millis(200 * (attempt as u64 + 1)))
                    .await;
            }
            Err(e) => return Err(e.into()),
        }
    }
    Err(last
        .map(RsbError::from)
        .unwrap_or_else(|| RsbError::Other("repository lock unavailable".into())))
}

async fn release(lock: RepoLock) {
    if let Err(e) = lock.release().await {
        warn!("Failed to release repository lock: {}", e);
    }
}

/// Inspects existing snapshots before a repository is upgraded to v3.
///
/// Returns `true` if the newest snapshot that is encrypted uses the v1/v2
/// (password-derived) format, after checking that `password` opens it:
/// creating a key file with a mistyped password would otherwise split the
/// repository between two passwords. Clear snapshots are ignored.
async fn probe_legacy_snapshots(storage: &dyn Storage, password: &[u8]) -> Result<bool, RsbError> {
    let mut snaps = match storage.list("snapshots").await {
        Ok(s) => s,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e.into()),
    };
    snaps.retain(|s| s.ends_with(".toml"));
    crate::core::manifest::sort_snapshots_newest_first(&mut snaps);
    let cache = super::KeyCache::new(password);
    for snap in snaps {
        let raw = storage.read(&snap).await?;
        if !looks_encrypted(&raw) {
            continue;
        }
        if super::stream::is_v3(&raw) {
            // Should not happen without a key file: refuse to guess.
            return Err(corrupt(format!(
                "{} is a v3 blob but {} is missing; restore the key file from a backup",
                snap, REPO_KEY_PATH
            )));
        }
        return match cache.decrypt(&raw) {
            Ok(_) => Ok(true),
            Err(e) if super::is_authentication_error(&e) => Err(RsbError::crypto(
                CryptoErrorKind::AuthenticationFailed,
                format!(
                    "❌ Decryption failed (wrong key)\n\n\
                     The password does not open the existing encrypted snapshot {}; refusing \
                     to create {} with it. Use the password of the existing backups.",
                    snap, REPO_KEY_PATH
                ),
            )),
            Err(e) => Err(corrupt(format!("Cannot read {}: {}", snap, e))),
        };
    }
    Ok(false)
}

/// Clear manifests are zstd frames or plain TOML text.
fn looks_encrypted(raw: &[u8]) -> bool {
    const ZSTD_MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];
    !(raw.starts_with(&ZSTD_MAGIC) || std::str::from_utf8(raw).is_ok())
}

/// Creates `keys/repo.key` with a new random DEK. Fails if it exists.
///
/// Holds the exclusive repository lock so two first backups cannot race
/// and create two different keys. If the repository already holds v1/v2
/// encrypted snapshots, `password` must open the newest one and is kept as
/// the legacy secret (see module docs).
pub async fn init_repo_key(
    storage: Arc<dyn Storage>,
    password: &[u8],
    params: KdfParams,
) -> Result<RepoKey, RsbError> {
    params.validate_for_create()?;
    let lock = lock_exclusive(&storage, "key-init").await?;
    let result = init_locked(&*storage, password, params).await;
    release(lock).await;
    result
}

async fn init_locked(
    storage: &dyn Storage,
    password: &[u8],
    params: KdfParams,
) -> Result<RepoKey, RsbError> {
    if repo_key_exists(storage).await? {
        return Err(RsbError::InvalidInput(format!(
            "{} already exists; use `rsb key change-password` to change the password",
            REPO_KEY_PATH
        )));
    }
    let has_legacy = probe_legacy_snapshots(storage, password).await?;
    let mut key = RepoKey::generate()?;
    if has_legacy {
        key.legacy_password = Some(Zeroizing::new(password.to_vec()));
    }
    let key = Arc::new(key);
    let file = wrap_blocking(key.clone(), password, params).await?;
    storage.write(REPO_KEY_PATH, &file.to_bytes()?).await?;

    // Read back: the stored file must open to the same key before any blob
    // is encrypted with it.
    let stored = load_repo_key(storage, password)
        .await?
        .ok_or_else(|| RsbError::Storage(format!("{} vanished after write", REPO_KEY_PATH)))?;
    if !stored.same_key(&key) {
        return Err(RsbError::Storage(format!(
            "{} was modified concurrently; aborting",
            REPO_KEY_PATH
        )));
    }
    info!(
        "🔑 Created repository key {} (format v3{})",
        REPO_KEY_PATH,
        if has_legacy {
            ", existing v1/v2 objects stay readable"
        } else {
            ""
        }
    );
    Ok(stored)
}

/// Loads the repository key, creating it on first use.
///
/// `dry_run` never writes: without a key file it returns an ephemeral key
/// (nothing gets encrypted in a dry run anyway).
pub async fn open_or_init_repo_key(
    storage: Arc<dyn Storage>,
    password: &[u8],
    dry_run: bool,
) -> Result<RepoKey, RsbError> {
    if let Some(k) = load_repo_key(&*storage, password).await? {
        return Ok(k);
    }
    if dry_run {
        return RepoKey::generate();
    }
    let lock = lock_exclusive(&storage, "key-init").await?;
    let result = async {
        // Another process may have created it while we waited for the lock.
        if let Some(k) = load_repo_key(&*storage, password).await? {
            return Ok(k);
        }
        init_locked(&*storage, password, KdfParams::DEFAULT).await
    }
    .await;
    release(lock).await;
    result
}

/// Rewraps the DEK under `new_password` (optionally with new Argon2
/// parameters, default: keep the stored ones if they meet the creation
/// minimum, else [`KdfParams::DEFAULT`]). No blob is rewritten.
///
/// Procedure (exclusive lock held): unlock with `old_password` → write a
/// timestamped copy `keys/repo.key.bak-<ts>` of the current file → write the
/// new file (atomic per object on every backend) → read it back and check it
/// opens with `new_password` to the same key → delete the copy. If the check
/// fails the old file is restored and the copy is kept.
pub async fn change_password(
    storage: Arc<dyn Storage>,
    old_password: &[u8],
    new_password: &[u8],
    params: Option<KdfParams>,
) -> Result<(), RsbError> {
    if new_password.is_empty() {
        return Err(RsbError::InvalidInput("The new password is empty".into()));
    }
    if let Some(p) = &params {
        p.validate_for_create()?;
    }
    let lock = lock_exclusive(&storage, "key-change-password").await?;
    let result = change_locked(&*storage, old_password, new_password, params).await;
    release(lock).await;
    result
}

async fn change_locked(
    storage: &dyn Storage,
    old_password: &[u8],
    new_password: &[u8],
    params: Option<KdfParams>,
) -> Result<(), RsbError> {
    let raw = match storage.read(REPO_KEY_PATH).await {
        Ok(r) => r,
        Err(e) if e.kind() == ErrorKind::NotFound => {
            return Err(RsbError::NotFound(format!(
                "{} not found: run `rsb key init` (or an encrypted backup) first",
                REPO_KEY_PATH
            )));
        }
        Err(e) => return Err(e.into()),
    };
    let current = RepoKeyFile::from_bytes(&raw)?;
    let params = params.unwrap_or_else(|| {
        let p = current.params();
        if p.validate_for_create().is_ok() {
            p
        } else {
            KdfParams::DEFAULT
        }
    });
    let key = Arc::new(unwrap_blocking(current.clone(), old_password).await?);
    let mut new_file = wrap_blocking(key.clone(), new_password, params).await?;
    new_file.created_at = current.created_at.clone();
    new_file.updated_at = Some(chrono::Utc::now().to_rfc3339());

    let backup = format!(
        "{}{}",
        REPO_KEY_BACKUP_PREFIX,
        chrono::Utc::now().format("%Y%m%dT%H%M%S%.3fZ")
    );
    storage.write(&backup, &raw).await?;
    storage.write(REPO_KEY_PATH, &new_file.to_bytes()?).await?;

    let verified = match load_repo_key(storage, new_password).await {
        Ok(Some(k)) => k.same_key(&key),
        _ => false,
    };
    if !verified {
        warn!(
            "New {} did not verify; restoring the previous one (copy kept at {})",
            REPO_KEY_PATH, backup
        );
        storage.write(REPO_KEY_PATH, &raw).await?;
        return Err(RsbError::Storage(format!(
            "The rewritten {} could not be verified; the previous key file was restored \
             (a copy is kept at {})",
            REPO_KEY_PATH, backup
        )));
    }
    if let Err(e) = storage.delete(&backup).await {
        warn!("Could not delete temporary key backup {}: {}", backup, e);
    }
    info!("🔑 Repository password changed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MemoryStorage;

    fn fast() -> KdfParams {
        KdfParams::MIN_CREATE
    }

    #[test]
    fn param_bounds() {
        assert!(KdfParams::DEFAULT.validate_for_create().is_ok());
        assert!(KdfParams::MIN_CREATE.validate_for_create().is_ok());
        let weak_m = KdfParams {
            m_cost_kib: 19 * 1024 - 1,
            ..KdfParams::MIN_CREATE
        };
        assert!(weak_m.validate_for_create().is_err());
        assert!(weak_m.validate_for_read().is_ok());
        let weak_t = KdfParams {
            t_cost: 1,
            ..KdfParams::MIN_CREATE
        };
        assert!(weak_t.validate_for_create().is_err());
        assert!(weak_t.validate_for_read().is_ok());
        let huge_m = KdfParams {
            m_cost_kib: KdfParams::MAX_M_COST_KIB + 1,
            ..KdfParams::DEFAULT
        };
        assert!(huge_m.validate_for_read().is_err());
        let huge_t = KdfParams {
            t_cost: 11,
            ..KdfParams::DEFAULT
        };
        assert!(huge_t.validate_for_read().is_err());
        let zero_p = KdfParams {
            p_cost: 0,
            ..KdfParams::DEFAULT
        };
        assert!(zero_p.validate_for_read().is_err());
    }

    #[test]
    fn wrap_unwrap_and_wrong_password() {
        let key = RepoKey::generate().unwrap();
        let file = key.wrap(b"pw", fast()).unwrap();
        let back = RepoKeyFile::from_bytes(&file.to_bytes().unwrap()).unwrap();
        assert!(back.unwrap_key(b"pw").unwrap().same_key(&key));
        let err = back.unwrap_key(b"nope").unwrap_err();
        assert!(matches!(
            err,
            RsbError::Crypto {
                kind: CryptoErrorKind::AuthenticationFailed,
                ..
            }
        ));
        assert!(err.to_string().contains("wrong key"));
    }

    #[test]
    fn tampered_params_fail_authentication() {
        let key = RepoKey::generate().unwrap();
        let mut file = key.wrap(b"pw", fast()).unwrap();
        file.kdf.params.t_cost += 1;
        assert!(
            file.unwrap_key(b"pw")
                .unwrap_err()
                .is_authentication_failure()
        );
    }

    #[test]
    fn stored_params_out_of_bounds_are_refused() {
        let key = RepoKey::generate().unwrap();
        let file = key.wrap(b"pw", fast()).unwrap();
        let mut v: serde_json::Value = serde_json::from_slice(&file.to_bytes().unwrap()).unwrap();
        v["kdf"]["m_cost_kib"] = serde_json::json!(KdfParams::MAX_M_COST_KIB as u64 + 1);
        let raw = serde_json::to_vec(&v).unwrap();
        assert!(matches!(
            RepoKeyFile::from_bytes(&raw).unwrap_err(),
            RsbError::Crypto {
                kind: CryptoErrorKind::Corrupt,
                ..
            }
        ));
        // Weaker-than-creation params written by someone else still open.
        let weak = KdfParams {
            m_cost_kib: 1024,
            t_cost: 1,
            p_cost: 1,
        };
        let salt = [5u8; 16];
        let kek = derive_kek(b"pw", &salt, &weak).unwrap();
        let mut f = file.clone();
        f.kdf.params = weak;
        f.kdf.salt = B64.encode(salt);
        f.wrapped_dek = seal(&kek, &kdf_aad(&weak, &salt), &key.dek[..]).unwrap();
        let f = RepoKeyFile::from_bytes(&f.to_bytes().unwrap()).unwrap();
        assert!(f.unwrap_key(b"pw").unwrap().same_key(&key));
    }

    #[test]
    fn legacy_secret_survives_rewrap() {
        let mut key = RepoKey::generate().unwrap();
        key.legacy_password = Some(Zeroizing::new(b"old-pw".to_vec()));
        let f1 = key.wrap(b"a", fast()).unwrap();
        let k1 = f1.unwrap_key(b"a").unwrap();
        assert_eq!(k1.legacy_password(), Some(&b"old-pw"[..]));
        let f2 = k1.wrap(b"b", fast()).unwrap();
        assert_eq!(
            f2.unwrap_key(b"b").unwrap().legacy_password(),
            Some(&b"old-pw"[..])
        );
    }

    #[test]
    fn debug_does_not_leak() {
        let key = RepoKey::from_dek([0xAB; 32]);
        let s = format!("{:?}", key);
        assert!(!s.contains("171") && !s.to_lowercase().contains("ab, ab"));
    }

    #[tokio::test]
    async fn init_change_password_and_backup_copy_removed() {
        let mem = Arc::new(MemoryStorage::new());
        let storage: Arc<dyn Storage> = mem.clone();
        assert!(load_repo_key(&*storage, b"pw").await.unwrap().is_none());
        let k = init_repo_key(storage.clone(), b"pw", fast()).await.unwrap();
        assert!(k.legacy_password().is_none());
        assert!(init_repo_key(storage.clone(), b"pw", fast()).await.is_err());

        let err = change_password(storage.clone(), b"bad", b"new", Some(fast()))
            .await
            .unwrap_err();
        assert!(err.is_authentication_failure());

        change_password(storage.clone(), b"pw", b"new", Some(fast()))
            .await
            .unwrap();
        let k2 = load_repo_key(&*storage, b"new").await.unwrap().unwrap();
        assert!(k2.same_key(&k));
        assert!(
            load_repo_key(&*storage, b"pw")
                .await
                .unwrap_err()
                .is_authentication_failure()
        );
        assert!(
            mem.keys()
                .iter()
                .all(|p| !p.starts_with(REPO_KEY_BACKUP_PREFIX) && !p.starts_with("locks/")),
            "{:?}",
            mem.keys()
        );
        assert!(
            change_password(
                storage.clone(),
                b"new",
                b"x",
                Some(KdfParams {
                    t_cost: 1,
                    ..fast()
                })
            )
            .await
            .is_err()
        );
    }
}
