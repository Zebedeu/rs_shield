//! Repository key file (`keys/repo.key`): envelope encryption for format v3.
//!
//! A random 32-byte data encryption key (DEK) encrypts every v3 blob of the
//! repository (through a per-blob HKDF subkey, see [`super::stream`]). The
//! DEK is stored wrapped with AES-256-GCM under a key-encryption key (KEK)
//! derived from the password with Argon2id. Changing the password only
//! rewraps the DEK; no blob is rewritten. `rsb key rotate` replaces the DEK
//! itself and re-encrypts every blob (see [`super::lifecycle`]).
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
//!   "key_id": "<hex, 4 bytes>",
//!   "rotation": { "key_id": "...", "wrapped_dek": { ... }, "started_at": "..." },
//!   "created_at": "<RFC 3339>"
//! }
//! ```
//!
//! The DEK wrap uses as AAD a canonical binary encoding of the KDF
//! parameters ([`kdf_aad`]), so tampering with the stored parameters (e.g.
//! to weaken them before a password change) makes the unwrap fail.
//!
//! `rotation` only exists while `rsb key rotate` runs (or after it was
//! interrupted): it holds the new DEK, wrapped by the same KEK with a
//! distinct AAD. During a rotation new blobs use the new DEK and readers pick
//! the DEK by the key id in each blob header.
//!
//! `legacy_secret` (read only) is found in key files written by earlier
//! versions for repositories upgraded from v1/v2: it holds the password that
//! encrypted the pre-v3 objects. This version never writes it: `rsb key
//! migrate` re-encrypts those objects as v3 and then removes it.

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
use super::stream::{KeyId, V3Header, key_id_of};

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
    /// Key id (hex) of `wrapped_dek`; optional (files written before key
    /// ids existed lack it), checked against the DEK when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    key_id: Option<String>,
    /// Read only: written by earlier versions, never by this one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    legacy_secret: Option<SealedSection>,
    /// Present only while a key rotation is in progress.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rotation: Option<RotationSection>,
    created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    updated_at: Option<String>,
}

/// New DEK of an unfinished rotation, wrapped under the same KEK as
/// `wrapped_dek` with AAD [`rotation_aad`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct RotationSection {
    key_id: String,
    wrapped_dek: SealedSection,
    started_at: String,
}

/// AAD of the rotation DEK wrap: [`kdf_aad`] followed by `"rotation"`, so
/// the two wrapped keys cannot be swapped.
fn rotation_aad(params: &KdfParams, salt: &[u8; KDF_SALT_LEN]) -> Vec<u8> {
    let mut aad = kdf_aad(params, salt).to_vec();
    aad.extend_from_slice(b"rotation");
    aad
}

/// Lowercase hex of a key id.
pub fn key_id_hex(id: &KeyId) -> String {
    id.iter().map(|b| format!("{:02x}", b)).collect()
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

/// One data encryption key and its id.
#[derive(Clone)]
struct Dek {
    id: KeyId,
    key: Zeroizing<[u8; DEK_LEN]>,
}

impl Dek {
    fn new(key: [u8; DEK_LEN]) -> Self {
        Self {
            id: key_id_of(&key),
            key: Zeroizing::new(key),
        }
    }
}

/// The unlocked repository key: the DEK (two of them while a rotation is in
/// progress) and, for key files written by earlier versions of migrated
/// repositories, the password of the pre-v3 objects. Secrets are wiped on
/// drop and never shown in `Debug`.
pub struct RepoKey {
    /// The `wrapped_dek` slot. Opens blobs without a key id.
    primary: Dek,
    /// The new DEK of an unfinished rotation; when set, it encrypts.
    pending: Option<Dek>,
    legacy_password: Option<Zeroizing<Vec<u8>>>,
}

impl fmt::Debug for RepoKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RepoKey")
            .field("dek", &"***REDACTED***")
            .field("key_id", &self.key_id_hex())
            .field("rotating", &self.pending.is_some())
            .field("has_legacy_password", &self.legacy_password.is_some())
            .finish()
    }
}

impl RepoKey {
    /// Generates a new random DEK.
    pub fn generate() -> Result<Self, RsbError> {
        Ok(Self::from_dek(random()?))
    }

    /// Builds a key from raw DEK bytes (tests, recovery tooling).
    pub fn from_dek(dek: [u8; DEK_LEN]) -> Self {
        Self {
            primary: Dek::new(dek),
            pending: None,
            legacy_password: None,
        }
    }

    /// The DEK that encrypts new blobs (the new one during a rotation).
    fn active(&self) -> &Dek {
        self.pending.as_ref().unwrap_or(&self.primary)
    }

    /// Key id of the DEK that encrypts new blobs.
    pub fn key_id(&self) -> KeyId {
        self.active().id
    }

    /// [`RepoKey::key_id`] in hex.
    pub fn key_id_hex(&self) -> String {
        key_id_hex(&self.active().id)
    }

    /// True while a key rotation is unfinished (two DEKs).
    pub fn is_rotating(&self) -> bool {
        self.pending.is_some()
    }

    /// Password that encrypted the pre-v3 (v1/v2) objects, if the key file
    /// was written by an earlier version that stored it.
    pub fn legacy_password(&self) -> Option<&[u8]> {
        self.legacy_password.as_deref().map(|v| &v[..])
    }

    /// The DEK that opens a blob with this header: by key id when the
    /// header has one, else the primary DEK. An unknown key id is an
    /// authentication failure (no DEK of this key file wrote the blob).
    fn dek_for(&self, header: &V3Header) -> io::Result<&[u8; DEK_LEN]> {
        match header.key_id() {
            None => Ok(&self.primary.key),
            Some(id) => [Some(&self.primary), self.pending.as_ref()]
                .into_iter()
                .flatten()
                .find(|d| d.id == id)
                .map(|d| &*d.key)
                .ok_or_else(|| CryptoError::AuthenticationFailed.into()),
        }
    }

    /// True if a blob with this header was written by the active DEK (and
    /// carries its key id).
    pub fn is_active_blob(&self, header: &V3Header) -> bool {
        header.key_id() == Some(self.active().id)
    }

    /// Encrypts an in-memory payload as a v3 blob bound to `object_id`.
    pub fn encrypt_object(&self, object_id: &str, data: &[u8]) -> io::Result<Vec<u8>> {
        let k = self.active();
        super::stream::encrypt_v3(&k.key, Some(k.id), object_id, data)
    }

    /// Streaming v3 encryptor writing into `inner`.
    pub fn encryptor<W: io::Write>(
        &self,
        object_id: &str,
        inner: W,
    ) -> io::Result<super::stream::StreamEncryptor<W>> {
        let k = self.active();
        super::stream::StreamEncryptor::new(&k.key, Some(k.id), object_id, inner)
    }

    /// Streaming v3 decryptor over `reader`; `prefix` are bytes already
    /// consumed from it (e.g. the magic used to detect the format).
    pub async fn stream_decryptor<R: tokio::io::AsyncRead + Unpin>(
        &self,
        object_id: &str,
        prefix: &[u8],
        reader: R,
    ) -> io::Result<super::stream::StreamDecryptor<R>> {
        super::stream::StreamDecryptor::with_resolver(
            |h| self.dek_for(h),
            object_id,
            prefix,
            reader,
        )
        .await
    }

    /// Decrypts a v3 blob held in memory.
    pub fn decrypt_object(&self, object_id: &str, blob: &[u8]) -> io::Result<Vec<u8>> {
        let header = V3Header::parse(blob)?;
        super::stream::decrypt_v3(self.dek_for(&header)?, object_id, blob)
    }

    /// Wraps this key under `password` (fresh salt and nonce). A pending
    /// rotation key is wrapped too. The legacy password is never written.
    pub fn wrap(&self, password: &[u8], params: KdfParams) -> Result<RepoKeyFile, RsbError> {
        params.validate_for_create()?;
        let salt: [u8; KDF_SALT_LEN] = random()?;
        let kek = derive_kek(password, &salt, &params)?;
        let wrapped_dek = seal(&kek, &kdf_aad(&params, &salt), &self.primary.key[..])?;
        let now = chrono::Utc::now().to_rfc3339();
        let rotation = match &self.pending {
            Some(p) => Some(RotationSection {
                key_id: key_id_hex(&p.id),
                wrapped_dek: seal(&kek, &rotation_aad(&params, &salt), &p.key[..])?,
                started_at: now.clone(),
            }),
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
            key_id: Some(key_id_hex(&self.primary.id)),
            legacy_secret: None,
            rotation,
            created_at: now,
            updated_at: None,
        })
    }

    /// Same DEKs (and legacy password) as `other`.
    pub(crate) fn same_key(&self, other: &RepoKey) -> bool {
        // Not secret-dependent timing in any useful way (both are ours).
        let pending_eq = match (&self.pending, &other.pending) {
            (None, None) => true,
            (Some(a), Some(b)) => a.key[..] == b.key[..],
            _ => false,
        };
        self.primary.key[..] == other.primary.key[..]
            && pending_eq
            && self.legacy_password() == other.legacy_password()
    }

    /// Copy without the legacy password.
    #[doc(hidden)]
    pub fn without_legacy(&self) -> RepoKey {
        RepoKey {
            primary: self.primary.clone(),
            pending: self.pending.clone(),
            legacy_password: None,
        }
    }

    /// Copy that starts a rotation: a new random DEK becomes active, the
    /// current one stays as primary (it still opens the existing blobs).
    #[doc(hidden)]
    pub fn begin_rotation(&self) -> Result<RepoKey, RsbError> {
        if self.pending.is_some() {
            return Err(RsbError::InvalidInput(
                "A key rotation is already in progress".into(),
            ));
        }
        let new = loop {
            let d = Dek::new(random()?);
            // Ids are 32 bits: never let the two keys share one.
            if d.id != self.primary.id {
                break d;
            }
        };
        Ok(RepoKey {
            primary: self.primary.clone(),
            pending: Some(new),
            legacy_password: None,
        })
    }

    /// Copy holding only the active DEK (the end state of a rotation). Used
    /// to prove that no blob still needs the old DEK.
    #[doc(hidden)]
    pub fn only_active(&self) -> RepoKey {
        RepoKey {
            primary: self.active().clone(),
            pending: None,
            legacy_password: None,
        }
    }

    /// Key holding only the old (primary) DEK of a rotation.
    #[doc(hidden)]
    pub fn only_primary(&self) -> RepoKey {
        RepoKey {
            primary: self.primary.clone(),
            pending: None,
            legacy_password: None,
        }
    }
}

impl RepoKeyFile {
    pub fn to_bytes(&self) -> Result<Vec<u8>, RsbError> {
        serde_json::to_vec_pretty(self)
            .map_err(|e| RsbError::Other(format!("serialize key file: {e}")))
    }

    /// Single-line JSON (used for the paper form, where size matters).
    pub fn to_compact_bytes(&self) -> Result<Vec<u8>, RsbError> {
        serde_json::to_vec(self).map_err(|e| RsbError::Other(format!("serialize key file: {e}")))
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

    /// True if the file still holds the legacy (v1/v2) password.
    pub fn has_legacy_secret(&self) -> bool {
        self.legacy_secret.is_some()
    }

    /// True while a key rotation is unfinished.
    pub fn is_rotating(&self) -> bool {
        self.rotation.is_some()
    }

    /// Key id (hex) recorded for the primary DEK, if any.
    pub fn key_id(&self) -> Option<&str> {
        self.key_id.as_deref()
    }

    /// The same file without the legacy secret.
    #[doc(hidden)]
    pub fn without_legacy_secret(&self) -> RepoKeyFile {
        let mut f = self.clone();
        f.legacy_secret = None;
        f.updated_at = Some(chrono::Utc::now().to_rfc3339());
        f
    }

    /// Adds a `legacy_secret` the way earlier versions wrote it (tests of
    /// key files from those versions).
    #[cfg(test)]
    pub(crate) fn add_legacy_secret(&mut self, key: &RepoKey, legacy_password: &[u8]) {
        let sub = legacy_subkey(&key.primary.key).unwrap();
        self.legacy_secret = Some(seal(&sub, LEGACY_SECRET_AAD, legacy_password).unwrap());
    }

    fn unwrap_dek(
        kek: &[u8; 32],
        aad: &[u8],
        sealed: &SealedSection,
        recorded_id: Option<&str>,
    ) -> Result<Dek, RsbError> {
        let dek = open(kek, aad, sealed)?.ok_or_else(wrong_password)?;
        let dek: [u8; DEK_LEN] = dek[..]
            .try_into()
            .map_err(|_| corrupt("Repository key file: wrapped key has wrong length"))?;
        let d = Dek::new(dek);
        if let Some(id) = recorded_id
            && !id.eq_ignore_ascii_case(&key_id_hex(&d.id))
        {
            return Err(corrupt(
                "Repository key file: key id does not match the wrapped key",
            ));
        }
        Ok(d)
    }

    /// Unlocks the DEK with `password`. A wrong password yields
    /// `RsbError::Crypto { kind: AuthenticationFailed, .. }`.
    pub fn unwrap_key(&self, password: &[u8]) -> Result<RepoKey, RsbError> {
        let salt: [u8; KDF_SALT_LEN] = b64_fixed(&self.kdf.salt, "kdf salt")?;
        let kek = derive_kek(password, &salt, &self.kdf.params)?;
        let primary = Self::unwrap_dek(
            &kek,
            &kdf_aad(&self.kdf.params, &salt),
            &self.wrapped_dek,
            self.key_id.as_deref(),
        )?;
        let pending = match &self.rotation {
            Some(r) => {
                let d = Self::unwrap_dek(
                    &kek,
                    &rotation_aad(&self.kdf.params, &salt),
                    &r.wrapped_dek,
                    Some(&r.key_id),
                )
                .map_err(|e| {
                    if e.is_authentication_failure() {
                        corrupt("Repository key file: rotation key failed authentication")
                    } else {
                        e
                    }
                })?;
                if d.id == primary.id {
                    return Err(corrupt(
                        "Repository key file: rotation key has the same id as the current key",
                    ));
                }
                Some(d)
            }
            None => None,
        };
        let mut key = RepoKey {
            primary,
            pending,
            legacy_password: None,
        };
        if let Some(s) = &self.legacy_secret {
            let pw = open(&*legacy_subkey(&key.primary.key)?, LEGACY_SECRET_AAD, s)?.ok_or_else(
                || corrupt("Repository key file: legacy secret failed authentication"),
            )?;
            key.legacy_password = Some(pw);
        }
        Ok(key)
    }
}

/// Runs Argon2 on the blocking pool (it is CPU and memory heavy).
pub(crate) async fn unwrap_blocking(
    file: RepoKeyFile,
    password: &[u8],
) -> Result<RepoKey, RsbError> {
    let pw = Zeroizing::new(password.to_vec());
    tokio::task::spawn_blocking(move || file.unwrap_key(&pw)).await?
}

pub(crate) async fn wrap_blocking(
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

/// Reads the raw bytes of `keys/repo.key` (a clear error if it is missing).
pub(crate) async fn read_key_file_raw(storage: &dyn Storage) -> Result<Vec<u8>, RsbError> {
    match storage.read(REPO_KEY_PATH).await {
        Ok(r) => Ok(r),
        Err(e) if e.kind() == ErrorKind::NotFound => Err(RsbError::NotFound(format!(
            "{} not found: run `rsb key init` (or an encrypted backup) first",
            REPO_KEY_PATH
        ))),
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
pub(crate) async fn lock_exclusive(
    storage: &Arc<dyn Storage>,
    op: &str,
) -> Result<RepoLock, RsbError> {
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

pub(crate) async fn release(lock: RepoLock) {
    if let Err(e) = lock.release().await {
        warn!("Failed to release repository lock: {}", e);
    }
}

/// Storage key of a new timestamped key file copy.
pub(crate) fn backup_copy_path() -> String {
    format!(
        "{}{}",
        REPO_KEY_BACKUP_PREFIX,
        chrono::Utc::now().format("%Y%m%dT%H%M%S%.3fZ")
    )
}

/// Replaces `keys/repo.key` (currently `old_raw`) with `new_file`, safely:
/// writes a timestamped copy of the current file, writes the new one (an
/// atomic replacement per object on every backend), reads it back and
/// checks that `password` unlocks it to `expected`; only then deletes the
/// copy. If the check fails the previous file is written back and the copy
/// is kept. Returns the key read back.
pub(crate) async fn replace_key_file(
    storage: &dyn Storage,
    old_raw: &[u8],
    new_file: &RepoKeyFile,
    password: &[u8],
    expected: &RepoKey,
) -> Result<RepoKey, RsbError> {
    let backup = backup_copy_path();
    storage.write(&backup, old_raw).await?;
    storage.write(REPO_KEY_PATH, &new_file.to_bytes()?).await?;

    let verified = match load_repo_key(storage, password).await {
        Ok(Some(k)) if k.same_key(expected) => Some(k),
        _ => None,
    };
    let Some(key) = verified else {
        warn!(
            "New {} did not verify; restoring the previous one (copy kept at {})",
            REPO_KEY_PATH, backup
        );
        storage.write(REPO_KEY_PATH, old_raw).await?;
        return Err(RsbError::Storage(format!(
            "The rewritten {} could not be verified; the previous key file was restored \
             (a copy is kept at {})",
            REPO_KEY_PATH, backup
        )));
    };
    if let Err(e) = storage.delete(&backup).await {
        warn!("Could not delete temporary key backup {}: {}", backup, e);
    }
    Ok(key)
}

/// Inspects existing snapshots before a repository is upgraded to v3.
///
/// Returns `true` if the newest snapshot that is encrypted uses the v1/v2
/// (password-derived) format, after checking that `password` opens it:
/// creating a key file with a mistyped password would otherwise split the
/// repository between two passwords. Clear snapshots are ignored.
pub(crate) async fn probe_legacy_snapshots(
    storage: &dyn Storage,
    password: &[u8],
) -> Result<bool, RsbError> {
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
                "{} is a v3 blob but {} is missing; restore the key file from a backup \
                 (`rsb key import`)",
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
pub(crate) fn looks_encrypted(raw: &[u8]) -> bool {
    const ZSTD_MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];
    !(raw.starts_with(&ZSTD_MAGIC) || std::str::from_utf8(raw).is_ok())
}

/// Creates `keys/repo.key` with a new random DEK. Fails if it exists.
///
/// Holds the exclusive repository lock so two first backups cannot race
/// and create two different keys. If the repository already holds v1/v2
/// encrypted snapshots, `password` must open the newest one: the v1/v2
/// objects stay readable with the same password until `rsb key migrate`
/// re-encrypts them as v3 (and `rsb key change-password` refuses to run
/// while any remain).
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
    // The v1/v2 objects keep opening with `password` (KeyCache falls back
    // to it); change-password refuses until `rsb key migrate` rewrote them,
    // so the legacy password never needs to be stored.
    let key = Arc::new(RepoKey::generate()?);
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
            "; existing v1/v2 objects stay readable with the same password until \
             `rsb key migrate` re-encrypts them"
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
/// Refused while v1/v2 objects or manifests remain (run `rsb key migrate`
/// first: their keys derive from the old password and cannot be rewrapped)
/// and while a key rotation is unfinished. The new file never holds the
/// legacy password.
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
    let raw = read_key_file_raw(storage).await?;
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
    if key.is_rotating() {
        return Err(RsbError::InvalidInput(
            "A key rotation is unfinished: run `rsb key rotate` again to complete it before \
             changing the password"
                .into(),
        ));
    }
    let cache = super::KeyCache::with_repo_key(old_password, key.clone());
    let legacy = super::lifecycle::legacy_blockers(storage, &cache).await?;
    if legacy > 0 {
        return Err(RsbError::InvalidInput(format!(
            "The repository still holds {} v1/v2 (pre-v3) object(s) or manifest(s), encrypted \
             with a key derived from the current password. Run `rsb key migrate` to \
             re-encrypt them as v3 first, then change the password.",
            legacy
        )));
    }
    // The new file never holds the legacy password (nothing needs it).
    let expected = key.without_legacy();
    let mut new_file = wrap_blocking(Arc::new(key.without_legacy()), new_password, params).await?;
    new_file.created_at = current.created_at.clone();
    new_file.updated_at = Some(chrono::Utc::now().to_rfc3339());
    replace_key_file(storage, &raw, &new_file, new_password, &expected).await?;
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
        assert_eq!(back.key_id(), Some(key.key_id_hex().as_str()));
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
        f.wrapped_dek = seal(&kek, &kdf_aad(&weak, &salt), &key.primary.key[..]).unwrap();
        let f = RepoKeyFile::from_bytes(&f.to_bytes().unwrap()).unwrap();
        assert!(f.unwrap_key(b"pw").unwrap().same_key(&key));
    }

    /// Key files written by earlier versions may hold `legacy_secret`: it
    /// is still read, but never written again.
    #[test]
    fn legacy_secret_is_read_but_not_rewritten() {
        let key = RepoKey::generate().unwrap();
        let mut f1 = key.wrap(b"a", fast()).unwrap();
        assert!(!f1.has_legacy_secret());
        f1.add_legacy_secret(&key, b"old-pw");
        // An old file (no key id) with a legacy secret.
        f1.key_id = None;
        let f1 = RepoKeyFile::from_bytes(&f1.to_bytes().unwrap()).unwrap();
        assert!(f1.has_legacy_secret());
        let k1 = f1.unwrap_key(b"a").unwrap();
        assert_eq!(k1.legacy_password(), Some(&b"old-pw"[..]));
        let f2 = k1.wrap(b"b", fast()).unwrap();
        assert!(!f2.has_legacy_secret());
        let json = String::from_utf8(f2.to_bytes().unwrap()).unwrap();
        assert!(!json.contains("legacy_secret"));
        assert_eq!(f2.unwrap_key(b"b").unwrap().legacy_password(), None);
        let f3 = f1.without_legacy_secret();
        assert!(!f3.has_legacy_secret());
        assert!(f3.unwrap_key(b"a").unwrap().same_key(&k1.without_legacy()));
    }

    #[test]
    fn key_id_mismatch_is_corrupt() {
        let key = RepoKey::generate().unwrap();
        let mut f = key.wrap(b"pw", fast()).unwrap();
        f.key_id = Some("00000000".into());
        if key.key_id_hex() == "00000000" {
            return;
        }
        assert!(matches!(
            f.unwrap_key(b"pw").unwrap_err(),
            RsbError::Crypto {
                kind: CryptoErrorKind::Corrupt,
                ..
            }
        ));
    }

    #[test]
    fn rotation_state_roundtrips_and_selects_keys_by_id() {
        let old = RepoKey::generate().unwrap();
        let blob_old = old.encrypt_object("oid", b"old data").unwrap();
        // Blob written before key ids existed (no flag): primary key.
        let unflagged =
            crate::crypto::stream::encrypt_v3(&old.primary.key, None, "oid", b"unflagged").unwrap();
        let rot = old.begin_rotation().unwrap();
        assert!(rot.is_rotating());
        assert_ne!(rot.key_id(), old.key_id());
        let blob_new = rot.encrypt_object("oid", b"new data").unwrap();

        let f = rot.wrap(b"pw", fast()).unwrap();
        assert!(f.is_rotating());
        let back = RepoKeyFile::from_bytes(&f.to_bytes().unwrap())
            .unwrap()
            .unwrap_key(b"pw")
            .unwrap();
        assert!(back.same_key(&rot));
        for (blob, pt) in [
            (&blob_old, &b"old data"[..]),
            (&blob_new, b"new data"),
            (&unflagged, b"unflagged"),
        ] {
            assert_eq!(back.decrypt_object("oid", blob).unwrap(), pt);
        }
        // The end state opens only blobs of the new key.
        let fin = back.only_active();
        assert_eq!(fin.decrypt_object("oid", &blob_new).unwrap(), b"new data");
        let e = fin.decrypt_object("oid", &blob_old).unwrap_err();
        assert!(crate::crypto::is_authentication_error(&e));
        // The old key alone does not open new blobs.
        let e = old.decrypt_object("oid", &blob_new).unwrap_err();
        assert!(crate::crypto::is_authentication_error(&e));
        // Swapping the two wrapped keys is detected.
        let mut swapped = f.clone();
        let r = swapped.rotation.as_mut().unwrap();
        std::mem::swap(&mut r.wrapped_dek, &mut swapped.wrapped_dek);
        assert!(swapped.unwrap_key(b"pw").is_err());
        assert!(rot.begin_rotation().is_err());
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
