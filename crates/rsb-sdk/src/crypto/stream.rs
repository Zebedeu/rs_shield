//! Blob format v3: per-blob key + chunked streaming AEAD (STREAM).
//!
//! Layout (see `docs/FORMAT.md` for the normative description):
//!
//! ```text
//! header (45 bytes) = "RSBENCv3" (8) | flags u8 (1) | blob salt (32) | chunk size u32 BE (4)
//!                     with flag 0x01 (key id): blob salt = key id (4) | random (28)
//! body              = chunk_0 | chunk_1 | ... | chunk_n      (n >= 0, chunk_n is the final chunk)
//! chunk_i           = AES-256-GCM(K_blob, nonce_i, AAD, plaintext_i) = ciphertext_i | tag (16)
//! ```
//!
//! * `K_blob = HKDF-SHA256(ikm = DEK, salt = blob salt, info = "rsb v3 blob")`, 32 bytes.
//!   The blob salt is random per blob, so every blob has its own key and the
//!   nonce does not need a random part.
//! * `nonce_i = i as u64 BE (8) | 0x00 0x00 0x00 | last (1)` where `last` is
//!   `0x01` for the final chunk and `0x00` otherwise.
//! * Every non-final chunk carries exactly `chunk size` plaintext bytes; the
//!   final chunk carries `0..=chunk size` bytes (an empty blob is a single,
//!   empty, final chunk).
//! * `AAD = header (45 bytes) | object id` for every chunk.
//!
//! # Why the object id is bound into the AAD
//!
//! The object id is the name the blob is stored under: the BLAKE3 content
//! hash for data objects (`data/enc/<hash>`) and the storage key for
//! manifests (`snapshots/<name>.toml`). Binding it means a blob only opens
//! under the name it was written for: an attacker with write access to the
//! repository cannot swap two valid blobs (e.g. replace `data/enc/<A>` with
//! the bytes of `data/enc/<B>`) without decryption failing. It is the
//! content hash and **not** the source file path on purpose: identical
//! content from different files maps to the same object, so deduplication
//! keeps working and the path never has to be known to read the object.
//!
//! The counter in the nonce rejects reordering, the `last` flag rejects
//! truncation at a chunk boundary (the new last chunk was sealed as
//! non-final) and extension (the real final chunk is no longer last), and
//! the header in the AAD rejects any header change.

use super::CryptoError;
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use ring::hkdf;
use ring::rand::{SecureRandom, SystemRandom};
use std::io::{self, ErrorKind, Write};
use tokio::io::{AsyncRead, AsyncReadExt};
use zeroize::Zeroizing;

/// Magic marker of the v3 blob format.
pub const BLOB_MAGIC_V3: &[u8; 8] = b"RSBENCv3";
/// Length of the v3 header: magic(8) + flags(1) + salt(32) + chunk size(4).
pub const V3_HEADER_LEN: usize = 8 + 1 + V3_SALT_LEN + 4;
/// Length of the random per-blob salt.
pub const V3_SALT_LEN: usize = 32;
/// AES-GCM tag length (one per chunk).
pub const V3_TAG_LEN: usize = 16;
/// Plaintext bytes per chunk written by this version.
pub const V3_DEFAULT_CHUNK_SIZE: u32 = 1024 * 1024;
/// Smallest chunk size accepted from a header.
pub const V3_MIN_CHUNK_SIZE: u32 = 16;
/// Largest chunk size accepted from a header: bounds the memory a reader
/// allocates for one chunk, whatever the (untrusted) header says.
pub const V3_MAX_CHUNK_SIZE: u32 = 16 * 1024 * 1024;
/// HKDF `info` for per-blob keys.
pub const V3_HKDF_INFO: &[u8] = b"rsb v3 blob";
/// Header flag: the first [`KEY_ID_LEN`] bytes of the blob salt are the
/// key id of the DEK that encrypted the blob (see [`key_id_of`]). Blobs
/// without it were written before key ids existed and belong to the
/// repository's primary key.
pub const V3_FLAG_KEY_ID: u8 = 0x01;
/// Flags understood by this version.
const V3_KNOWN_FLAGS: u8 = V3_FLAG_KEY_ID;
/// Length of a key id.
pub const KEY_ID_LEN: usize = 4;
/// Short identifier of a DEK (see [`key_id_of`]).
pub type KeyId = [u8; KEY_ID_LEN];
/// HKDF `info` of the key id.
const KEY_ID_INFO: &[u8] = b"rsb v3 key id";

/// Length of a 32-byte data encryption key.
pub const DEK_LEN: usize = 32;

/// Key id of a DEK: the first 4 bytes of
/// `HKDF-SHA256(IKM = DEK, salt = "", info = "rsb v3 key id")`. A PRF output,
/// so it reveals nothing useful about the DEK; it only tells readers which
/// DEK of the key file opens a blob.
pub fn key_id_of(dek: &[u8; DEK_LEN]) -> KeyId {
    struct Len;
    impl hkdf::KeyType for Len {
        fn len(&self) -> usize {
            KEY_ID_LEN
        }
    }
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]).extract(dek);
    let mut out = [0u8; KEY_ID_LEN];
    // Cannot fail: the output length is far below 255 * 32.
    if let Ok(okm) = prk.expand(&[KEY_ID_INFO], Len) {
        let _ = okm.fill(&mut out);
    }
    out
}

/// Stored size of a v3 blob holding `payload_len` bytes with `chunk_size`.
pub fn v3_blob_len(payload_len: u64, chunk_size: u32) -> u64 {
    let cs = chunk_size.max(1) as u64;
    // An empty payload is still one (empty) final chunk; a payload that is
    // an exact multiple of the chunk size ends with a full final chunk.
    let chunks = payload_len.div_ceil(cs).max(1);
    V3_HEADER_LEN as u64 + payload_len + chunks * V3_TAG_LEN as u64
}

fn malformed(msg: &str) -> io::Error {
    io::Error::new(
        ErrorKind::InvalidData,
        MalformedBlob {
            detail: msg.to_string(),
        },
    )
}

/// Inner error for structurally invalid v3 blobs; classified as
/// [`CryptoError::Malformed`] by [`super::crypto_error_of`].
#[derive(Debug)]
pub(crate) struct MalformedBlob {
    pub(crate) detail: String,
}

impl std::fmt::Display for MalformedBlob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", CryptoError::Malformed, self.detail)
    }
}

impl std::error::Error for MalformedBlob {}

/// Parsed v3 header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V3Header {
    pub flags: u8,
    pub salt: [u8; V3_SALT_LEN],
    pub chunk_size: u32,
}

impl V3Header {
    /// Key id carried by the header ([`V3_FLAG_KEY_ID`]), if any.
    pub fn key_id(&self) -> Option<KeyId> {
        if self.flags & V3_FLAG_KEY_ID == 0 {
            return None;
        }
        let mut id = [0u8; KEY_ID_LEN];
        id.copy_from_slice(&self.salt[..KEY_ID_LEN]);
        Some(id)
    }

    pub fn to_bytes(&self) -> [u8; V3_HEADER_LEN] {
        let mut h = [0u8; V3_HEADER_LEN];
        h[..8].copy_from_slice(BLOB_MAGIC_V3);
        h[8] = self.flags;
        h[9..9 + V3_SALT_LEN].copy_from_slice(&self.salt);
        h[9 + V3_SALT_LEN..].copy_from_slice(&self.chunk_size.to_be_bytes());
        h
    }

    /// Parses and validates a header (magic, known flags, chunk size bounds).
    pub fn parse(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() < V3_HEADER_LEN {
            return Err(malformed("truncated v3 header"));
        }
        if &bytes[..8] != BLOB_MAGIC_V3 {
            return Err(malformed("not a v3 blob"));
        }
        let flags = bytes[8];
        if flags & !V3_KNOWN_FLAGS != 0 {
            return Err(malformed("unknown v3 header flags"));
        }
        let mut salt = [0u8; V3_SALT_LEN];
        salt.copy_from_slice(&bytes[9..9 + V3_SALT_LEN]);
        let chunk_size = u32::from_be_bytes(
            bytes[9 + V3_SALT_LEN..V3_HEADER_LEN]
                .try_into()
                .map_err(|_| malformed("truncated v3 header"))?,
        );
        if !(V3_MIN_CHUNK_SIZE..=V3_MAX_CHUNK_SIZE).contains(&chunk_size) {
            return Err(malformed("v3 chunk size out of bounds"));
        }
        Ok(Self {
            flags,
            salt,
            chunk_size,
        })
    }
}

/// Derives the per-blob AES-256-GCM key from the DEK and the blob salt.
fn blob_key(dek: &[u8; DEK_LEN], salt: &[u8; V3_SALT_LEN]) -> io::Result<LessSafeKey> {
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, salt).extract(dek);
    let okm = prk
        .expand(&[V3_HKDF_INFO], &AES_256_GCM)
        .map_err(|_| io::Error::other("HKDF expand failed"))?;
    Ok(LessSafeKey::new(UnboundKey::from(okm)))
}

/// Raw HKDF output (test vectors / independent checks only).
#[cfg(test)]
pub(crate) fn blob_key_bytes(dek: &[u8; DEK_LEN], salt: &[u8; V3_SALT_LEN]) -> [u8; 32] {
    struct Len32;
    impl hkdf::KeyType for Len32 {
        fn len(&self) -> usize {
            32
        }
    }
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, salt).extract(dek);
    let okm = prk.expand(&[V3_HKDF_INFO], Len32).unwrap();
    let mut out = [0u8; 32];
    okm.fill(&mut out).unwrap();
    out
}

/// Nonce of chunk `counter`: `counter BE (8) | 0 0 0 | last`.
pub(crate) fn chunk_nonce(counter: u64, last: bool) -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    n[..8].copy_from_slice(&counter.to_be_bytes());
    n[11] = last as u8;
    n
}

fn build_aad(header: &[u8; V3_HEADER_LEN], object_id: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(V3_HEADER_LEN + object_id.len());
    aad.extend_from_slice(header);
    aad.extend_from_slice(object_id.as_bytes());
    aad
}

/// Streaming v3 encryptor. Writes the header immediately, then one
/// ciphertext chunk each time `chunk_size` plaintext bytes are buffered and
/// more data follows; [`StreamEncryptor::finish`] seals the final chunk.
/// Memory: one chunk of plaintext.
pub struct StreamEncryptor<W: Write> {
    inner: W,
    key: LessSafeKey,
    aad: Vec<u8>,
    buf: Zeroizing<Vec<u8>>,
    chunk_size: usize,
    counter: u64,
}

impl<W: Write> StreamEncryptor<W> {
    /// New encryptor with a random blob salt and the default chunk size.
    /// With `key_id`, the header carries [`V3_FLAG_KEY_ID`] and the first
    /// [`KEY_ID_LEN`] salt bytes are the key id (28 random bytes remain).
    pub fn new(
        dek: &[u8; DEK_LEN],
        key_id: Option<KeyId>,
        object_id: &str,
        inner: W,
    ) -> io::Result<Self> {
        let mut salt = [0u8; V3_SALT_LEN];
        SystemRandom::new()
            .fill(&mut salt)
            .map_err(|_| io::Error::other("Failed to generate blob salt"))?;
        let flags = match key_id {
            Some(id) => {
                salt[..KEY_ID_LEN].copy_from_slice(&id);
                V3_FLAG_KEY_ID
            }
            None => 0,
        };
        Self::build(dek, flags, salt, V3_DEFAULT_CHUNK_SIZE, object_id, inner)
    }

    /// Deterministic constructor. A salt must never be reused with the same
    /// DEK for different content: only tests use this directly.
    #[cfg(test)]
    pub(crate) fn with_params(
        dek: &[u8; DEK_LEN],
        salt: [u8; V3_SALT_LEN],
        chunk_size: u32,
        object_id: &str,
        inner: W,
    ) -> io::Result<Self> {
        Self::build(dek, 0, salt, chunk_size, object_id, inner)
    }

    fn build(
        dek: &[u8; DEK_LEN],
        flags: u8,
        salt: [u8; V3_SALT_LEN],
        chunk_size: u32,
        object_id: &str,
        mut inner: W,
    ) -> io::Result<Self> {
        let header = V3Header {
            flags,
            salt,
            chunk_size,
        };
        // Validates the chunk size like a reader would.
        V3Header::parse(&header.to_bytes())?;
        let header = header.to_bytes();
        inner.write_all(&header)?;
        Ok(Self {
            inner,
            key: blob_key(dek, &salt)?,
            aad: build_aad(&header, object_id),
            buf: Zeroizing::new(Vec::with_capacity(chunk_size as usize + V3_TAG_LEN)),
            chunk_size: chunk_size as usize,
            counter: 0,
        })
    }

    fn seal_chunk(&mut self, last: bool) -> io::Result<()> {
        let nonce = Nonce::assume_unique_for_key(chunk_nonce(self.counter, last));
        let tag = self
            .key
            .seal_in_place_separate_tag(nonce, Aad::from(&self.aad[..]), &mut self.buf[..])
            .map_err(|_| io::Error::other("Encryption failed"))?;
        self.inner.write_all(&self.buf)?;
        self.inner.write_all(tag.as_ref())?;
        self.buf.clear();
        self.counter = self
            .counter
            .checked_add(1)
            .ok_or_else(|| io::Error::other("v3 chunk counter overflow"))?;
        Ok(())
    }

    /// Seals the final chunk and returns the inner writer.
    pub fn finish(mut self) -> io::Result<W> {
        self.seal_chunk(true)?;
        self.inner.flush()?;
        Ok(self.inner)
    }
}

impl<W: Write> Write for StreamEncryptor<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        // A full buffer is only sealed (as non-final) once we know more
        // data follows; otherwise `finish` seals it as the final chunk.
        if self.buf.len() == self.chunk_size {
            self.seal_chunk(false)?;
        }
        let n = data.len().min(self.chunk_size - self.buf.len());
        self.buf.extend_from_slice(&data[..n]);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        // Chunks are only emitted once complete; nothing else to flush.
        self.inner.flush()
    }
}

/// One-shot v3 encryption of an in-memory payload.
pub fn encrypt_v3(
    dek: &[u8; DEK_LEN],
    key_id: Option<KeyId>,
    object_id: &str,
    data: &[u8],
) -> io::Result<Vec<u8>> {
    let cap = v3_blob_len(data.len() as u64, V3_DEFAULT_CHUNK_SIZE) as usize;
    let mut enc = StreamEncryptor::new(dek, key_id, object_id, Vec::with_capacity(cap))?;
    enc.write_all(data)?;
    enc.finish()
}

/// True if `blob` starts with the v3 magic.
pub fn is_v3(blob: &[u8]) -> bool {
    blob.starts_with(BLOB_MAGIC_V3)
}

/// Opens one chunk in place; returns the plaintext length.
fn open_chunk(
    key: &LessSafeKey,
    aad: &[u8],
    counter: u64,
    last: bool,
    chunk: &mut [u8],
) -> io::Result<usize> {
    if chunk.len() < V3_TAG_LEN {
        return Err(malformed("truncated v3 chunk"));
    }
    let nonce = Nonce::assume_unique_for_key(chunk_nonce(counter, last));
    key.open_in_place(nonce, Aad::from(aad), chunk)
        .map(|p| p.len())
        .map_err(|_| CryptoError::AuthenticationFailed.into())
}

/// One-shot v3 decryption of a blob held in memory.
pub fn decrypt_v3(dek: &[u8; DEK_LEN], object_id: &str, blob: &[u8]) -> io::Result<Vec<u8>> {
    let header = V3Header::parse(blob)?;
    let header_bytes = header.to_bytes();
    let key = blob_key(dek, &header.salt)?;
    let aad = build_aad(&header_bytes, object_id);
    let ct_chunk = header.chunk_size as usize + V3_TAG_LEN;

    let mut body = &blob[V3_HEADER_LEN..];
    if body.is_empty() {
        return Err(malformed("v3 blob has no final chunk"));
    }
    let mut out = Vec::with_capacity(body.len());
    let mut scratch = Vec::with_capacity(ct_chunk.min(body.len()));
    let mut counter: u64 = 0;
    loop {
        // Same rule as the streaming reader: a chunk is non-final iff more
        // bytes follow a full-size chunk.
        let last = body.len() <= ct_chunk;
        let take = if last { body.len() } else { ct_chunk };
        scratch.clear();
        scratch.extend_from_slice(&body[..take]);
        let n = open_chunk(&key, &aad, counter, last, &mut scratch)?;
        out.extend_from_slice(&scratch[..n]);
        body = &body[take..];
        if last {
            return Ok(out);
        }
        counter = counter
            .checked_add(1)
            .ok_or_else(|| malformed("v3 chunk counter overflow"))?;
    }
}

/// Streaming v3 decryptor over an async reader. Memory: one ciphertext
/// chunk (`chunk_size + 16` bytes, at most [`V3_MAX_CHUNK_SIZE`] + 17).
///
/// Every chunk returned by [`StreamDecryptor::next_chunk`] has been
/// authenticated; the caller must still treat the stream as failed (and
/// discard what it wrote) unless `next_chunk` eventually returns
/// `Ok(None)`, which proves the final chunk was seen and nothing follows.
pub struct StreamDecryptor<R> {
    reader: R,
    key: LessSafeKey,
    aad: Vec<u8>,
    ct_chunk: usize,
    buf: Vec<u8>,
    carry: Option<u8>,
    counter: u64,
    done: bool,
    header: V3Header,
}

impl<R: AsyncRead + Unpin> StreamDecryptor<R> {
    /// Reads and validates the header, then derives the blob key.
    /// `prefix` are bytes already consumed from `reader` (e.g. the magic
    /// read to detect the format); at most [`V3_HEADER_LEN`] bytes.
    pub async fn new(
        dek: &[u8; DEK_LEN],
        object_id: &str,
        prefix: &[u8],
        reader: R,
    ) -> io::Result<Self> {
        Self::with_resolver(|_| Ok(dek), object_id, prefix, reader).await
    }

    /// Like [`StreamDecryptor::new`], but picks the DEK from the parsed
    /// header (e.g. by its key id) with `resolve`.
    pub async fn with_resolver<'k, F>(
        resolve: F,
        object_id: &str,
        prefix: &[u8],
        mut reader: R,
    ) -> io::Result<Self>
    where
        F: FnOnce(&V3Header) -> io::Result<&'k [u8; DEK_LEN]>,
    {
        if prefix.len() > V3_HEADER_LEN {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "prefix longer than the v3 header",
            ));
        }
        let mut header_bytes = [0u8; V3_HEADER_LEN];
        header_bytes[..prefix.len()].copy_from_slice(prefix);
        let got = read_full(&mut reader, &mut header_bytes[prefix.len()..]).await?;
        if prefix.len() + got < V3_HEADER_LEN {
            return Err(malformed("truncated v3 header"));
        }
        let header = V3Header::parse(&header_bytes)?;
        let dek = resolve(&header)?;
        let ct_chunk = header.chunk_size as usize + V3_TAG_LEN;
        Ok(Self {
            reader,
            key: blob_key(dek, &header.salt)?,
            aad: build_aad(&header_bytes, object_id),
            ct_chunk,
            buf: Vec::with_capacity(ct_chunk + 1),
            carry: None,
            counter: 0,
            done: false,
            header,
        })
    }

    pub fn header(&self) -> &V3Header {
        &self.header
    }

    /// Next authenticated plaintext chunk, or `None` after the final chunk.
    pub async fn next_chunk(&mut self) -> io::Result<Option<&[u8]>> {
        if self.done {
            return Ok(None);
        }
        self.buf.clear();
        if let Some(b) = self.carry.take() {
            self.buf.push(b);
        }
        // Read one full chunk plus one byte: the extra byte tells whether
        // this chunk is followed by more data (non-final) or by EOF (final).
        let want = self.ct_chunk + 1;
        let start = self.buf.len();
        self.buf.resize(want, 0);
        let got = read_full(&mut self.reader, &mut self.buf[start..]).await?;
        self.buf.truncate(start + got);

        let last = self.buf.len() < want;
        if !last {
            self.carry = self.buf.pop();
        }
        if self.buf.is_empty() {
            return Err(malformed("v3 blob has no final chunk"));
        }
        let n = open_chunk(&self.key, &self.aad, self.counter, last, &mut self.buf[..])?;
        if last {
            self.done = true;
        } else {
            self.counter = self
                .counter
                .checked_add(1)
                .ok_or_else(|| malformed("v3 chunk counter overflow"))?;
        }
        Ok(Some(&self.buf[..n]))
    }
}

/// Fills `buf` from `reader` until full or EOF; returns bytes read.
async fn read_full<R: AsyncRead + Unpin>(reader: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]).await {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{CryptoError, crypto_error_of};

    const DEK: [u8; 32] = [0x11; 32];
    const SALT: [u8; 32] = [0x22; 32];
    const OID: &str = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";

    fn enc(data: &[u8], cs: u32, oid: &str) -> Vec<u8> {
        let mut e = StreamEncryptor::with_params(&DEK, SALT, cs, oid, Vec::new()).unwrap();
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }

    async fn stream_dec(blob: &[u8], oid: &str) -> io::Result<Vec<u8>> {
        let mut d = StreamDecryptor::new(&DEK, oid, &[], blob).await?;
        let mut out = Vec::new();
        while let Some(c) = d.next_chunk().await? {
            out.extend_from_slice(c);
        }
        Ok(out)
    }

    /// HKDF-SHA256 output for (DEK=0x11*32, salt=0x22*32, info="rsb v3 blob"),
    /// computed independently with Python's hmac/hashlib (RFC 5869).
    const KAT_BLOB_KEY: &str = "d3e235de75a6140f8135f3eda8788dd33c0b8135e38b3536c6ec96d364f5b039";

    #[test]
    fn kat_hkdf_blob_key() {
        assert_eq!(hex(&blob_key_bytes(&DEK, &SALT)), KAT_BLOB_KEY);
    }

    /// Known-answer vectors: fixed DEK, salt, chunk size and object id.
    #[test]
    fn kat_v3_vectors() {
        let vectors: &[(&[u8], u32, &str)] = &[
            (
                b"",
                16,
                "525342454e43763300222222222222222222222222222222222222222222222222222222222222222200000010dea800c9a96d5b155d26fa95e0b67c33",
            ),
            (
                b"rsb",
                16,
                "525342454e4376330022222222222222222222222222222222222222222222222222222222222222220000001090cb4cce0d4f0f08ba37eb075e9e424295d34f",
            ),
            (
                b"0123456789abcdef0123456789abcdefXYZ",
                16,
                "525342454e437633002222222222222222222222222222222222222222222222222222222222222222000000106f9040a0fce16efb84d33bdefd651f369f2bab8b6845b87e6027f2f5f3158b50849edbc2cb58fb48cb1a56edb972e36f971f8b783f6f006a0db738582505746dd4f4ad9f74e762ca2c79dd6b057581954646d3",
            ),
        ];
        for (pt, cs, expected) in vectors {
            let blob = enc(pt, *cs, OID);
            assert_eq!(&hex(&blob), expected, "pt={:?}", pt);
            assert_eq!(decrypt_v3(&DEK, OID, &blob).unwrap(), *pt);
            assert_eq!(blob.len() as u64, v3_blob_len(pt.len() as u64, *cs));
        }
    }

    /// Cross-checks the chunk construction with an independent AES-GCM
    /// implementation (RustCrypto `aes-gcm`) using the HKDF test vector key.
    #[test]
    fn independent_aes_gcm_opens_chunks() {
        use aes_gcm::aead::{Aead, KeyInit, Payload};
        use aes_gcm::{Aes256Gcm, Nonce as GNonce};
        let pt = b"0123456789abcdef0123456789abcdefXYZ";
        let blob = enc(pt, 16, OID);
        let key = blob_key_bytes(&DEK, &SALT);
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let mut aad = blob[..V3_HEADER_LEN].to_vec();
        aad.extend_from_slice(OID.as_bytes());
        let body = &blob[V3_HEADER_LEN..];
        let mut out = Vec::new();
        for (i, chunk) in body.chunks(32).enumerate() {
            let last = (i + 1) * 32 >= body.len();
            let nonce = chunk_nonce(i as u64, last);
            let p = cipher
                .decrypt(
                    GNonce::from_slice(&nonce),
                    Payload {
                        msg: chunk,
                        aad: &aad,
                    },
                )
                .unwrap();
            out.extend_from_slice(&p);
        }
        assert_eq!(out, pt);
    }

    #[tokio::test]
    async fn roundtrip_boundaries() {
        let cs = 64u32;
        for len in [0usize, 1, 63, 64, 65, 128, 129, 1000] {
            let pt: Vec<u8> = (0..len).map(|i| (i * 7 % 251) as u8).collect();
            let blob = enc(&pt, cs, OID);
            assert_eq!(blob.len() as u64, v3_blob_len(len as u64, cs));
            assert_eq!(decrypt_v3(&DEK, OID, &blob).unwrap(), pt, "len {}", len);
            assert_eq!(stream_dec(&blob, OID).await.unwrap(), pt, "len {}", len);
        }
    }

    #[tokio::test]
    async fn default_chunk_size_roundtrip() {
        let cs = V3_DEFAULT_CHUNK_SIZE as usize;
        for len in [0, 1, cs, cs + 1, 3 * cs + 17] {
            let pt: Vec<u8> = (0..len).map(|i| (i % 253) as u8).collect();
            let blob = encrypt_v3(&DEK, None, OID, &pt).unwrap();
            assert_eq!(
                blob.len() as u64,
                v3_blob_len(len as u64, V3_DEFAULT_CHUNK_SIZE)
            );
            assert_eq!(decrypt_v3(&DEK, OID, &blob).unwrap(), pt);
            assert_eq!(stream_dec(&blob, OID).await.unwrap(), pt);
        }
    }

    fn kind(e: &io::Error) -> Option<CryptoError> {
        crypto_error_of(e)
    }

    async fn both_reject(blob: &[u8], oid: &str) -> (Option<CryptoError>, Option<CryptoError>) {
        let a = decrypt_v3(&DEK, oid, blob).unwrap_err();
        let b = stream_dec(blob, oid).await.unwrap_err();
        (kind(&a), kind(&b))
    }

    #[tokio::test]
    async fn tampering_is_rejected() {
        use CryptoError::*;
        let cs = 16u32;
        let pt: Vec<u8> = (0..40u8).collect(); // chunks: 16, 16, 8 (final)
        let blob = enc(&pt, cs, OID);
        let ct = cs as usize + V3_TAG_LEN;
        let h = V3_HEADER_LEN;

        // Header byte (salt) flipped.
        let mut b = blob.clone();
        b[12] ^= 1;
        assert_eq!(
            both_reject(&b, OID).await,
            (Some(AuthenticationFailed), Some(AuthenticationFailed))
        );
        // Unknown flag / bad magic / chunk size out of bounds: malformed.
        for i in [0usize, 8, h - 1] {
            let mut b = blob.clone();
            b[i] ^= 0x80;
            let (x, y) = both_reject(&b, OID).await;
            assert!(x.is_some() && y.is_some(), "byte {}", i);
        }
        // Ciphertext byte flipped.
        let mut b = blob.clone();
        b[h + 3] ^= 1;
        assert_eq!(
            both_reject(&b, OID).await,
            (Some(AuthenticationFailed), Some(AuthenticationFailed))
        );
        // Two chunks swapped.
        let mut b = blob[..h].to_vec();
        b.extend_from_slice(&blob[h + ct..h + 2 * ct]);
        b.extend_from_slice(&blob[h..h + ct]);
        b.extend_from_slice(&blob[h + 2 * ct..]);
        assert_eq!(
            both_reject(&b, OID).await,
            (Some(AuthenticationFailed), Some(AuthenticationFailed))
        );
        // Final chunk dropped (truncation at a chunk boundary).
        let b = blob[..h + 2 * ct].to_vec();
        assert_eq!(
            both_reject(&b, OID).await,
            (Some(AuthenticationFailed), Some(AuthenticationFailed))
        );
        // Everything after the header dropped.
        let b = blob[..h].to_vec();
        assert_eq!(
            both_reject(&b, OID).await,
            (Some(Malformed), Some(Malformed))
        );
        // Extra chunk appended after the final one.
        let mut b = blob.clone();
        b.extend_from_slice(&blob[h..h + ct]);
        assert_eq!(
            both_reject(&b, OID).await,
            (Some(AuthenticationFailed), Some(AuthenticationFailed))
        );
        // Truncated in the middle of a chunk.
        let b = blob[..h + ct + 20].to_vec();
        assert_eq!(
            both_reject(&b, OID).await,
            (Some(AuthenticationFailed), Some(AuthenticationFailed))
        );
        // Truncated inside the final chunk's tag (fewer than 16 bytes left).
        let b = blob[..h + 2 * ct + 3].to_vec();
        assert_eq!(
            both_reject(&b, OID).await,
            (Some(Malformed), Some(Malformed))
        );
        // Wrong object id (blob moved to another name).
        let other = "0".repeat(64);
        assert_eq!(
            both_reject(&blob, &other).await,
            (Some(AuthenticationFailed), Some(AuthenticationFailed))
        );
        // Wrong DEK.
        assert_eq!(
            kind(&decrypt_v3(&[0x12; 32], OID, &blob).unwrap_err()),
            Some(AuthenticationFailed)
        );
        // Truncated header.
        assert_eq!(
            both_reject(&blob[..20], OID).await,
            (Some(Malformed), Some(Malformed))
        );
    }

    #[test]
    fn header_bounds() {
        let mut h = V3Header {
            flags: 0,
            salt: SALT,
            chunk_size: V3_MAX_CHUNK_SIZE + 1,
        };
        assert!(V3Header::parse(&h.to_bytes()).is_err());
        h.chunk_size = V3_MIN_CHUNK_SIZE - 1;
        assert!(V3Header::parse(&h.to_bytes()).is_err());
        h.chunk_size = V3_DEFAULT_CHUNK_SIZE;
        assert_eq!(V3Header::parse(&h.to_bytes()).unwrap(), h);
        assert!(StreamEncryptor::with_params(&DEK, SALT, 1, OID, Vec::new()).is_err());
    }

    #[test]
    fn distinct_salts_give_distinct_blobs() {
        let a = encrypt_v3(&DEK, None, OID, b"same").unwrap();
        let b = encrypt_v3(&DEK, None, OID, b"same").unwrap();
        assert_ne!(a, b);
    }

    #[tokio::test]
    async fn key_id_flag_roundtrips_and_is_authenticated() {
        let id = key_id_of(&DEK);
        assert_ne!(id, key_id_of(&[0x12; 32]));
        let blob = encrypt_v3(&DEK, Some(id), OID, b"payload").unwrap();
        let h = V3Header::parse(&blob).unwrap();
        assert_eq!(h.flags, V3_FLAG_KEY_ID);
        assert_eq!(h.key_id(), Some(id));
        // Same length as an unflagged blob: sizes do not depend on the id.
        assert_eq!(blob.len() as u64, v3_blob_len(7, V3_DEFAULT_CHUNK_SIZE));
        assert_eq!(decrypt_v3(&DEK, OID, &blob).unwrap(), b"payload");
        assert_eq!(stream_dec(&blob, OID).await.unwrap(), b"payload");
        // Unflagged blobs (written before key ids) carry no id.
        let old = enc(b"payload", 16, OID);
        assert_eq!(V3Header::parse(&old).unwrap().key_id(), None);
        // Clearing the flag or changing the id breaks authentication.
        let mut b = blob.clone();
        b[8] = 0;
        assert_eq!(
            kind(&decrypt_v3(&DEK, OID, &b).unwrap_err()),
            Some(CryptoError::AuthenticationFailed)
        );
        let mut b = blob.clone();
        b[9] ^= 1;
        assert_eq!(
            kind(&decrypt_v3(&DEK, OID, &b).unwrap_err()),
            Some(CryptoError::AuthenticationFailed)
        );
        // Unknown flags are still rejected.
        let mut b = blob;
        b[8] = 0x02;
        assert_eq!(
            kind(&decrypt_v3(&DEK, OID, &b).unwrap_err()),
            Some(CryptoError::Malformed)
        );
    }
}
