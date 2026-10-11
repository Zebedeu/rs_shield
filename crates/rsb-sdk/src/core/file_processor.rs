// file_processor.rs - dedup, compression and (v3 streaming) encryption of files
use super::dedup_index::DedupIndex;
use super::types::{CHUNK_SIZE, ChunkMetadata, FileMetadata, FileStatus, MULTIPART_THRESHOLD};
use crate::crypto::stream::{V3_HEADER_LEN, V3Header};
use crate::crypto::{
    BLOB_MAGIC_V2, BLOB_MAGIC_V3, RepoKey, V3_DEFAULT_CHUNK_SIZE, hash_file_content, v3_blob_len,
};
use crate::storage::Storage;
use glob::Pattern;
use std::collections::{HashMap, HashSet};
use std::fs::Metadata;
use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::Arc;
use tokio::runtime::Handle;
use tracing::warn;
use zstd::stream::write::Encoder as ZstdEncoder;

/// AES-GCM framing overhead of a legacy (v1) blob:
/// salt(16) + nonce(12) + tag(16). Also the smallest possible encrypted
/// object of any format.
const ENCRYPTION_OVERHEAD: u64 = 16 + 12 + 16;
/// Overhead of the versioned (v2) blob format: magic(8) + iterations(4) + legacy framing.
const ENCRYPTION_OVERHEAD_V2: u64 = 8 + 4 + ENCRYPTION_OVERHEAD;
/// Encrypted output up to this size is spooled in memory before the upload;
/// larger output spills to a temp file that is streamed to storage.
pub(crate) const SPOOL_MEM_LIMIT: usize = 8 * 1024 * 1024;
/// zstd level used when an existing object forces compression but the
/// profile has compression disabled.
const FALLBACK_COMPRESSION_LEVEL: u8 = 3;
/// Files up to this size are read into memory in one go; larger ones are
/// streamed (hash pass, then store pass) through a [`READ_BUF`] buffer.
const INLINE_READ_MAX: u64 = 1024 * 1024;
/// Read buffer of the streaming passes.
const READ_BUF: usize = 1024 * 1024;

/// How an existing object in `data/{enc,clear}/<hash>` was stored.
///
/// The zstd *level* never matters for decoding (frames are self-describing);
/// only whether the payload is a zstd frame at all. The `enc`/`clear` split
/// is part of the object path, so the encryption flag cannot be confused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StoredMode {
    Compressed,
    Uncompressed,
}

impl StoredMode {
    fn from_level(level: u8) -> Self {
        if level > 0 {
            StoredMode::Compressed
        } else {
            StoredMode::Uncompressed
        }
    }

    fn is_compressed(self) -> bool {
        self == StoredMode::Compressed
    }

    /// Level to use when writing a new object in this mode.
    fn write_level(self, configured: u8) -> u8 {
        match self {
            StoredMode::Uncompressed => 0,
            StoredMode::Compressed if configured > 0 => configured,
            StoredMode::Compressed => FALLBACK_COMPRESSION_LEVEL,
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn process_file(
    src: &Path,
    storage: &Arc<dyn Storage>,
    rel_path: &Path,
    encryption_key: Option<Arc<RepoKey>>, // repository key (v3); None = no encryption
    previous_metadata_cache: &HashMap<String, FileMetadata>,
    dry_run: bool,
    rt_handle: &Handle,
    encrypt_patterns: &Option<Vec<String>>,
    compression_level: u8,
    index: Option<&DedupIndex>, // local dedup index (None = ask storage)
) -> io::Result<(FileStatus, FileMetadata)> {
    let before = std::fs::metadata(src)?;
    let should_encrypt = should_encrypt_file(rel_path, encryption_key.as_deref(), encrypt_patterns);

    // =============== LARGE FILES (Multipart, streamed) ===============
    if before.len() > MULTIPART_THRESHOLD {
        let result = process_file_multipart_streaming(
            src,
            storage,
            should_encrypt,
            encryption_key.as_deref(),
            previous_metadata_cache,
            dry_run,
            rt_handle,
            compression_level,
            index,
        )?;
        ensure_unchanged(src, &before, None)?;
        return Ok(result);
    }

    // =============== NORMAL FILES ===============
    // Small files are read once into memory: the bytes we hash are exactly
    // the bytes we compress/store. Larger files are hashed in a streaming
    // pass and, only when they must be stored, streamed a second time
    // through compression/encryption while their hash is checked against
    // the first pass, so a file that changed in between is reported and
    // never stored. Memory per file stays bounded by the read buffer and
    // the upload spool, whatever the file size. No mmap (no SIGBUS if the
    // file is truncated).
    let inline = if before.len() <= INLINE_READ_MAX {
        let data = std::fs::read(src)?;
        ensure_unchanged(src, &before, Some(data.len() as u64))?;
        Some(data)
    } else {
        None
    };
    let (current_hash, plain_len) = match &inline {
        Some(data) => (hash_file_content(data)?, data.len() as u64),
        None => hash_reader(&mut std::fs::File::open(src)?)?,
    };

    // Fast deduplication against the previous snapshot - but only if the
    // object it points to is still there (`verify` with repair deletes
    // corrupt objects so that the next backup re-uploads them).
    if let Some(cached) = previous_metadata_cache.get(&current_hash) {
        if cached_objects_present(storage, rt_handle, index, cached, plain_len)? {
            if inline.is_none() {
                ensure_unchanged(src, &before, Some(plain_len))?;
            }
            return Ok((FileStatus::Skipped, cached.clone().with_size(plain_len)));
        }
        warn!(
            "Object for {} referenced by the previous snapshot is missing or damaged; re-uploading",
            rel_path.display()
        );
    }

    let data_path = format!(
        "data/{}/{}",
        if should_encrypt { "enc" } else { "clear" },
        current_hash
    );

    // File already exists in storage (deduplicated by hash) — but only trust
    // it if its size is plausible; a zero/short object is a torn write.
    //
    // The manifest entry must describe the *stored* object, not the current
    // profile settings: an object written with compression disabled must
    // keep `compressed = false` even if compression is now enabled (and
    // vice versa), otherwise restore decodes it wrongly.
    if let Some(existing) = object_size(storage, rt_handle, index, &data_path, None)? {
        if let Some(mode) = classify_existing_object(
            storage,
            rt_handle,
            &data_path,
            existing,
            plain_len,
            &current_hash,
            should_encrypt,
        )? {
            if inline.is_none() {
                ensure_unchanged(src, &before, Some(plain_len))?;
            }
            let metadata = build_file_metadata(
                current_hash,
                should_encrypt,
                mode.is_compressed(),
                None,
                Some(existing),
            )
            .with_size(plain_len);
            return Ok((FileStatus::Skipped, metadata));
        }
        warn!(
            "Stored object {} has implausible size {} for {} bytes of content; rewriting it",
            data_path, existing, plain_len
        );
    }

    if dry_run {
        let metadata = build_file_metadata(
            current_hash.clone(),
            should_encrypt,
            compression_level > 0,
            None,
            None,
        )
        .with_size(plain_len);
        return Ok((FileStatus::Processed, metadata));
    }

    // Compress + encrypt (streamed) + upload.
    let mut file;
    let source = match &inline {
        Some(data) => Source::Bytes(data),
        None => {
            file = std::fs::File::open(src)?;
            Source::Reader(&mut file)
        }
    };
    let (stored_size, stored_hash) = store_object(
        storage,
        rt_handle,
        &data_path,
        &current_hash,
        source,
        compression_level,
        should_encrypt,
        encryption_key.as_deref(),
    )?;
    if let Some(i) = index {
        i.record_upload(&data_path, stored_size);
    }
    if inline.is_none() {
        ensure_unchanged(src, &before, Some(plain_len))?;
    }

    let metadata = build_file_metadata(
        current_hash,
        should_encrypt,
        compression_level > 0,
        Some(stored_hash),
        Some(stored_size),
    )
    .with_size(plain_len);

    Ok((FileStatus::Processed, metadata))
}

/// Errors if the file changed (size/mtime) while it was being read, so the
/// backup reports it instead of silently storing a torn snapshot.
fn ensure_unchanged(src: &Path, before: &Metadata, read_len: Option<u64>) -> io::Result<()> {
    let after = std::fs::metadata(src)?;
    let changed = after.len() != before.len()
        || read_len.is_some_and(|n| n != before.len())
        || after.modified().ok() != before.modified().ok();
    if changed {
        return Err(io::Error::other(format!(
            "file changed while being backed up (size {} → {}); it will be picked up by the next backup",
            before.len(),
            after.len()
        )));
    }
    Ok(())
}

/// Cheap sanity check on an existing deduplicated object, without
/// downloading it. Never flags a valid object (whatever compression level
/// produced it); only catches objects that cannot possibly hold
/// `plain_len` bytes, e.g. a zero-byte file left by a crashed write.
fn plausible_stored_size(stored: u64, plain_len: u64, encrypted: bool) -> bool {
    let min = if encrypted { ENCRYPTION_OVERHEAD } else { 0 };
    if stored < min {
        return false;
    }
    // Exactly the framing overhead means an empty payload, which is only
    // possible for empty content (a zstd frame is never empty).
    !(stored == min && plain_len > 0)
}

/// Fills `buf` from `reader` until full or EOF; returns bytes read.
fn read_full(reader: &mut (impl Read + ?Sized), buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

/// Error for a file whose content no longer matches its first read.
fn changed_while_reading() -> io::Error {
    io::Error::other("file changed while being backed up; it will be picked up by the next backup")
}

/// BLAKE3 (hex) and length of everything `reader` yields, read
/// [`READ_BUF`] bytes at a time.
fn hash_reader(reader: &mut impl Read) -> io::Result<(String, u64)> {
    let mut buf = vec![0u8; READ_BUF];
    let mut hasher = blake3::Hasher::new();
    let mut len = 0u64;
    loop {
        let n = read_full(reader, &mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        len += n as u64;
    }
    Ok((hasher.finalize().to_hex().to_string(), len))
}

/// Hashes the next chunk (up to [`CHUNK_SIZE`] bytes) of `reader` through
/// `buf`, also feeding `full` when given. Returns (chunk hash, length);
/// length 0 at EOF.
fn hash_chunk(
    reader: &mut impl Read,
    buf: &mut [u8],
    mut full: Option<&mut blake3::Hasher>,
) -> io::Result<(String, u64)> {
    let mut hasher = blake3::Hasher::new();
    let mut len = 0usize;
    while len < CHUNK_SIZE {
        let want = buf.len().min(CHUNK_SIZE - len);
        let n = read_full(reader, &mut buf[..want])?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        if let Some(f) = full.as_deref_mut() {
            f.update(&buf[..n]);
        }
        len += n;
    }
    Ok((hasher.finalize().to_hex().to_string(), len as u64))
}

/// Plaintext of an object to store.
enum Source<'a> {
    /// Bytes already in memory (and already hashed by the caller).
    Bytes(&'a [u8]),
    /// Streamed content; its BLAKE3 must equal the object id, which is
    /// checked before anything is uploaded.
    Reader(&'a mut dyn Read),
}

// ====================== EXISTING-OBJECT CLASSIFICATION ======================

/// Decides how an already-stored object was written so the manifest entry
/// that dedups onto it describes it correctly.
///
/// Returns `None` if the object cannot hold `plain_len` bytes (torn/corrupt write) and
/// must be rewritten. Only downloads the object when its size is consistent
/// with an *uncompressed* payload (otherwise it must be a zstd frame):
/// - clear objects are then checked byte-for-byte (raw hash, else zstd);
/// - encrypted objects are then classified by their exact framing overhead
///   (v3 header + per-chunk tags, v2 header or legacy), without decrypting.
///   The only residual ambiguity is a zstd frame of exactly `plain_len`
///   bytes, which is classified as uncompressed; restore's hash check still
///   catches that case.
fn classify_existing_object(
    storage: &Arc<dyn Storage>,
    rt_handle: &Handle,
    data_path: &str,
    stored_size: u64,
    plain_len: u64,
    content_hash: &str,
    encrypted: bool,
) -> io::Result<Option<StoredMode>> {
    if !plausible_stored_size(stored_size, plain_len, encrypted) {
        return Ok(None);
    }

    if !encrypted {
        if stored_size != plain_len {
            return Ok(Some(StoredMode::Compressed));
        }
        // Streamed: no copy of the object in memory in the common case.
        if hash_stored_object(storage, rt_handle, data_path)?
            == (content_hash.to_string(), plain_len)
        {
            return Ok(Some(StoredMode::Uncompressed));
        }
        // Rare: a zstd frame exactly as long as the content.
        let raw = rt_handle.block_on(storage.read(data_path))?;
        let mut decoded = Vec::with_capacity(plain_len as usize);
        if zstd::stream::copy_decode(&raw[..], &mut decoded).is_ok()
            && hash_file_content(&decoded)? == content_hash
        {
            return Ok(Some(StoredMode::Compressed));
        }
        return Ok(None);
    }

    if stored_size != plain_len + ENCRYPTION_OVERHEAD
        && stored_size != plain_len + ENCRYPTION_OVERHEAD_V2
        && stored_size != v3_blob_len(plain_len, V3_DEFAULT_CHUNK_SIZE)
    {
        return Ok(Some(StoredMode::Compressed));
    }
    // The framing is told by the header alone: read that, not the object.
    let raw = read_stored_prefix(storage, rt_handle, data_path, V3_HEADER_LEN)?;
    let raw_len = stored_size;
    if raw.starts_with(BLOB_MAGIC_V3) {
        // The chunk size comes from the header (it may differ from ours).
        let Ok(header) = V3Header::parse(&raw) else {
            return Ok(None);
        };
        if raw_len < v3_blob_len(0, header.chunk_size) {
            return Ok(None);
        }
        return Ok(Some(
            if raw_len == v3_blob_len(plain_len, header.chunk_size) {
                StoredMode::Uncompressed
            } else {
                StoredMode::Compressed
            },
        ));
    }
    let overhead = if raw.starts_with(BLOB_MAGIC_V2) {
        ENCRYPTION_OVERHEAD_V2
    } else {
        ENCRYPTION_OVERHEAD
    };
    match raw_len.checked_sub(overhead) {
        Some(payload) if payload == plain_len => Ok(Some(StoredMode::Uncompressed)),
        Some(_) => Ok(Some(StoredMode::Compressed)),
        None => Ok(None),
    }
}

/// BLAKE3 (hex) and length of a stored object, streamed.
fn hash_stored_object(
    storage: &Arc<dyn Storage>,
    rt_handle: &Handle,
    path: &str,
) -> io::Result<(String, u64)> {
    use tokio::io::AsyncReadExt;
    rt_handle.block_on(async {
        let mut reader = storage.read_stream(path).await?;
        let mut buf = vec![0u8; READ_BUF];
        let mut hasher = blake3::Hasher::new();
        let mut len = 0u64;
        loop {
            let n = reader.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            len += n as u64;
        }
        Ok((hasher.finalize().to_hex().to_string(), len))
    })
}

/// First `max` bytes of a stored object (fewer if it is shorter).
fn read_stored_prefix(
    storage: &Arc<dyn Storage>,
    rt_handle: &Handle,
    path: &str,
    max: usize,
) -> io::Result<Vec<u8>> {
    use tokio::io::AsyncReadExt;
    rt_handle.block_on(async {
        let reader = storage.read_stream(path).await?;
        let mut out = Vec::with_capacity(max);
        reader.take(max as u64).read_to_end(&mut out).await?;
        Ok(out)
    })
}

/// True if every object referenced by `cached` (a previous snapshot's
/// entry) still exists with a plausible size (matching the recorded stored
/// size when known).
fn cached_objects_present(
    storage: &Arc<dyn Storage>,
    rt_handle: &Handle,
    index: Option<&DedupIndex>,
    cached: &FileMetadata,
    plain_len: u64,
) -> io::Result<bool> {
    let kind = if cached.encrypted { "enc" } else { "clear" };
    let objects: Vec<(String, Option<u64>, Option<u64>)> = match &cached.chunks {
        Some(chunks) => chunks
            .iter()
            .map(|c| {
                (
                    format!("data/{}/{}", kind, c.hash),
                    Some(c.stored_size),
                    None,
                )
            })
            .collect(),
        None => vec![(
            format!("data/{}/{}", kind, cached.hash),
            cached.stored_size,
            Some(plain_len),
        )],
    };
    for (path, expected, plain) in objects {
        let Some(actual) = object_size(storage, rt_handle, index, &path, expected)? else {
            return Ok(false);
        };
        if expected.is_some_and(|e| e != 0 && e != actual) {
            return Ok(false);
        }
        if let Some(p) = plain
            && !plausible_stored_size(actual, p, cached.encrypted)
        {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Size of a stored object (`None` if missing): from the dedup index when
/// it may be trusted (see [`DedupIndex::size`]), else from storage.
/// `expected` is the stored size the caller already knows, if any.
fn object_size(
    storage: &Arc<dyn Storage>,
    rt_handle: &Handle,
    index: Option<&DedupIndex>,
    path: &str,
    expected: Option<u64>,
) -> io::Result<Option<u64>> {
    match index {
        Some(i) => i.size(storage, rt_handle, path, expected),
        None => rt_handle.block_on(storage.size(path)),
    }
}

// ====================== STREAMING MULTIPART ======================

/// Result of the planning pass for one chunk.
struct ChunkPlan {
    hash: String,
    /// `Some((stored_size, mode))` if a valid object already exists.
    existing: Option<(u64, StoredMode)>,
}

/// Streams a large file in `CHUNK_SIZE` pieces.
///
/// All chunks of a file share one `compressed` flag in the manifest, so
/// the file is processed in two passes (memory stays bounded by one read
/// buffer and the upload spool, whatever the chunk or file size):
/// 1. plan: hash every chunk and stat its object, without writing anything.
///    If the previous snapshot has this exact file and all its objects are
///    present, reuse that entry. Otherwise classify the existing chunks and
///    pick the storage mode that matches them (or the configured one if
///    none exist);
/// 2. write (only if some chunk is missing): re-read the file and store the
///    missing chunks in that mode, checking each chunk hash against pass 1.
#[allow(clippy::too_many_arguments)]
fn process_file_multipart_streaming(
    src: &Path,
    storage: &Arc<dyn Storage>,
    should_encrypt: bool,
    encryption_key: Option<&RepoKey>,
    previous_metadata_cache: &HashMap<String, FileMetadata>,
    dry_run: bool,
    rt_handle: &Handle,
    compression_level: u8,
    index: Option<&DedupIndex>,
) -> io::Result<(FileStatus, FileMetadata)> {
    let kind = if should_encrypt { "enc" } else { "clear" };
    // Both passes stream through one small buffer: memory does not grow
    // with the chunk or file size.
    let mut buf = vec![0u8; READ_BUF];

    // ---- Pass 1: hash + stat ----
    let mut file = std::fs::File::open(src)?;
    let mut full_hasher = blake3::Hasher::new();
    // (chunk hash, plain length, stored size if the object exists)
    let mut scanned: Vec<(String, u64, Option<u64>)> = Vec::new();
    let mut file_size: u64 = 0;
    loop {
        let (chunk_hash, n) = hash_chunk(&mut file, &mut buf, Some(&mut full_hasher))?;
        if n == 0 {
            break;
        }
        file_size += n;
        let data_path = format!("data/{}/{}", kind, chunk_hash);
        let size = object_size(storage, rt_handle, index, &data_path, None)?;
        scanned.push((chunk_hash, n, size));
    }
    let file_hash = full_hasher.finalize().to_hex().to_string();

    // Unchanged since the previous snapshot: its entry already describes
    // the stored objects (no download needed to classify them).
    if let Some(cached) = previous_metadata_cache.get(&file_hash)
        && cached.encrypted == should_encrypt
        && let Some(chunks) = &cached.chunks
    {
        let same = chunks.len() == scanned.len()
            && chunks.iter().zip(&scanned).all(|(c, (h, plain, sz))| {
                c.hash == *h
                    && sz.is_some_and(|sz| {
                        (c.stored_size == 0 || c.stored_size == sz)
                            && plausible_stored_size(sz, *plain, should_encrypt)
                    })
            });
        if same {
            return Ok((FileStatus::Skipped, cached.clone().with_size(file_size)));
        }
    }

    // Classify existing chunks.
    let mut plans: Vec<ChunkPlan> = Vec::with_capacity(scanned.len());
    let mut existing_mode: Option<StoredMode> = None;
    for (chunk_hash, plain_len, size) in scanned {
        let data_path = format!("data/{}/{}", kind, chunk_hash);
        let existing = match size {
            Some(sz) => match classify_existing_object(
                storage,
                rt_handle,
                &data_path,
                sz,
                plain_len,
                &chunk_hash,
                should_encrypt,
            )? {
                Some(mode) => Some((sz, mode)),
                None => {
                    warn!(
                        "Stored chunk {} has implausible size {}; rewriting it",
                        data_path, sz
                    );
                    None
                }
            },
            None => None,
        };
        if let Some((_, mode)) = existing {
            match existing_mode {
                None => existing_mode = Some(mode),
                Some(m) if m != mode => {
                    return Err(io::Error::other(format!(
                        "{}: its chunks are already stored with mixed compression modes, \
                         which a manifest entry cannot describe",
                        src.display()
                    )));
                }
                Some(_) => {}
            }
        }
        plans.push(ChunkPlan {
            hash: chunk_hash,
            existing,
        });
    }
    let mode = existing_mode.unwrap_or(StoredMode::from_level(compression_level));
    let write_level = mode.write_level(compression_level);
    let needs_write = plans.iter().any(|p| p.existing.is_none());

    // ---- Pass 2: write missing chunks ----
    let mut written: HashMap<String, (u64, String)> = HashMap::new();
    if needs_write && !dry_run {
        let mut file = std::fs::File::open(src)?;
        let mut seen: HashSet<&str> = HashSet::new();
        for plan in &plans {
            if plan.existing.is_some() || !seen.insert(plan.hash.as_str()) {
                // Not stored again, but still checked against pass 1.
                let (hash, n) = hash_chunk(&mut file, &mut buf, None)?;
                if n == 0 || hash != plan.hash {
                    return Err(changed_while_reading());
                }
                continue;
            }
            let data_path = format!("data/{}/{}", kind, plan.hash);
            // Streamed; its hash is checked against pass 1 before upload.
            let mut part = (&mut file).take(CHUNK_SIZE as u64);
            let (stored_size, stored_hash) = store_object(
                storage,
                rt_handle,
                &data_path,
                &plan.hash,
                Source::Reader(&mut part),
                write_level,
                should_encrypt,
                encryption_key,
            )?;
            if let Some(i) = index {
                i.record_upload(&data_path, stored_size);
            }
            written.insert(plan.hash.clone(), (stored_size, stored_hash));
        }
    }

    let mut chunks_meta = Vec::with_capacity(plans.len());
    let mut total_stored_size = 0u64;
    for plan in plans {
        let (stored_size, stored_hash) = match plan.existing {
            Some((sz, _)) => (sz, None),
            None => match written.get(&plan.hash) {
                Some((sz, h)) => (*sz, Some(h.clone())),
                None => (0, None), // dry run
            },
        };
        total_stored_size += stored_size;
        chunks_meta.push(ChunkMetadata {
            hash: plan.hash,
            stored_size,
            stored_hash,
        });
    }

    let metadata = FileMetadata::new_multipart(
        file_hash,
        should_encrypt,
        mode.is_compressed(),
        chunks_meta,
        total_stored_size,
    )
    .with_size(file_size);
    let status = if needs_write {
        FileStatus::Processed
    } else {
        FileStatus::Skipped
    };
    Ok((status, metadata))
}

// ====================== HELPERS ======================

fn should_encrypt_file(
    rel_path: &Path,
    key: Option<&RepoKey>,
    encrypt_patterns: &Option<Vec<String>>,
) -> bool {
    if key.is_none() {
        return false;
    }
    match encrypt_patterns {
        Some(patterns) if !patterns.is_empty() => patterns
            .iter()
            .any(|p| Pattern::new(p).is_ok_and(|pat| pat.matches_path(rel_path))),
        _ => true, // encrypt everything if there is a key but no specific patterns
    }
}

/// Compresses (if `compression_level > 0`), encrypts (only if
/// `should_encrypt` and a key is present) and uploads `source` to
/// `data_path`. Used for whole files and chunks alike, so the `enc`/`clear`
/// location always matches the stored bytes. Returns (stored size, stored
/// BLAKE3).
///
/// Objects are produced as a stream (zstd → v3 chunk encryptor, if
/// encrypted → hasher → spool) and uploaded with [`Storage::write_file`]
/// once the spool exceeds [`SPOOL_MEM_LIMIT`], so neither the plaintext of
/// a streamed source nor its compressed/encrypted copy is ever held in
/// memory as a whole. A [`Source::Reader`] is hashed on the way and must
/// match `object_id` (the content hash), otherwise nothing is uploaded.
/// `object_id` is bound into v3 blobs.
#[allow(clippy::too_many_arguments)]
fn store_object(
    storage: &Arc<dyn Storage>,
    rt_handle: &Handle,
    data_path: &str,
    object_id: &str,
    source: Source<'_>,
    compression_level: u8,
    should_encrypt: bool,
    encryption_key: Option<&RepoKey>,
) -> io::Result<(u64, String)> {
    let key = match (should_encrypt, encryption_key) {
        (true, Some(k)) => Some(k),
        (true, None) => {
            // Never silently store in clear what was meant to be encrypted.
            return Err(io::Error::other(
                "encryption requested but no repository key is loaded",
            ));
        }
        (false, _) => None,
    };

    let sink = HashingWriter::new(Spool::new(SPOOL_MEM_LIMIT));
    let sink = match key {
        Some(k) => {
            let enc = k.encryptor(object_id, sink)?;
            compress_into(enc, source, compression_level, object_id)?.finish()?
        }
        None => compress_into(sink, source, compression_level, object_id)?,
    };
    let (spool, len, hash) = sink.into_parts();
    // Deferred durability: the backup calls `Storage::sync` before it
    // writes the manifest that references this object.
    match spool {
        Spool::Memory { buf, .. } => rt_handle.block_on(storage.write_deferred(data_path, &buf))?,
        Spool::File(tmp) => {
            rt_handle.block_on(storage.write_file_deferred(data_path, tmp.path()))?
        }
    }
    Ok((len, hash))
}

/// Writes `source` into `w`, zstd-compressed when `level > 0`. A streamed
/// source must hash to `expected_hash`.
fn compress_into<W: Write>(
    w: W,
    source: Source<'_>,
    level: u8,
    expected_hash: &str,
) -> io::Result<W> {
    if level > 0 {
        let mut z = ZstdEncoder::new(w, level as i32)?;
        copy_source(source, &mut z, expected_hash)?;
        z.finish()
    } else {
        let mut w = w;
        copy_source(source, &mut w, expected_hash)?;
        Ok(w)
    }
}

fn copy_source(source: Source<'_>, w: &mut impl Write, expected_hash: &str) -> io::Result<()> {
    match source {
        Source::Bytes(data) => w.write_all(data),
        Source::Reader(reader) => {
            let mut buf = vec![0u8; READ_BUF];
            let mut hasher = blake3::Hasher::new();
            loop {
                let n = read_full(reader, &mut buf)?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
                w.write_all(&buf[..n])?;
            }
            if hasher.finalize().to_hex().as_str() != expected_hash {
                return Err(changed_while_reading());
            }
            Ok(())
        }
    }
}

/// Counts and hashes everything written through it.
pub(crate) struct HashingWriter<W: Write> {
    inner: W,
    hasher: blake3::Hasher,
    len: u64,
}

impl<W: Write> HashingWriter<W> {
    pub(crate) fn new(inner: W) -> Self {
        Self {
            inner,
            hasher: blake3::Hasher::new(),
            len: 0,
        }
    }

    /// (inner writer, bytes written, BLAKE3 hex of them)
    pub(crate) fn into_parts(self) -> (W, u64, String) {
        (
            self.inner,
            self.len,
            self.hasher.finalize().to_hex().to_string(),
        )
    }
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.hasher.update(&buf[..n]);
        self.len += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// In-memory buffer that spills to an anonymous-on-drop temp file once it
/// exceeds `limit` bytes.
pub(crate) enum Spool {
    Memory { buf: Vec<u8>, limit: usize },
    File(tempfile::NamedTempFile),
}

impl Spool {
    pub(crate) fn new(limit: usize) -> Self {
        Spool::Memory {
            buf: Vec::new(),
            limit,
        }
    }
}

impl Write for Spool {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if let Spool::Memory { buf, limit } = self
            && buf.len() + data.len() > *limit
        {
            let mut tmp = tempfile::NamedTempFile::new()?;
            tmp.write_all(buf)?;
            *self = Spool::File(tmp);
        }
        match self {
            Spool::Memory { buf, .. } => {
                buf.extend_from_slice(data);
                Ok(data.len())
            }
            Spool::File(f) => f.write(data),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Spool::Memory { .. } => Ok(()),
            Spool::File(f) => f.flush(),
        }
    }
}

fn build_file_metadata(
    hash: String,
    encrypted: bool,
    compressed: bool,
    stored_hash: Option<String>,
    stored_size: Option<u64>,
) -> FileMetadata {
    FileMetadata {
        hash,
        encrypted,
        stored_hash,
        stored_size,
        chunks: None,
        compressed,
        size: None,
    }
}

pub fn get_file_priority(path: &Path) -> u8 {
    match path.extension().and_then(|s| s.to_str()) {
        Some(ext) => {
            let ext_lower = ext.to_lowercase();
            match ext_lower.as_str() {
                "txt" | "md" | "pdf" | "doc" | "docx" | "json" | "toml" => 0,
                "rs" | "py" | "js" | "ts" | "go" | "java" => 1,
                "jpg" | "jpeg" | "png" | "webp" => 2,
                "mp3" | "wav" | "flac" => 3,
                "mp4" | "mkv" => 4,
                _ => 10,
            }
        }
        None => 10,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::LocalStorage;

    #[test]
    fn plausibility_rejects_torn_objects_only() {
        assert!(!plausible_stored_size(0, 10, false));
        assert!(plausible_stored_size(0, 0, false));
        assert!(plausible_stored_size(3, 10, false)); // compressed
        assert!(!plausible_stored_size(20, 10, true));
        assert!(!plausible_stored_size(44, 10, true));
        assert!(plausible_stored_size(44, 0, true));
        assert!(plausible_stored_size(60, 10, true));
    }

    fn run(
        rt: &tokio::runtime::Runtime,
        storage: &Arc<dyn Storage>,
        src: &Path,
        key: Option<Arc<RepoKey>>,
        cache: &HashMap<String, FileMetadata>,
        level: u8,
    ) -> (FileStatus, FileMetadata) {
        process_file(
            src,
            storage,
            Path::new("f.txt"),
            key,
            cache,
            false,
            rt.handle(),
            &None,
            level,
            None,
        )
        .unwrap()
    }

    /// Decodes a stored object the way restore does, driven only by the
    /// manifest entry.
    fn decode_like_restore(
        raw: Vec<u8>,
        meta: &FileMetadata,
        key: Option<&Arc<RepoKey>>,
    ) -> Vec<u8> {
        let dec = match (meta.encrypted, key) {
            (true, Some(k)) => crate::crypto::KeyCache::with_repo_key(b"pw", k.clone())
                .decrypt_object(&meta.hash, &raw)
                .unwrap(),
            _ => raw,
        };
        if meta.compressed {
            zstd::stream::decode_all(&dec[..]).expect("manifest says compressed")
        } else {
            dec
        }
    }

    #[test]
    fn dedup_records_how_existing_object_was_stored() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let src_dir = tempfile::tempdir().unwrap();
        let src = src_dir.path().join("f.txt");
        let content = b"compressible content ".repeat(200);
        std::fs::write(&src, &content).unwrap();
        let none = HashMap::new();

        for encrypted in [false, true] {
            let key = encrypted.then(|| Arc::new(RepoKey::generate().unwrap()));
            for (first, second) in [(0u8, 3u8), (3, 0), (1, 19)] {
                let repo = tempfile::tempdir().unwrap();
                let storage: Arc<dyn Storage> =
                    Arc::new(LocalStorage::new(repo.path().to_str().unwrap()));
                let (s1, m1) = run(&rt, &storage, &src, key.clone(), &none, first);
                assert_eq!(s1, FileStatus::Processed);
                // Second backup with a different compression setting dedups
                // onto the existing object (empty cache: e.g. other profile).
                let (s2, m2) = run(&rt, &storage, &src, key.clone(), &none, second);
                assert_eq!(s2, FileStatus::Skipped);
                assert_eq!(
                    m2.compressed, m1.compressed,
                    "enc={} {}->{}: manifest must describe the stored object",
                    encrypted, first, second
                );
                let kind = if encrypted { "enc" } else { "clear" };
                let raw =
                    std::fs::read(repo.path().join("data").join(kind).join(&m2.hash)).unwrap();
                assert!(!encrypted || raw.starts_with(BLOB_MAGIC_V3));
                assert_eq!(decode_like_restore(raw, &m2, key.as_ref()), content);
            }
        }
    }

    #[test]
    fn dedup_onto_existing_v2_object_keeps_it_readable() {
        // Mixed repository: an object written by an older version (v2,
        // password-derived key) is reused as-is by a v3 backup.
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let src_dir = tempfile::tempdir().unwrap();
        let src = src_dir.path().join("f.txt");
        let content = b"legacy content ".repeat(100);
        std::fs::write(&src, &content).unwrap();
        let hash = hash_file_content(&content).unwrap();
        let repo = tempfile::tempdir().unwrap();
        let storage: Arc<dyn Storage> = Arc::new(LocalStorage::new(repo.path().to_str().unwrap()));
        for compressed in [false, true] {
            let payload = if compressed {
                zstd::stream::encode_all(&content[..], 3).unwrap()
            } else {
                content.clone()
            };
            let v2 = crate::crypto::EncryptionKey::new(b"pw")
                .unwrap()
                .encrypt(&payload)
                .unwrap();
            let obj = repo.path().join("data/enc").join(&hash);
            std::fs::create_dir_all(obj.parent().unwrap()).unwrap();
            std::fs::write(&obj, &v2).unwrap();
            let key = Arc::new(RepoKey::generate().unwrap());
            let (status, meta) = run(&rt, &storage, &src, Some(key), &HashMap::new(), 3);
            assert_eq!(status, FileStatus::Skipped);
            assert_eq!(meta.compressed, compressed);
            assert_eq!(std::fs::read(&obj).unwrap(), v2, "v2 object must be kept");
        }
    }

    #[test]
    fn large_encrypted_object_spools_to_disk_and_roundtrips() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let src_dir = tempfile::tempdir().unwrap();
        let src = src_dir.path().join("big.bin");
        // Incompressible and larger than SPOOL_MEM_LIMIT.
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        let content: Vec<u8> = (0..SPOOL_MEM_LIMIT + 3 * 1024 * 1024 + 7)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect();
        std::fs::write(&src, &content).unwrap();
        let repo = tempfile::tempdir().unwrap();
        let storage: Arc<dyn Storage> = Arc::new(LocalStorage::new(repo.path().to_str().unwrap()));
        let key = Arc::new(RepoKey::generate().unwrap());
        for level in [0u8, 3] {
            let (_, meta) = run(
                &rt,
                &storage,
                &src,
                Some(key.clone()),
                &HashMap::new(),
                level,
            );
            let raw = std::fs::read(repo.path().join("data/enc").join(&meta.hash)).unwrap();
            assert_eq!(meta.stored_size, Some(raw.len() as u64));
            assert_eq!(meta.size, Some(content.len() as u64));
            assert_eq!(meta.stored_hash, Some(hash_file_content(&raw).unwrap()));
            assert_eq!(decode_like_restore(raw, &meta, Some(&key)), content);
            std::fs::remove_file(repo.path().join("data/enc").join(&meta.hash)).unwrap();
        }
    }

    #[test]
    fn dedup_of_plain_object_that_looks_like_zstd() {
        // Content that is itself a zstd frame, stored uncompressed: must not
        // be mistaken for a compressed object.
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let src_dir = tempfile::tempdir().unwrap();
        let src = src_dir.path().join("f.zst");
        let content = zstd::stream::encode_all(&b"inner ".repeat(100)[..], 3).unwrap();
        std::fs::write(&src, &content).unwrap();
        let repo = tempfile::tempdir().unwrap();
        let storage: Arc<dyn Storage> = Arc::new(LocalStorage::new(repo.path().to_str().unwrap()));
        let none = HashMap::new();
        let (_, m1) = run(&rt, &storage, &src, None, &none, 0);
        assert!(!m1.compressed);
        let (_, m2) = run(&rt, &storage, &src, None, &none, 3);
        assert!(!m2.compressed);
    }

    #[test]
    fn cache_hit_with_deleted_object_reuploads() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let src_dir = tempfile::tempdir().unwrap();
        let src = src_dir.path().join("f.txt");
        std::fs::write(&src, b"some content").unwrap();
        let repo = tempfile::tempdir().unwrap();
        let storage: Arc<dyn Storage> = Arc::new(LocalStorage::new(repo.path().to_str().unwrap()));
        let (_, m1) = run(&rt, &storage, &src, None, &HashMap::new(), 3);
        let mut cache = HashMap::new();
        cache.insert(m1.hash.clone(), m1.clone());
        let (s, _) = run(&rt, &storage, &src, None, &cache, 3);
        assert_eq!(s, FileStatus::Skipped);
        // Object removed (e.g. by verify --repair): must be uploaded again.
        let obj = repo.path().join("data/clear").join(&m1.hash);
        std::fs::remove_file(&obj).unwrap();
        let (s, _) = run(&rt, &storage, &src, None, &cache, 3);
        assert_eq!(s, FileStatus::Processed);
        assert!(obj.exists());
    }

    #[test]
    fn truncated_dedup_object_is_rewritten() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let repo = tempfile::tempdir().unwrap();
        let src_dir = tempfile::tempdir().unwrap();
        let src = src_dir.path().join("f.txt");
        std::fs::write(&src, b"hello world").unwrap();
        let hash = hash_file_content(b"hello world").unwrap();

        let storage: Arc<dyn Storage> = Arc::new(LocalStorage::new(repo.path().to_str().unwrap()));
        // Simulate a torn write from an older version: zero-byte object.
        let obj = repo.path().join("data/clear").join(&hash);
        std::fs::create_dir_all(obj.parent().unwrap()).unwrap();
        std::fs::write(&obj, b"").unwrap();

        let (status, meta) = process_file(
            &src,
            &storage,
            Path::new("f.txt"),
            None,
            &HashMap::new(),
            false,
            rt.handle(),
            &None,
            0,
            None,
        )
        .unwrap();
        assert_eq!(status, FileStatus::Processed);
        assert_eq!(meta.hash, hash);
        assert_eq!(std::fs::read(&obj).unwrap(), b"hello world");
    }
    /// Mixed content: compressible runs and pseudo-random bytes.
    fn mixed_content(len: usize, seed: u64) -> Vec<u8> {
        let mut x = seed | 1;
        (0..len)
            .map(|i| {
                if (i / 65536) % 2 == 0 {
                    (i % 251) as u8
                } else {
                    x ^= x << 13;
                    x ^= x >> 7;
                    x ^= x << 17;
                    x as u8
                }
            })
            .collect()
    }

    #[test]
    fn streamed_files_round_trip_clear_and_encrypted() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let src_dir = tempfile::tempdir().unwrap();
        // Above INLINE_READ_MAX: hashed, then streamed into the store.
        let content = mixed_content(3 * 1024 * 1024 + 11, 7);
        let src = src_dir.path().join("medium.bin");
        std::fs::write(&src, &content).unwrap();
        for key in [None, Some(Arc::new(RepoKey::generate().unwrap()))] {
            for level in [0u8, 3] {
                let repo = tempfile::tempdir().unwrap();
                let storage: Arc<dyn Storage> =
                    Arc::new(LocalStorage::new(repo.path().to_str().unwrap()));
                let (status, meta) = run(&rt, &storage, &src, key.clone(), &HashMap::new(), level);
                assert_eq!(status, FileStatus::Processed);
                assert_eq!(meta.hash, hash_file_content(&content).unwrap());
                let kind = if key.is_some() { "enc" } else { "clear" };
                let raw =
                    std::fs::read(repo.path().join("data").join(kind).join(&meta.hash)).unwrap();
                assert_eq!(meta.stored_size, Some(raw.len() as u64));
                assert_eq!(meta.stored_hash, Some(hash_file_content(&raw).unwrap()));
                assert_eq!(decode_like_restore(raw, &meta, key.as_ref()), content);
                // Second run dedups without rewriting.
                let (status, _) = run(&rt, &storage, &src, key.clone(), &HashMap::new(), level);
                assert_eq!(status, FileStatus::Skipped);
            }
        }
    }

    #[test]
    fn multipart_files_stream_and_round_trip() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let src_dir = tempfile::tempdir().unwrap();
        let len = MULTIPART_THRESHOLD as usize + 5 * 1024 * 1024 + 3;
        let content = mixed_content(len, 11);
        let src = src_dir.path().join("big.bin");
        std::fs::write(&src, &content).unwrap();
        for (key, level) in [
            (None, 3u8),
            (Some(Arc::new(RepoKey::generate().unwrap())), 0u8),
        ] {
            let repo = tempfile::tempdir().unwrap();
            let storage: Arc<dyn Storage> =
                Arc::new(LocalStorage::new(repo.path().to_str().unwrap()));
            let (status, meta) = run(&rt, &storage, &src, key.clone(), &HashMap::new(), level);
            assert_eq!(status, FileStatus::Processed);
            assert_eq!(meta.hash, hash_file_content(&content).unwrap());
            assert_eq!(meta.size, Some(len as u64));
            let chunks = meta.chunks.clone().unwrap();
            assert_eq!(chunks.len(), len.div_ceil(CHUNK_SIZE));
            let kind = if key.is_some() { "enc" } else { "clear" };
            let mut restored = Vec::with_capacity(len);
            for (i, c) in chunks.iter().enumerate() {
                let raw = std::fs::read(repo.path().join("data").join(kind).join(&c.hash)).unwrap();
                assert_eq!(c.stored_size, raw.len() as u64);
                assert_eq!(c.stored_hash, Some(hash_file_content(&raw).unwrap()));
                let part = FileMetadata {
                    hash: c.hash.clone(),
                    ..meta.clone()
                };
                let plain = decode_like_restore(raw, &part, key.as_ref());
                let start = i * CHUNK_SIZE;
                assert_eq!(c.hash, hash_file_content(&plain).unwrap());
                assert_eq!(&plain[..], &content[start..(start + CHUNK_SIZE).min(len)]);
                restored.extend_from_slice(&plain);
            }
            assert_eq!(restored, content);
            // Unchanged file with the previous entry: skipped, same entry.
            let mut cache = HashMap::new();
            cache.insert(meta.hash.clone(), meta.clone());
            let (status, again) = run(&rt, &storage, &src, key.clone(), &cache, level);
            assert_eq!(status, FileStatus::Skipped);
            assert_eq!(again.chunks, meta.chunks);
        }
    }

    #[test]
    fn streamed_source_that_changed_is_never_uploaded() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let repo = tempfile::tempdir().unwrap();
        let storage: Arc<dyn Storage> = Arc::new(LocalStorage::new(repo.path().to_str().unwrap()));
        let expected = hash_file_content(b"what pass 1 hashed").unwrap();
        let path = format!("data/clear/{}", expected);
        let mut changed: &[u8] = b"what pass 2 reads";
        let err = store_object(
            &storage,
            rt.handle(),
            &path,
            &expected,
            Source::Reader(&mut changed),
            3,
            false,
            None,
        )
        .unwrap_err();
        assert!(err.to_string().contains("changed"), "{}", err);
        assert!(!repo.path().join(&path).exists());
    }
}
