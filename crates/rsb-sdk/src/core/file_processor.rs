// file_processor.rs - Performant version with EncryptionKey
use super::types::{CHUNK_SIZE, ChunkMetadata, FileMetadata, FileStatus, MULTIPART_THRESHOLD};
use crate::crypto::{EncryptionKey, hash_file_content};
use crate::storage::Storage;
use glob::Pattern;
use std::collections::HashMap;
use std::fs::Metadata;
use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::Arc;
use tokio::runtime::Handle;
use tracing::warn;
use zstd::stream::write::Encoder as ZstdEncoder;

/// AES-GCM framing overhead added by `EncryptionKey::encrypt`:
/// salt(16) + nonce(12) + tag(16).
const ENCRYPTION_OVERHEAD: u64 = 16 + 12 + 16;

#[allow(clippy::too_many_arguments)]
pub fn process_file(
    src: &Path,
    storage: &Arc<dyn Storage>,
    rel_path: &Path,
    encryption_key: Option<Arc<EncryptionKey>>, // ⚡ Pre-derived EncryptionKey instead of password
    previous_metadata_cache: &HashMap<String, FileMetadata>,
    dry_run: bool,
    rt_handle: &Handle,
    encrypt_patterns: &Option<Vec<String>>,
    compression_level: u8,
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
            dry_run,
            rt_handle,
            compression_level,
        )?;
        ensure_unchanged(src, &before, None)?;
        return Ok(result);
    }

    // =============== NORMAL FILES ===============
    // Read once into memory: the bytes we hash are exactly the bytes we
    // compress/store (no mmap → no SIGBUS if the file is truncated, and no
    // window where hash and stored content can diverge).
    let data = std::fs::read(src)?;
    ensure_unchanged(src, &before, Some(data.len() as u64))?;
    let current_hash = hash_file_content(&data)?;

    // Fast deduplication
    if let Some(cached) = previous_metadata_cache.get(&current_hash) {
        return Ok((FileStatus::Skipped, cached.clone()));
    }

    let data_path = format!(
        "data/{}/{}",
        if should_encrypt { "enc" } else { "clear" },
        current_hash
    );

    // File already exists in storage (deduplicated by hash) — but only trust
    // it if its size is plausible; a zero/short object is a torn write.
    if let Some(existing) = rt_handle.block_on(storage.size(&data_path))? {
        if plausible_stored_size(existing, data.len() as u64, should_encrypt) {
            let metadata = build_file_metadata(
                current_hash,
                should_encrypt,
                compression_level,
                None,
                Some(existing),
            );
            return Ok((FileStatus::Skipped, metadata));
        }
        warn!(
            "Stored object {} has implausible size {} for {} bytes of content; rewriting it",
            data_path,
            existing,
            data.len()
        );
    }

    if dry_run {
        let metadata = build_file_metadata(
            current_hash.clone(),
            should_encrypt,
            compression_level,
            None,
            None,
        );
        return Ok((FileStatus::Processed, metadata));
    }

    // Compress + Encrypt (optimized)
    let final_data = compress_and_encrypt(
        &data,
        compression_level,
        should_encrypt,
        encryption_key.as_deref(), // ⚡ Dereference Arc to get Option<&EncryptionKey>
    )?;

    let stored_size = final_data.len() as u64;
    let stored_hash = hash_file_content(&final_data)?;

    rt_handle.block_on(storage.write(&data_path, &final_data))?;

    let metadata = build_file_metadata(
        current_hash,
        should_encrypt,
        compression_level,
        Some(stored_hash),
        Some(stored_size),
    );

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
fn read_full(reader: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
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

// ====================== STREAMING MULTIPART ======================
/// Streams a large file in `CHUNK_SIZE` pieces: each chunk is hashed and
/// stored from the same buffer, and the full-file hash is computed over
/// exactly those bytes. Memory use is bounded by one chunk.
fn process_file_multipart_streaming(
    src: &Path,
    storage: &Arc<dyn Storage>,
    should_encrypt: bool,
    encryption_key: Option<&EncryptionKey>, // ⚡ Pre-derived key
    dry_run: bool,
    rt_handle: &Handle,
    compression_level: u8,
) -> io::Result<(FileStatus, FileMetadata)> {
    let mut file = std::fs::File::open(src)?;
    let mut buf = vec![0u8; CHUNK_SIZE];
    let mut full_hasher = blake3::Hasher::new();
    let mut chunks_meta = Vec::new();
    let mut total_stored_size = 0u64;
    let mut wrote_any = false;

    loop {
        let n = read_full(&mut file, &mut buf)?;
        if n == 0 {
            break;
        }
        let chunk_data = &buf[..n];
        full_hasher.update(chunk_data);

        let chunk_hash = hash_file_content(chunk_data)?;
        let data_path = format!(
            "data/{}/{}",
            if should_encrypt { "enc" } else { "clear" },
            chunk_hash
        );

        let existing = rt_handle.block_on(storage.size(&data_path))?;
        let (stored_size, stored_hash) = match existing {
            // Dedup on size metadata only: no more downloading the whole
            // stored chunk just to hash it.
            Some(sz) if plausible_stored_size(sz, n as u64, should_encrypt) => (sz, None),
            _ if dry_run => (0, None),
            other => {
                if let Some(sz) = other {
                    warn!(
                        "Stored chunk {} has implausible size {}; rewriting it",
                        data_path, sz
                    );
                }
                let final_data = compress_and_encrypt(
                    chunk_data,
                    compression_level,
                    should_encrypt,
                    encryption_key,
                )?;
                let len = final_data.len() as u64;
                let hash = hash_file_content(&final_data)?;
                rt_handle.block_on(storage.write(&data_path, &final_data))?;
                wrote_any = true;
                (len, Some(hash))
            }
        };

        chunks_meta.push(ChunkMetadata {
            hash: chunk_hash,
            stored_size,
            stored_hash,
        });
        total_stored_size += stored_size;
    }

    let file_hash = full_hasher.finalize().to_hex().to_string();
    let metadata = FileMetadata::new_multipart(
        file_hash,
        should_encrypt,
        compression_level > 0,
        chunks_meta,
        total_stored_size,
    );
    let status = if wrote_any || dry_run {
        FileStatus::Processed
    } else {
        FileStatus::Skipped
    };
    Ok((status, metadata))
}

// ====================== HELPERS ======================

fn should_encrypt_file(
    rel_path: &Path,
    key: Option<&EncryptionKey>,
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

/// Compresses (if `compression_level > 0`) and encrypts (only if
/// `should_encrypt` and a key is present). Used for whole files and chunks
/// alike, so the `enc`/`clear` location always matches the stored bytes.
fn compress_and_encrypt(
    data: &[u8],
    compression_level: u8,
    should_encrypt: bool,
    encryption_key: Option<&EncryptionKey>, // ⚡ Pre-derived key instead of password
) -> io::Result<Vec<u8>> {
    let compressed = if compression_level > 0 {
        let mut compressed = Vec::with_capacity(data.len() * 2 / 3);
        let mut encoder = ZstdEncoder::new(&mut compressed, compression_level as i32)?;
        encoder.write_all(data)?;
        encoder.finish()?;
        compressed
    } else {
        data.to_vec()
    };

    if should_encrypt {
        if let Some(key) = encryption_key {
            key.encrypt(&compressed) // ✅ No PBKDF2 - key already derived!
        } else {
            Ok(compressed)
        }
    } else {
        Ok(compressed)
    }
}

fn build_file_metadata(
    hash: String,
    encrypted: bool,
    compression_level: u8,
    stored_hash: Option<String>,
    stored_size: Option<u64>,
) -> FileMetadata {
    FileMetadata {
        hash,
        encrypted,
        stored_hash,
        stored_size,
        chunks: None,
        compressed: compression_level > 0,
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

        let storage: Arc<dyn Storage> =
            Arc::new(LocalStorage::new(repo.path().to_str().unwrap()));
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
        )
        .unwrap();
        assert_eq!(status, FileStatus::Processed);
        assert_eq!(meta.hash, hash);
        assert_eq!(std::fs::read(&obj).unwrap(), b"hello world");
    }
}
