use super::manifest::find_latest_snapshot_cached;
use super::types::FileMetadata;
use crate::config::Config;
use crate::crypto::{BLOB_MAGIC_V3, CryptoError, KeyCache};
use crate::options::RestoreOptions;
use crate::report::ReportData;
use crate::storage::{Storage, sync_dir};
use crate::storage::{validate_content_hash, validate_storage_path};
use chrono::Utc;
use indicatif::{ProgressBar, ProgressStyle};
use std::collections::HashMap;
use std::io::{self, ErrorKind};
use std::path::{Component, Path, PathBuf};
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tracing::{error, info};

/// Restores a snapshot of the repository described by `config`.
///
/// Snapshot, target, key, force/versioned, progress and cancellation are
/// given through [`RestoreOptions`].
pub async fn perform_restore(
    config: &Config,
    options: RestoreOptions,
) -> crate::error::Result<ReportData> {
    let storage =
        super::storage_backend::storage_or_from_config(options.storage.clone(), config).await?;
    restore_from_storage(&*storage, options).await
}

/// Restore implementation working on any [`Storage`] (used by tests too).
/// `options.storage` is ignored here: `storage` is used.
pub async fn restore_from_storage(
    storage: &dyn Storage,
    options: RestoreOptions,
) -> crate::error::Result<ReportData> {
    let RestoreOptions {
        snapshot_id,
        target_path,
        encryption_key,
        force,
        versioned,
        on_progress,
        cancellation_token,
        storage: _,
    } = options;
    let snapshot_id = snapshot_id.as_deref();
    let encryption_key = encryption_key.as_ref().map(|k| k.as_str());
    let start_time = Instant::now();

    // 🐛 Fix: Validate backup structure before attempting restore
    validate_backup_structure(storage).await?;

    // Unlocks keys/repo.key first (a wrong password fails here, before any
    // blob is read); v1/v2 blobs use one PBKDF2 per salt for the whole
    // restore instead of one per blob.
    let key_cache = match encryption_key {
        Some(k) => Some(KeyCache::open(storage, k.as_bytes()).await?),
        None => None,
    };

    let (manifest_path, manifest_content) =
        find_latest_snapshot_cached(storage, snapshot_id, key_cache.as_ref()).await?;
    info!("Restoring snapshot: {}", manifest_path);

    let manifest: HashMap<PathBuf, FileMetadata> = toml::from_str(&manifest_content)?;

    let restore_root = if versioned {
        let timestamp = Utc::now().format("%Y%m%d_%H%M%S").to_string();
        target_path.join(format!("restore_{}", timestamp))
    } else {
        target_path
    };

    info!("Restoring to: {}", restore_root.display());

    // Fail-closed: create + canonicalize the destination once; every restored
    // path is built from (and checked against) this canonical root.
    tokio::fs::create_dir_all(&restore_root).await?;
    let restore_root_canon = tokio::fs::canonicalize(&restore_root).await?;

    let pb = ProgressBar::new(manifest.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template(
            "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta}) {msg}")
            .unwrap()
            .progress_chars("#>-"),
    );

    let mut errors = Vec::new();
    let mut success = 0;
    let total_files = manifest.len();

    for (current_files, (rel_path, metadata)) in manifest.into_iter().enumerate() {
        // Check if the operation was cancelled
        if let Some(token) = &cancellation_token
            && token.is_cancelled()
        {
            info!("⏹️ Restore cancelled by user");
            break;
        }

        pb.set_message(format!("Restoring: {}", rel_path.display()));
        if let Some(cb) = &on_progress {
            cb(
                current_files,
                total_files,
                format!("Restoring: {}", rel_path.display()),
            );
        }

        if let Err(msg) = restore_entry(
            storage,
            &restore_root_canon,
            &rel_path,
            &metadata,
            key_cache.as_ref(),
            force,
        )
        .await
        {
            error!("{}", msg);
            errors.push(msg);
        } else {
            success += 1;
        }

        pb.inc(1);
    }

    pb.finish_with_message("Restore completed");

    let status = if errors.is_empty() {
        "Success"
    } else {
        "Failure with errors"
    }
    .to_string();

    let report_data = ReportData {
        operation: "Restore".to_string(),
        profile_path: "".to_string(),
        timestamp: chrono::Local::now().to_rfc3339(),
        duration: start_time.elapsed(),
        mode: None,
        files_processed: success,
        files_skipped: 0,
        files_with_errors: errors.len(),
        total_files,
        errors,
        status,
    };

    Ok(report_data)
}

/// Restores one manifest entry; returns a user-facing message on failure.
async fn restore_entry(
    storage: &dyn Storage,
    restore_root_canon: &Path,
    rel_path: &Path,
    metadata: &FileMetadata,
    key_cache: Option<&KeyCache>,
    force: bool,
) -> Result<(), String> {
    // Contenção anti-traversal: rejeita absoluto, `..`, componentes especiais.
    // Manifests escritos no Windows antes da normalização usam `\`: aí é
    // separador e cada componente continua a ser validado.
    let rel_str = rel_path.to_string_lossy();
    #[cfg(windows)]
    let rel_str = std::borrow::Cow::<str>::Owned(rel_str.replace('\\', "/"));
    if let Err(e) = validate_storage_path(&rel_str) {
        return Err(format!(
            "⛔ Refused unsafe manifest entry '{}': {}",
            rel_path.display(),
            e
        ));
    }
    // Hashes vindos do manifest montam `data/<enc|clear>/<hash>`.
    if let Err(e) = validate_content_hash(&metadata.hash) {
        return Err(format!(
            "⛔ Refused entry '{}' with invalid content hash: {}",
            rel_path.display(),
            e
        ));
    }
    if let Some(chunks) = &metadata.chunks {
        for chunk in chunks {
            if let Err(e) = validate_content_hash(&chunk.hash) {
                return Err(format!(
                    "⛔ Refused entry '{}' with invalid chunk hash: {}",
                    rel_path.display(),
                    e
                ));
            }
        }
    }

    let key = if metadata.encrypted {
        match key_cache {
            Some(k) => Some(k),
            None => {
                return Err(format!(
                    "Cannot restore {}: file is encrypted but no encryption key was provided",
                    rel_path.display()
                ));
            }
        }
    } else {
        None
    };
    let kind = if metadata.encrypted { "enc" } else { "clear" };

    // Refuses symlinked parents/targets and existing files without --force.
    let target = prepare_restore_target(restore_root_canon, rel_path, force).map_err(|e| {
        if e.kind() == ErrorKind::AlreadyExists {
            format!("File already exists (use --force): {}", rel_path.display())
        } else {
            format!("⛔ Refused to restore {}: {}", rel_path.display(), e)
        }
    })?;

    let blobs: Vec<BlobRef<'_>> = match &metadata.chunks {
        Some(chunks) => chunks
            .iter()
            .map(|c| BlobRef {
                path: format!("data/{}/{}", kind, c.hash),
                object_id: c.hash.as_str(),
                chunk_hash: Some(c.hash.as_str()),
            })
            .collect(),
        None => {
            let data_path = format!("data/{}/{}", kind, metadata.hash);
            match storage.exists(&data_path).await {
                Ok(true) => {}
                Ok(false) => {
                    // 🐛 Fix: More informative error about missing data
                    return Err(format!(
                        "❌ Missing data for file: {}\n   This file is referenced in the backup metadata but the data file is missing.\n   Your backup may be incomplete or corrupted.",
                        rel_path.display()
                    ));
                }
                Err(e) => return Err(format!("Failed to restore {}: {}", rel_path.display(), e)),
            }
            vec![BlobRef {
                path: data_path,
                object_id: metadata.hash.as_str(),
                chunk_hash: None,
            }]
        }
    };

    restore_blobs(
        storage,
        &blobs,
        &target,
        key,
        &metadata.hash,
        metadata.compressed,
        OutputLimits {
            file: metadata.max_plain_size(),
            blob: metadata.max_object_plain_size(),
        },
    )
    .await
    .map_err(|e| {
        let what = if metadata.chunks.is_some() {
            "multipart "
        } else {
            ""
        };
        format!("Failed to restore {}{}: {}", what, rel_path.display(), e)
    })
}

/// Builds the on-disk target for `rel` under `root_canon`, creating parent
/// directories one component at a time and refusing to traverse or write
/// through symlinks.
///
/// Errors with `AlreadyExists` if the target exists and `force` is false.
pub fn prepare_restore_target(root_canon: &Path, rel: &Path, force: bool) -> io::Result<PathBuf> {
    let comps: Vec<Component> = rel.components().collect();
    let Some((Component::Normal(file_name), parents)) = comps.split_last() else {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "Invalid restore path",
        ));
    };

    let mut dir = root_canon.to_path_buf();
    for comp in parents {
        let Component::Normal(name) = comp else {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "Invalid restore path",
            ));
        };
        dir.push(name);
        match std::fs::symlink_metadata(&dir) {
            Ok(m) if m.file_type().is_symlink() => {
                return Err(io::Error::new(
                    ErrorKind::PermissionDenied,
                    format!("refusing to traverse symlink {}", dir.display()),
                ));
            }
            Ok(m) if m.is_dir() => {}
            Ok(_) => {
                return Err(io::Error::new(
                    ErrorKind::InvalidInput,
                    format!("{} exists and is not a directory", dir.display()),
                ));
            }
            Err(e) if e.kind() == ErrorKind::NotFound => {
                // Plain mkdir (no ~ / $VAR expansion); tolerate a concurrent create.
                if let Err(e) = std::fs::create_dir(&dir) {
                    if e.kind() != ErrorKind::AlreadyExists {
                        return Err(e);
                    }
                    if std::fs::symlink_metadata(&dir)?.file_type().is_symlink() {
                        return Err(io::Error::new(
                            ErrorKind::PermissionDenied,
                            format!("refusing to traverse symlink {}", dir.display()),
                        ));
                    }
                }
            }
            Err(e) => return Err(e),
        }
    }

    // Defence in depth: the canonical parent must stay inside the root.
    let parent_canon = std::fs::canonicalize(&dir)?;
    if !parent_canon.starts_with(root_canon) {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            format!(
                "restore path escapes destination: {}",
                parent_canon.display()
            ),
        ));
    }

    let target = parent_canon.join(file_name);
    match std::fs::symlink_metadata(&target) {
        Ok(m) if m.file_type().is_symlink() => Err(io::Error::new(
            ErrorKind::PermissionDenied,
            format!("refusing to write through symlink {}", target.display()),
        )),
        Ok(m) if m.is_dir() => Err(io::Error::new(
            ErrorKind::InvalidInput,
            format!("{} is a directory", target.display()),
        )),
        Ok(_) if !force => Err(io::Error::new(
            ErrorKind::AlreadyExists,
            format!("{} already exists", target.display()),
        )),
        Ok(_) => Ok(target),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(target),
        Err(e) => Err(e),
    }
}

/// Temp file next to the target; renamed over it only after the full-file
/// hash has been verified. The existing target is never truncated first.
struct VerifiedOutput {
    tmp: PathBuf,
    file: tokio::fs::File,
    hasher: blake3::Hasher,
    written: u64,
}

impl VerifiedOutput {
    async fn create(target: &Path) -> io::Result<Self> {
        let parent = target
            .parent()
            .ok_or_else(|| io::Error::new(ErrorKind::InvalidInput, "target has no parent"))?;
        let name = target
            .file_name()
            .ok_or_else(|| io::Error::new(ErrorKind::InvalidInput, "target has no file name"))?
            .to_string_lossy();
        let tmp = parent.join(format!(
            ".{}.rsb-restore-{}",
            name,
            uuid::Uuid::new_v4().simple()
        ));
        // create_new => O_CREAT|O_EXCL, which never follows a symlink.
        let file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .await?;
        Ok(Self {
            tmp,
            file,
            hasher: blake3::Hasher::new(),
            written: 0,
        })
    }

    async fn write(&mut self, data: &[u8]) -> io::Result<()> {
        self.hasher.update(data);
        self.written += data.len() as u64;
        self.file.write_all(data).await
    }

    async fn commit(mut self, expected_hash: &str, target: &Path) -> io::Result<()> {
        self.file.flush().await?;
        self.file.sync_all().await?;
        let computed = self.hasher.finalize().to_hex().to_string();
        if computed != expected_hash {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "Full file hash mismatch after restore",
            ));
        }
        tokio::fs::rename(&self.tmp, target).await?;
        if let Some(parent) = target.parent() {
            sync_dir(parent).await?;
        }
        Ok(())
    }
}

/// Size of the buffers used to stream blob / decompressed data to disk.
const STREAM_BUF: usize = 1024 * 1024;

/// Process-wide memory budget (MiB) for blobs being restored concurrently.
///
/// Unencrypted blobs stream with constant memory (two `STREAM_BUF` buffers),
/// and so do v3 encrypted blobs (plus one ciphertext chunk, at most
/// 16 MiB + 16 bytes). v1/v2 encrypted blobs must be held whole once
/// (one-shot AES-GCM is authenticated as a single unit), so each reserves
/// its size from this budget; concurrent
/// restores (CLI + desktop, parallel callers) wait instead of stacking many
/// large blobs in memory. A blob larger than the budget takes all of it and
/// runs alone, so peak blob memory is max(budget, largest blob).
pub const RESTORE_MEM_BUDGET_MIB: u32 = 512;
static RESTORE_MEM_BUDGET: tokio::sync::Semaphore =
    tokio::sync::Semaphore::const_new(RESTORE_MEM_BUDGET_MIB as usize);

/// Budget permits (MiB) needed to restore one blob while holding `held`
/// extra bytes (a whole v1/v2 blob, or one v3 ciphertext chunk).
fn budget_permits(held: Option<u64>) -> u32 {
    const MIB: u64 = 1024 * 1024;
    let buffers = (2 * STREAM_BUF as u64).div_ceil(MIB);
    let held = held.unwrap_or(0).div_ceil(MIB);
    (buffers + held).clamp(1, RESTORE_MEM_BUDGET_MIB as u64) as u32
}

/// One stored object making up (part of) a restored file.
struct BlobRef<'a> {
    /// Storage key, `data/<enc|clear>/<hash>`.
    path: String,
    /// Object id bound into v3 blobs (the content hash).
    object_id: &'a str,
    /// Expected hash of this blob's plaintext (multipart chunks only).
    chunk_hash: Option<&'a str>,
}

/// Largest decoded size accepted for a whole file and for each of its
/// blobs (from the manifest entry, see `FileMetadata::max_plain_size`).
#[derive(Debug, Clone, Copy)]
struct OutputLimits {
    file: u64,
    blob: u64,
}

/// Output side of a blob decode: feeds the optional per-chunk hasher and the
/// verified temp file (which hashes the full file incrementally).
///
/// Enforces the output limits as data arrives, so a malicious repository
/// (e.g. a zstd bomb) cannot fill the disk before the final hash check:
/// writing past a limit fails with `io::ErrorKind::FileTooLarge` and the
/// temp file is removed by the caller.
struct BlobSink<'a> {
    out: &'a mut VerifiedOutput,
    chunk_hasher: Option<&'a mut blake3::Hasher>,
    blob_written: u64,
    limits: OutputLimits,
}

impl BlobSink<'_> {
    async fn write(&mut self, data: &[u8]) -> io::Result<()> {
        let len = data.len() as u64;
        if self.blob_written + len > self.limits.blob {
            return Err(super::limits::too_large(
                "Restored object",
                self.limits.blob,
            ));
        }
        if self.out.written + len > self.limits.file {
            return Err(super::limits::too_large("Restored file", self.limits.file));
        }
        self.blob_written += len;
        if let Some(h) = self.chunk_hasher.as_deref_mut() {
            h.update(data);
        }
        self.out.write(data).await
    }
}

/// Push-based decoder: feeds decrypted/raw input to `sink`,
/// zstd-decompressing on the fly when `compressed`. Memory is bounded by
/// the caller's `outbuf` whatever the blob size or compression ratio (no
/// decompression-bomb amplification).
struct PayloadDecoder {
    zstd: Option<zstd::stream::raw::Decoder<'static>>,
    saw_input: bool,
    frame_complete: bool,
}

impl PayloadDecoder {
    fn new(compressed: bool) -> io::Result<Self> {
        Ok(Self {
            zstd: if compressed {
                Some(zstd::stream::raw::Decoder::new()?)
            } else {
                None
            },
            saw_input: false,
            frame_complete: false,
        })
    }

    async fn push(
        &mut self,
        input: &[u8],
        outbuf: &mut [u8],
        sink: &mut BlobSink<'_>,
    ) -> io::Result<()> {
        use zstd::stream::raw::{InBuffer, Operation, OutBuffer};
        if input.is_empty() {
            return Ok(());
        }
        let Some(decoder) = self.zstd.as_mut() else {
            return sink.write(input).await;
        };
        self.saw_input = true;
        let mut consumed = 0;
        loop {
            let (used, produced, hint) = {
                let mut inb = InBuffer::around(&input[consumed..]);
                let mut outb = OutBuffer::around(&mut *outbuf);
                let hint = decoder.run(&mut inb, &mut outb)?;
                (inb.pos(), outb.pos(), hint)
            };
            consumed += used;
            // Only calls that made progress tell us about the frame: once a
            // frame ends, an extra empty call reports the next frame's hint.
            if used > 0 || produced > 0 {
                self.frame_complete = hint == 0;
            }
            if produced > 0 {
                sink.write(&outbuf[..produced]).await?;
            }
            // Input exhausted and the decoder has nothing more to flush. A
            // short (non-full) output is NOT enough: zstd may return early at
            // block boundaries while still holding decoded data.
            if consumed == input.len() && produced == 0 {
                return Ok(());
            }
        }
    }

    fn finish(self) -> io::Result<()> {
        if self.saw_input && !self.frame_complete {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "Truncated or corrupt compressed data",
            ));
        }
        Ok(())
    }
}

/// Copies `src` to `sink` through a [`PayloadDecoder`].
async fn decode_into<R>(
    src: &mut R,
    compressed: bool,
    inbuf: &mut [u8],
    outbuf: &mut [u8],
    sink: &mut BlobSink<'_>,
) -> io::Result<()>
where
    R: AsyncRead + Unpin + ?Sized,
{
    let mut decoder = PayloadDecoder::new(compressed)?;
    loop {
        let n = src.read(inbuf).await?;
        if n == 0 {
            break;
        }
        decoder.push(&inbuf[..n], outbuf, sink).await?;
    }
    decoder.finish()
}

/// Reads up to `buf.len()` bytes (fewer only at EOF).
async fn read_up_to<R>(src: &mut R, buf: &mut [u8]) -> io::Result<usize>
where
    R: AsyncRead + Unpin + ?Sized,
{
    let mut filled = 0;
    while filled < buf.len() {
        let n = src.read(&mut buf[filled..]).await?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    Ok(filled)
}

/// Restores one encrypted blob: v3 is decrypted chunk by chunk (bounded
/// memory, every chunk authenticated before it is written); v1/v2 blobs are
/// read whole and decrypted in place.
async fn decode_encrypted_blob(
    storage: &dyn Storage,
    blob: &BlobRef<'_>,
    key: &KeyCache,
    compressed: bool,
    outbuf: &mut [u8],
    sink: &mut BlobSink<'_>,
) -> io::Result<()> {
    let mut reader = storage.read_stream(&blob.path).await?;
    let mut magic = [0u8; 8];
    let got = read_up_to(&mut reader, &mut magic).await?;

    if got == magic.len() && &magic == BLOB_MAGIC_V3 {
        let repo_key = key
            .repo_key()
            .ok_or_else(|| io::Error::from(CryptoError::RepoKeyRequired))?;
        let mut dec = repo_key
            .stream_decryptor(blob.object_id, &magic, reader)
            .await?;
        let chunk = dec.header().chunk_size as u64 + crate::crypto::stream::V3_TAG_LEN as u64;
        let _permit = RESTORE_MEM_BUDGET
            .acquire_many(budget_permits(Some(chunk)))
            .await
            .map_err(io::Error::other)?;
        let mut decoder = PayloadDecoder::new(compressed)?;
        while let Some(plain) = dec.next_chunk().await? {
            decoder.push(plain, outbuf, sink).await?;
        }
        return decoder.finish();
    }

    let size = storage.size(&blob.path).await?;
    let _permit = RESTORE_MEM_BUDGET
        .acquire_many(budget_permits(size))
        .await
        .map_err(io::Error::other)?;
    // The size hint comes from storage metadata: cap the up-front allocation.
    const MAX_PREALLOC: u64 = 1024 * 1024 * 1024;
    let cap = size.unwrap_or(0).min(MAX_PREALLOC) as usize;
    let mut whole = Vec::with_capacity(cap.max(got));
    whole.extend_from_slice(&magic[..got]);
    reader.read_to_end(&mut whole).await?;
    // Decrypted in place: one copy of the blob in memory.
    let plain = key.decrypt_owned(whole)?;
    let mut decoder = PayloadDecoder::new(compressed)?;
    for piece in plain.chunks(STREAM_BUF) {
        decoder.push(piece, outbuf, sink).await?;
    }
    decoder.finish()
}

/// Streams, decrypts, decompresses and writes `blobs` in order to a temp
/// file next to `target`, verifying each chunk hash (when given) and the
/// full-file hash before atomically replacing `target`.
///
/// Memory: unencrypted and v3 blobs stream storage -> (decrypt) -> zstd ->
/// hasher -> file with bounded memory; v1/v2 encrypted blobs are held once
/// (decrypted in place) and then stream-decompressed. See
/// [`RESTORE_MEM_BUDGET_MIB`]. On any error (including a v3 blob that fails
/// authentication midway) the temp file is removed: nothing is left behind.
async fn restore_blobs(
    storage: &dyn Storage,
    blobs: &[BlobRef<'_>],
    target: &Path,
    key: Option<&KeyCache>,
    expected_full_hash: &str,
    compressed: bool,
    limits: OutputLimits,
) -> io::Result<()> {
    let mut out = VerifiedOutput::create(target).await?;
    let tmp = out.tmp.clone();

    let result = async {
        let mut inbuf = vec![0u8; STREAM_BUF];
        let mut outbuf = vec![0u8; STREAM_BUF];
        for blob in blobs {
            let mut chunk_hasher = blob.chunk_hash.map(|_| blake3::Hasher::new());
            {
                let mut sink = BlobSink {
                    out: &mut out,
                    chunk_hasher: chunk_hasher.as_mut(),
                    blob_written: 0,
                    limits,
                };
                match key {
                    Some(k) => {
                        decode_encrypted_blob(storage, blob, k, compressed, &mut outbuf, &mut sink)
                            .await?;
                    }
                    None => {
                        let _permit = RESTORE_MEM_BUDGET
                            .acquire_many(budget_permits(None))
                            .await
                            .map_err(io::Error::other)?;
                        let mut src = storage.read_stream(&blob.path).await?;
                        decode_into(&mut src, compressed, &mut inbuf, &mut outbuf, &mut sink)
                            .await?;
                    }
                }
            }

            if let (Some(expected), Some(h)) = (blob.chunk_hash, chunk_hasher)
                && h.finalize().to_hex().as_str() != expected
            {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    format!("Chunk hash mismatch for {}", blob.path),
                ));
            }
        }
        out.commit(expected_full_hash, target).await
    }
    .await;

    if result.is_err() {
        let _ = tokio::fs::remove_file(&tmp).await;
    }
    result
}

/// 🐛 Fix: Validate backup structure before attempting restore
/// This catches issues early and provides clear error messages
async fn validate_backup_structure(
    storage: &dyn Storage,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("🔍 Validating backup structure...");

    // Check for snapshots directory
    match storage.list("snapshots/").await {
        Ok(snapshots) => {
            if snapshots.is_empty() {
                return Err(
                    "❌ No backups found\n\n\
                    The snapshots/ directory is empty.\n\
                    This indicates:\n\
                    - The backup folder is empty or corrupt\n\
                    - The backup was never completed\n\
                    - Only parts of the backup were copied\n\n\
                    Solution: Ensure the entire backup folder was copied from the original computer."
                        .into(),
                );
            }
            info!("✅ Snapshots found: {}", snapshots.len());
        }
        Err(e) => {
            return Err(format!(
                "❌ Cannot read backup metadata\n\n\
                    The snapshots directory is missing or inaccessible.\n\
                    This likely means:\n\
                    - The backup folder structure is incomplete\n\
                    - The entire backup wasn't copied\n\
                    - Permission issues accessing the backup\n\n\
                    Error: {}\n\n\
                    Solution: Re-copy the entire backup folder from the original computer.",
                e
            )
            .into());
        }
    }

    // Check for data directory
    if !storage.exists("data/").await? {
        return Err("❌ Backup data directory missing\n\n\
            The data/ folder is not found in the backup.\n\
            This indicates:\n\
            - Incomplete backup copy (only copied metadata, not data)\n\
            - Corrupted backup structure\n\
            - Wrong backup folder selected\n\n\
            Solution: \n\
            1. Verify the backup folder has these subdirectories:\n\
               - snapshots/\n\
               - data/clear/ (or data/enc/ for encrypted backups)\n\
            2. If missing, re-copy the entire backup from the original computer"
            .into());
    }

    info!("✅ Backup structure is valid");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::types::ChunkMetadata;
    use crate::crypto::hash_file_content;
    use crate::storage::LocalStorage;

    async fn repo_with(
        files: &[(&str, &[u8])],
        multipart: bool,
    ) -> (tempfile::TempDir, LocalStorage) {
        let dir = tempfile::tempdir().unwrap();
        let storage = LocalStorage::new(dir.path().to_str().unwrap());
        let mut manifest = HashMap::new();
        for (name, content) in files {
            let hash = hash_file_content(content).unwrap();
            if multipart {
                let mut chunks = Vec::new();
                for part in content.chunks(3) {
                    let h = hash_file_content(part).unwrap();
                    storage
                        .write(&format!("data/clear/{}", h), part)
                        .await
                        .unwrap();
                    chunks.push(ChunkMetadata {
                        hash: h,
                        stored_size: part.len() as u64,
                        stored_hash: None,
                    });
                }
                manifest.insert(
                    PathBuf::from(name),
                    FileMetadata::new_multipart(hash, false, false, chunks, content.len() as u64),
                );
            } else {
                storage
                    .write(&format!("data/clear/{}", hash), content)
                    .await
                    .unwrap();
                manifest.insert(PathBuf::from(name), FileMetadata::new(hash, false, false));
            }
        }
        storage
            .write(
                "snapshots/2026-01-01T000000Z.toml",
                toml::to_string(&manifest).unwrap().as_bytes(),
            )
            .await
            .unwrap();
        (dir, storage)
    }

    async fn run(storage: &LocalStorage, target: &Path, force: bool) -> ReportData {
        restore_from_storage(
            storage,
            RestoreOptions {
                force,
                ..RestoreOptions::new(target)
            },
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn zstd_bomb_stops_at_recorded_size_and_leaves_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let storage = LocalStorage::new(dir.path().to_str().unwrap());
        let content = b"small file";
        let hash = hash_file_content(content).unwrap();
        // 512 MiB of zeros in a few KiB, where a 10-byte file belongs.
        let bomb = zstd::stream::encode_all(std::io::Read::take(std::io::repeat(0), 512 << 20), 1)
            .unwrap();
        storage
            .write(&format!("data/clear/{}", hash), &bomb)
            .await
            .unwrap();
        let out = tempfile::tempdir().unwrap();
        let target = out.path().join("f.txt");
        let blobs = [BlobRef {
            path: format!("data/clear/{}", hash),
            object_id: &hash,
            chunk_hash: None,
        }];
        let meta = FileMetadata::new(hash.clone(), false, true).with_size(content.len() as u64);
        let err = restore_blobs(
            &storage,
            &blobs,
            &target,
            None,
            &hash,
            true,
            OutputLimits {
                file: meta.max_plain_size(),
                blob: meta.max_object_plain_size(),
            },
        )
        .await
        .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::FileTooLarge);
        assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);

        // Through the public entry point: reported as a failed file.
        let mut manifest = HashMap::new();
        manifest.insert(PathBuf::from("f.txt"), meta);
        storage
            .write(
                "snapshots/2026-01-01T000000Z.toml",
                toml::to_string(&manifest).unwrap().as_bytes(),
            )
            .await
            .unwrap();
        let report = run(&storage, out.path(), false).await;
        assert_eq!(report.files_with_errors, 1);
        assert!(report.errors[0].contains("exceeds"), "{:?}", report.errors);
        assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn multipart_restore_respects_force_and_does_not_truncate() {
        let (_repo, storage) = repo_with(&[("big.bin", b"0123456789abcdef")], true).await;
        let out = tempfile::tempdir().unwrap();
        let target = out.path().join("big.bin");
        std::fs::write(&target, b"precious").unwrap();

        let report = run(&storage, out.path(), false).await;
        assert_eq!(report.files_with_errors, 1);
        assert_eq!(std::fs::read(&target).unwrap(), b"precious");

        let report = run(&storage, out.path(), true).await;
        assert_eq!(report.files_with_errors, 0, "{:?}", report.errors);
        assert_eq!(std::fs::read(&target).unwrap(), b"0123456789abcdef");
    }

    #[tokio::test]
    async fn corrupt_chunk_never_replaces_existing_file() {
        let (repo, storage) = repo_with(&[("big.bin", b"0123456789")], true).await;
        // Corrupt one chunk in place.
        let h = hash_file_content(b"345").unwrap();
        std::fs::write(repo.path().join("data/clear").join(&h), b"XXX").unwrap();
        let out = tempfile::tempdir().unwrap();
        let target = out.path().join("big.bin");
        std::fs::write(&target, b"precious").unwrap();
        let report = run(&storage, out.path(), true).await;
        assert_eq!(report.files_with_errors, 1);
        assert_eq!(std::fs::read(&target).unwrap(), b"precious");
        // No temp files left behind.
        assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn restore_refuses_to_write_through_symlinks() {
        let (_repo, storage) =
            repo_with(&[("a.txt", b"payload"), ("sub/b.txt", b"payload2")], false).await;
        let out = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let victim = outside.path().join("victim");
        std::fs::write(&victim, b"untouched").unwrap();
        std::os::unix::fs::symlink(&victim, out.path().join("a.txt")).unwrap();
        std::os::unix::fs::symlink(outside.path(), out.path().join("sub")).unwrap();

        let report = run(&storage, out.path(), true).await;
        assert_eq!(report.files_with_errors, 2, "{:?}", report.errors);
        assert_eq!(std::fs::read(&victim).unwrap(), b"untouched");
        assert!(!outside.path().join("b.txt").exists());
    }

    #[tokio::test]
    async fn restore_does_not_expand_env_vars_in_paths() {
        let (_repo, storage) = repo_with(&[("$HOME/x.txt", b"data")], false).await;
        let out = tempfile::tempdir().unwrap();
        let report = run(&storage, out.path(), false).await;
        assert_eq!(report.files_with_errors, 0, "{:?}", report.errors);
        assert!(out.path().join("$HOME").join("x.txt").exists());
    }
}
