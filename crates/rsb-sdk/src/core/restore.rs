use super::manifest::find_latest_snapshot_cached;
use super::types::FileMetadata;
use crate::config::Config;
use crate::crypto::KeyCache;
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

    // One PBKDF2 per salt for the whole restore instead of one per blob.
    let key_cache = encryption_key.map(|k| KeyCache::new(k.as_bytes()));

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

    let blobs: Vec<(String, Option<&str>)> = match &metadata.chunks {
        Some(chunks) => chunks
            .iter()
            .map(|c| (format!("data/{}/{}", kind, c.hash), Some(c.hash.as_str())))
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
            vec![(data_path, None)]
        }
    };

    restore_blobs(
        storage,
        &blobs,
        &target,
        key,
        &metadata.hash,
        metadata.compressed,
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
        })
    }

    async fn write(&mut self, data: &[u8]) -> io::Result<()> {
        self.hasher.update(data);
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
/// Unencrypted blobs stream with constant memory (two `STREAM_BUF` buffers).
/// Encrypted blobs must be held whole once (AES-GCM is authenticated as a
/// single unit), so each reserves its size from this budget; concurrent
/// restores (CLI + desktop, parallel callers) wait instead of stacking many
/// large blobs in memory. A blob larger than the budget takes all of it and
/// runs alone, so peak blob memory is max(budget, largest blob).
pub const RESTORE_MEM_BUDGET_MIB: u32 = 512;
static RESTORE_MEM_BUDGET: tokio::sync::Semaphore =
    tokio::sync::Semaphore::const_new(RESTORE_MEM_BUDGET_MIB as usize);

/// Budget permits (MiB) needed to restore one blob of `blob_size` bytes.
fn budget_permits(blob_size: Option<u64>, encrypted: bool) -> u32 {
    const MIB: u64 = 1024 * 1024;
    let buffers = (2 * STREAM_BUF as u64).div_ceil(MIB);
    let held = if encrypted {
        blob_size.unwrap_or(0).div_ceil(MIB)
    } else {
        0
    };
    (buffers + held).clamp(1, RESTORE_MEM_BUDGET_MIB as u64) as u32
}

/// Output side of a blob decode: feeds the optional per-chunk hasher and the
/// verified temp file (which hashes the full file incrementally).
struct BlobSink<'a> {
    out: &'a mut VerifiedOutput,
    chunk_hasher: Option<&'a mut blake3::Hasher>,
}

impl BlobSink<'_> {
    async fn write(&mut self, data: &[u8]) -> io::Result<()> {
        if let Some(h) = self.chunk_hasher.as_deref_mut() {
            h.update(data);
        }
        self.out.write(data).await
    }
}

/// Copies `src` to `sink`, zstd-decompressing on the fly when `compressed`.
/// Memory is bounded by `inbuf` + `outbuf` whatever the blob size or the
/// compression ratio (no decompression-bomb amplification).
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
    if !compressed {
        loop {
            let n = src.read(inbuf).await?;
            if n == 0 {
                return Ok(());
            }
            sink.write(&inbuf[..n]).await?;
        }
    }

    use zstd::stream::raw::{Decoder, InBuffer, Operation, OutBuffer};
    let mut decoder = Decoder::new()?;
    let mut saw_input = false;
    let mut frame_complete = false;
    loop {
        let n = src.read(inbuf).await?;
        if n == 0 {
            break;
        }
        saw_input = true;
        let mut consumed = 0;
        loop {
            let (used, produced, hint) = {
                let mut input = InBuffer::around(&inbuf[consumed..n]);
                let mut output = OutBuffer::around(&mut *outbuf);
                let hint = decoder.run(&mut input, &mut output)?;
                (input.pos(), output.pos(), hint)
            };
            consumed += used;
            // Only calls that made progress tell us about the frame: once a
            // frame ends, an extra empty call reports the next frame's hint.
            if used > 0 || produced > 0 {
                frame_complete = hint == 0;
            }
            if produced > 0 {
                sink.write(&outbuf[..produced]).await?;
            }
            // Input exhausted and the decoder has nothing more to flush. A
            // short (non-full) output is NOT enough: zstd may return early at
            // block boundaries while still holding decoded data.
            if consumed == n && produced == 0 {
                break;
            }
        }
    }
    if saw_input && !frame_complete {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "Truncated or corrupt compressed data",
        ));
    }
    Ok(())
}

/// Reads a whole (encrypted) blob into one allocation sized from the
/// object's metadata (no grow-and-copy, no collected intermediate buffers).
async fn read_blob_exact(
    storage: &dyn Storage,
    data_path: &str,
    size_hint: Option<u64>,
) -> io::Result<Vec<u8>> {
    // The hint comes from storage metadata: cap the up-front allocation.
    const MAX_PREALLOC: u64 = 1024 * 1024 * 1024;
    let cap = size_hint.unwrap_or(0).min(MAX_PREALLOC) as usize;
    let mut buf = Vec::with_capacity(cap);
    let mut reader = storage.read_stream(data_path).await?;
    reader.read_to_end(&mut buf).await?;
    Ok(buf)
}

/// Streams, decrypts, decompresses and writes `blobs` in order to a temp
/// file next to `target`, verifying each chunk hash (when given) and the
/// full-file hash before atomically replacing `target`.
///
/// Memory: unencrypted blobs stream storage -> zstd -> hasher -> file with
/// constant memory; encrypted blobs are held once (decrypted in place) and
/// then stream-decompressed. See [`RESTORE_MEM_BUDGET_MIB`].
async fn restore_blobs(
    storage: &dyn Storage,
    blobs: &[(String, Option<&str>)],
    target: &Path,
    key: Option<&KeyCache>,
    expected_full_hash: &str,
    compressed: bool,
) -> io::Result<()> {
    let mut out = VerifiedOutput::create(target).await?;
    let tmp = out.tmp.clone();

    let result = async {
        let mut inbuf = vec![0u8; STREAM_BUF];
        let mut outbuf = vec![0u8; STREAM_BUF];
        for (data_path, chunk_hash) in blobs {
            let mut chunk_hasher = chunk_hash.map(|_| blake3::Hasher::new());
            {
                let mut sink = BlobSink {
                    out: &mut out,
                    chunk_hasher: chunk_hasher.as_mut(),
                };
                match key {
                    Some(k) => {
                        let size = storage.size(data_path).await?;
                        let _permit = RESTORE_MEM_BUDGET
                            .acquire_many(budget_permits(size, true))
                            .await
                            .map_err(io::Error::other)?;
                        let blob = read_blob_exact(storage, data_path, size).await?;
                        // Decrypted in place: one copy of the blob in memory.
                        let plain = k.decrypt_owned(blob)?;
                        let mut src: &[u8] = &plain;
                        decode_into(&mut src, compressed, &mut inbuf, &mut outbuf, &mut sink)
                            .await?;
                    }
                    None => {
                        let _permit = RESTORE_MEM_BUDGET
                            .acquire_many(budget_permits(None, false))
                            .await
                            .map_err(io::Error::other)?;
                        let mut src = storage.read_stream(data_path).await?;
                        decode_into(&mut src, compressed, &mut inbuf, &mut outbuf, &mut sink)
                            .await?;
                    }
                }
            }

            if let (Some(expected), Some(h)) = (chunk_hash, chunk_hasher)
                && h.finalize().to_hex().as_str() != *expected
            {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    format!("Chunk hash mismatch for {}", data_path),
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
