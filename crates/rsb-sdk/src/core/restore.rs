use super::cancellation::CancellationToken;
use super::manifest::find_latest_snapshot_cached;
use super::restore_select::{FileSelector, find_snapshot_at_or_before, snapshot_id_of};
use super::types::{FileMetadata, ProgressCallback};
use crate::config::Config;
use crate::crypto::{BLOB_MAGIC_V3, CryptoError, KeyCache};
use crate::options::RestoreOptions;
use crate::report::ReportData;
use crate::storage::{BlobReader, Storage, sync_dir};
use crate::storage::{validate_content_hash, validate_storage_path};
use chrono::Utc;
use indicatif::{ProgressBar, ProgressStyle};
use std::collections::{BTreeSet, HashMap};
use std::io::{self, ErrorKind};
use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
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

/// Default number of files restored concurrently: twice the CPU count,
/// between 4 and 64. Concurrency overlaps storage latency, fsyncs and
/// decoding; memory stays bounded by [`RESTORE_MEM_BUDGET_MIB`].
pub fn default_restore_concurrency() -> usize {
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    (cpus * 2).clamp(4, 64)
}

/// Restore implementation working on any [`Storage`] (used by tests too).
/// `options.storage` is ignored here: `storage` is used.
///
/// Files are restored concurrently (see [`RestoreOptions::concurrency`]),
/// each with the same guarantees as a sequential restore: temp file next to
/// the target, chunk and full-file hash verification, then an atomic
/// rename. Entries are handed out in path order, progress is reported in
/// that order and errors are listed in that order, whatever order the
/// files finish in. Entries whose paths differ only by case are restored
/// one after the other (they are the same file on case-insensitive file
/// systems). Cancellation stops handing out new files; files in progress
/// finish or fail as a whole.
pub async fn restore_from_storage(
    storage: &dyn Storage,
    options: RestoreOptions,
) -> crate::error::Result<ReportData> {
    let RestoreOptions {
        snapshot_id,
        at_or_before,
        include,
        target_path,
        encryption_key,
        force,
        versioned,
        concurrency,
        on_progress,
        cancellation_token,
        storage: _,
    } = options;
    let encryption_key = encryption_key.as_ref().map(|k| k.as_str());
    let start_time = Instant::now();

    // User input first: bad patterns / conflicting options fail before any
    // repository access.
    let selector = FileSelector::new(&include)?;
    if snapshot_id.is_some() && at_or_before.is_some() {
        return Err(crate::error::RsbError::InvalidInput(
            "Give either a snapshot id or a date (at_or_before), not both".to_string(),
        ));
    }

    // 🐛 Fix: Validate backup structure before attempting restore
    validate_backup_structure(storage).await?;

    let snapshot_id = match at_or_before {
        Some(when) => Some(find_snapshot_at_or_before(storage, when).await?),
        None => snapshot_id,
    };
    let snapshot_id = snapshot_id.as_deref();

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
    let entries: Vec<(PathBuf, FileMetadata)> = manifest.into_iter().collect();
    // Selection happens before the target is created: a selection that
    // matches nothing fails without touching the destination.
    let mut entries = selector.select(entries, snapshot_id_of(&manifest_path))?;
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    if !selector.is_empty() {
        info!(
            "Restoring {} selected file(s) of {}",
            entries.len(),
            manifest_path
        );
    }

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

    let pb = ProgressBar::new(entries.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template(
            "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta}) {msg}")
            .unwrap()
            .progress_chars("#>-"),
    );

    let total_files = entries.len();
    let (parallel, serial) = split_case_collisions(&entries);
    let run = RestoreRun {
        storage,
        root: &restore_root_canon,
        key: key_cache.as_ref(),
        force,
        entries: &entries,
        cancel: cancellation_token.as_ref(),
        on_progress: on_progress.as_ref(),
        pb: &pb,
        started: Mutex::new(0),
        results: Mutex::new(vec![None; total_files]),
        dirs: Mutex::new(BTreeSet::new()),
    };
    let workers = concurrency
        .filter(|&n| n > 0)
        .unwrap_or_else(default_restore_concurrency);
    run_workers(&run, &parallel, workers).await;
    run_workers(&run, &serial, 1).await;

    if cancellation_token
        .as_ref()
        .is_some_and(|t| t.is_cancelled())
    {
        info!("⏹️ Restore cancelled by user");
    }
    pb.finish_with_message("Restore completed");

    let RestoreRun { results, dirs, .. } = run;
    let mut errors = Vec::new();
    let mut success = 0;
    for r in results.into_inner().unwrap_or_else(|e| e.into_inner()) {
        match r {
            Some(Ok(())) => success += 1,
            Some(Err(msg)) => errors.push(msg),
            None => {} // not attempted (cancelled)
        }
    }
    // Each restored file was fsync'ed before its rename; one fsync per
    // directory now makes the renames durable before success is reported.
    for dir in dirs.into_inner().unwrap_or_else(|e| e.into_inner()) {
        if let Err(e) = sync_dir(&dir).await {
            let msg = format!("Failed to sync directory {}: {}", dir.display(), e);
            error!("{}", msg);
            errors.push(msg);
        }
    }

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

/// Splits entry indices into those that can be restored concurrently and
/// those whose path collides with another one when case is ignored (same
/// file on case-insensitive file systems): the latter are restored
/// sequentially, in path order, so `force`/"already exists" behave as in a
/// sequential restore.
fn split_case_collisions(entries: &[(PathBuf, FileMetadata)]) -> (Vec<usize>, Vec<usize>) {
    let folded: Vec<String> = entries
        .iter()
        .map(|(p, _)| p.to_string_lossy().to_lowercase())
        .collect();
    let mut seen: HashMap<&str, usize> = HashMap::with_capacity(entries.len());
    for f in &folded {
        *seen.entry(f.as_str()).or_default() += 1;
    }
    (0..entries.len()).partition(|&i| seen[folded[i].as_str()] == 1)
}

/// Shared state of one restore, used by every worker.
struct RestoreRun<'a> {
    storage: &'a dyn Storage,
    root: &'a Path,
    key: Option<&'a KeyCache>,
    force: bool,
    entries: &'a [(PathBuf, FileMetadata)],
    cancel: Option<&'a CancellationToken>,
    on_progress: Option<&'a ProgressCallback>,
    pb: &'a ProgressBar,
    /// Entries handed out so far (also serializes progress reporting).
    started: Mutex<usize>,
    /// Outcome per entry index (`None` = not attempted).
    results: Mutex<Vec<Option<Result<(), String>>>>,
    /// Directories that received a file (fsync'ed once at the end).
    dirs: Mutex<BTreeSet<PathBuf>>,
}

impl RestoreRun<'_> {
    /// Next entry of `queue` to restore, or `None` when the queue is empty
    /// or the restore was cancelled. Progress is reported here, under one
    /// lock, so callbacks see a strictly increasing count in path order.
    fn next(&self, queue: &[usize], pos: &AtomicUsize) -> Option<usize> {
        let mut started = self.started.lock().unwrap_or_else(|e| e.into_inner());
        if self.cancel.is_some_and(|t| t.is_cancelled()) {
            return None;
        }
        let i = *queue.get(pos.fetch_add(1, Ordering::Relaxed))?;
        let msg = format!("Restoring: {}", self.entries[i].0.display());
        self.pb.set_message(msg.clone());
        if let Some(cb) = self.on_progress {
            cb(*started, self.entries.len(), msg);
        }
        *started += 1;
        Some(i)
    }

    async fn worker(&self, queue: &[usize], pos: &AtomicUsize) {
        while let Some(i) = self.next(queue, pos) {
            let (rel_path, metadata) = &self.entries[i];
            let result = restore_entry(
                self.storage,
                self.root,
                rel_path,
                metadata,
                self.key,
                self.force,
            )
            .await;
            let result = match result {
                Ok(dir) => {
                    self.dirs
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .insert(dir);
                    Ok(())
                }
                Err(msg) => {
                    error!("{}", msg);
                    Err(msg)
                }
            };
            self.results.lock().unwrap_or_else(|e| e.into_inner())[i] = Some(result);
            self.pb.inc(1);
        }
    }
}

/// Restores the entries of `queue` with up to `concurrency` files in
/// flight.
///
/// On a multi-threaded tokio runtime the workers run on scoped OS threads
/// (at most one per CPU, each driving several files), so decryption,
/// decompression and hashing use several cores while the storage and the
/// key cache stay borrowed. Elsewhere (current-thread runtime) the workers
/// run concurrently on the calling task, which still overlaps I/O.
async fn run_workers(run: &RestoreRun<'_>, queue: &[usize], concurrency: usize) {
    use futures_util::future::join_all;
    use tokio::runtime::{Handle, RuntimeFlavor};

    if queue.is_empty() {
        return;
    }
    let pos = AtomicUsize::new(0);
    let n = concurrency.clamp(1, queue.len());
    let multi_thread =
        Handle::try_current().is_ok_and(|h| h.runtime_flavor() == RuntimeFlavor::MultiThread);
    if n == 1 || !multi_thread {
        join_all((0..n).map(|_| run.worker(queue, &pos))).await;
        return;
    }
    let cpus = std::thread::available_parallelism()
        .map(|c| c.get())
        .unwrap_or(1);
    let threads = n.min(cpus).max(1);
    let per_thread = n.div_ceil(threads);
    let handle = Handle::current();
    let (handle, pos) = (&handle, &pos);
    tokio::task::block_in_place(|| {
        std::thread::scope(|s| {
            for _ in 0..threads {
                s.spawn(move || {
                    handle.block_on(join_all((0..per_thread).map(|_| run.worker(queue, pos))))
                });
            }
        })
    });
}

/// Restores one manifest entry; returns the directory the file was
/// written to, or a user-facing message on failure.
async fn restore_entry(
    storage: &dyn Storage,
    restore_root_canon: &Path,
    rel_path: &Path,
    metadata: &FileMetadata,
    key_cache: Option<&KeyCache>,
    force: bool,
) -> Result<PathBuf, String> {
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
                stored_size: Some(c.stored_size).filter(|&n| n > 0),
            })
            .collect(),
        None => {
            // No HEAD first: a missing object is reported by the GET
            // (see `MissingObject`), which saves one round trip per file.
            let data_path = format!("data/{}/{}", kind, metadata.hash);
            vec![BlobRef {
                path: data_path,
                object_id: metadata.hash.as_str(),
                chunk_hash: None,
                stored_size: None,
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
        if metadata.chunks.is_none() && MissingObject::is(&e) {
            // 🐛 Fix: More informative error about missing data
            return format!(
                "❌ Missing data for file: {}\n   This file is referenced in the backup metadata but the data file is missing.\n   Your backup may be incomplete or corrupted.",
                rel_path.display()
            );
        }
        let what = if metadata.chunks.is_some() {
            "multipart "
        } else {
            ""
        };
        format!("Failed to restore {}{}: {}", what, rel_path.display(), e)
    })?;
    Ok(target
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| restore_root_canon.to_path_buf()))
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
        // Data reaches stable storage before the rename below (ordering
        // barrier); the restore fsyncs every directory at the end, before
        // it reports success.
        let file = self.file.into_std().await;
        tokio::task::spawn_blocking(move || crate::storage::sync_before_rename(&file))
            .await
            .map_err(io::Error::other)??;
        let computed = self.hasher.finalize().to_hex().to_string();
        if computed != expected_hash {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "Full file hash mismatch after restore",
            ));
        }
        // The caller fsyncs the parent directory (once per directory, at
        // the end of the restore) to make the rename durable.
        tokio::fs::rename(&self.tmp, target).await
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
    /// Stored size recorded in the manifest (multipart chunks only); bounds
    /// what a prefetch may buffer.
    stored_size: Option<u64>,
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
///
/// `prefetched` holds the whole stored blob when it was fetched ahead (its
/// memory, including the decode buffers, is already reserved from
/// [`RESTORE_MEM_BUDGET`]); otherwise the blob is streamed from storage.
async fn decode_encrypted_blob(
    storage: &dyn Storage,
    blob: &BlobRef<'_>,
    key: &KeyCache,
    compressed: bool,
    outbuf: &mut [u8],
    sink: &mut BlobSink<'_>,
    prefetched: Option<Vec<u8>>,
) -> io::Result<()> {
    let is_prefetched = prefetched.is_some();
    let mut reader: BlobReader = match prefetched {
        // v1/v2 are authenticated as a whole: decrypt the buffer in place.
        Some(whole) if !crate::crypto::is_v3(&whole) => {
            let plain = key.decrypt_owned(whole)?;
            return push_whole(&plain, compressed, outbuf, sink).await;
        }
        Some(whole) => Box::pin(std::io::Cursor::new(whole)),
        None => open_blob(storage, &blob.path).await?,
    };
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
        let _permit = if is_prefetched {
            None
        } else {
            Some(
                RESTORE_MEM_BUDGET
                    .acquire_many(budget_permits(Some(chunk)))
                    .await
                    .map_err(io::Error::other)?,
            )
        };
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
    push_whole(&plain, compressed, outbuf, sink).await
}

/// A data object referenced by the manifest does not exist in storage.
#[derive(Debug)]
struct MissingObject(String);

impl std::fmt::Display for MissingObject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "object {} is missing from the repository", self.0)
    }
}

impl std::error::Error for MissingObject {}

impl MissingObject {
    fn is(e: &io::Error) -> bool {
        e.kind() == ErrorKind::NotFound && e.get_ref().is_some_and(|i| i.is::<MissingObject>())
    }
}

/// Opens a data object for reading; a missing object is reported as
/// [`MissingObject`].
async fn open_blob(storage: &dyn Storage, path: &str) -> io::Result<BlobReader> {
    storage.read_stream(path).await.map_err(|e| {
        if e.kind() == ErrorKind::NotFound {
            io::Error::new(ErrorKind::NotFound, MissingObject(path.to_string()))
        } else {
            e
        }
    })
}

/// Decodes an in-memory payload into `sink`.
async fn push_whole(
    plain: &[u8],
    compressed: bool,
    outbuf: &mut [u8],
    sink: &mut BlobSink<'_>,
) -> io::Result<()> {
    let mut decoder = PayloadDecoder::new(compressed)?;
    for piece in plain.chunks(STREAM_BUF) {
        decoder.push(piece, outbuf, sink).await?;
    }
    decoder.finish()
}

/// Chunks of a multipart file fetched ahead of the one being written.
const PREFETCH_CHUNKS: usize = 2;

/// Largest stored chunk that is prefetched into memory: chunks are
/// written as 32 MiB of plaintext, so their stored size stays well below
/// this; anything larger (or of unknown size) is streamed instead.
const PREFETCH_MAX_STORED: u64 = 2 * super::types::CHUNK_SIZE as u64;

/// A multipart chunk downloaded ahead of the decoder, with its memory
/// reservation (stored bytes plus the decode buffers).
struct Prefetched<'s> {
    data: Vec<u8>,
    _budget: tokio::sync::SemaphorePermit<'static>,
    _slot: tokio::sync::SemaphorePermit<'s>,
}

/// Downloads `blob` whole if its manifest size is known and small enough
/// and the memory budget has room right now (never waits for budget, so a
/// prefetch can never hold memory that a decoder is waiting for).
///
/// Returns `None` when the blob should be streamed on demand instead
/// (no room, unknown or oversized blob, or any storage error: the on-demand
/// read reports it).
async fn prefetch<'s>(
    storage: &dyn Storage,
    blob: &BlobRef<'_>,
    slots: &'s tokio::sync::Semaphore,
) -> Option<Prefetched<'s>> {
    let size = blob.stored_size.filter(|&n| n <= PREFETCH_MAX_STORED)?;
    let slot = slots.acquire().await.ok()?;
    // Stored bytes + the largest v3 ciphertext chunk + the two stream
    // buffers: decoding a prefetched blob never takes budget again.
    let held = size
        + crate::crypto::stream::V3_MAX_CHUNK_SIZE as u64
        + crate::crypto::stream::V3_TAG_LEN as u64;
    let budget = RESTORE_MEM_BUDGET
        .try_acquire_many(budget_permits(Some(held)))
        .ok()?;
    let mut reader = storage.read_stream(&blob.path).await.ok()?;
    let mut data = Vec::with_capacity(size as usize);
    (&mut reader)
        .take(size + 1)
        .read_to_end(&mut data)
        .await
        .ok()?;
    if data.len() as u64 > size {
        // Larger than the manifest says: let the streaming path handle it.
        return None;
    }
    Some(Prefetched {
        data,
        _budget: budget,
        _slot: slot,
    })
}

/// Streams, decrypts, decompresses and writes `blobs` in order to a temp
/// file next to `target`, verifying each chunk hash (when given) and the
/// full-file hash before atomically replacing `target`.
///
/// Memory: unencrypted and v3 blobs stream storage -> (decrypt) -> zstd ->
/// hasher -> file with bounded memory; v1/v2 encrypted blobs are held once
/// (decrypted in place) and then stream-decompressed. The chunks of a
/// multipart file are fetched up to [`PREFETCH_CHUNKS`] ahead, in parallel,
/// when the memory budget allows, and always written in order. See
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
    use futures_util::future::{Either, select};
    use futures_util::{StreamExt, stream};

    let mut out = VerifiedOutput::create(target).await?;
    let tmp = out.tmp.clone();

    let slots = tokio::sync::Semaphore::new(PREFETCH_CHUNKS);
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let multipart = blobs.len() > 1;
    // In-order prefetch of the chunks; dropped as soon as the writer stops.
    //
    // Once one chunk is not prefetched, no later chunk of this file is
    // either: a writer that streams a chunk on demand (and may wait for
    // budget) then never holds budget for chunks it has not reached, so
    // writers cannot all wait on budget held by each other's prefetches.
    let stopped = std::sync::atomic::AtomicBool::new(false);
    let producer = async {
        if !multipart {
            return;
        }
        let mut fetched = stream::iter(blobs)
            .map(|b| async {
                if stopped.load(Ordering::Relaxed) {
                    return None;
                }
                prefetch(storage, b, &slots).await
            })
            .buffered(PREFETCH_CHUNKS);
        while let Some(p) = fetched.next().await {
            let p = if stopped.load(Ordering::Relaxed) {
                None // dropped here: frees its budget
            } else {
                p
            };
            if p.is_none() {
                stopped.store(true, Ordering::Relaxed);
            }
            if tx.send(p).is_err() {
                break;
            }
        }
    };

    let writer = async {
        let mut inbuf = vec![0u8; STREAM_BUF];
        let mut outbuf = vec![0u8; STREAM_BUF];
        for blob in blobs {
            let prefetched = if multipart {
                rx.recv().await.flatten()
            } else {
                None
            };
            let (data, _reservation) = match prefetched {
                Some(p) => (Some(p.data), Some((p._budget, p._slot))),
                None => (None, None),
            };
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
                        decode_encrypted_blob(
                            storage,
                            blob,
                            k,
                            compressed,
                            &mut outbuf,
                            &mut sink,
                            data,
                        )
                        .await?;
                    }
                    None => {
                        let _permit = match data {
                            Some(_) => None,
                            None => Some(
                                RESTORE_MEM_BUDGET
                                    .acquire_many(budget_permits(None))
                                    .await
                                    .map_err(io::Error::other)?,
                            ),
                        };
                        let mut src: BlobReader = match data {
                            Some(d) => Box::pin(std::io::Cursor::new(d)),
                            None => open_blob(storage, &blob.path).await?,
                        };
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
        drop(rx);
        out.commit(expected_full_hash, target).await
    };

    let result = {
        let (writer, producer) = (std::pin::pin!(writer), std::pin::pin!(producer));
        match select(writer, producer).await {
            Either::Left((result, _producer)) => result,
            Either::Right(((), writer)) => writer.await,
        }
    };

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
    use std::sync::Arc;

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
            stored_size: None,
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

    /// Many single-blob and multipart files, a few of them broken.
    async fn mixed_repo() -> (tempfile::TempDir, LocalStorage, Vec<(String, Vec<u8>)>) {
        let files: Vec<(String, Vec<u8>)> = (0..60)
            .map(|i| {
                (
                    format!("d{}/f{:02}.bin", i % 7, i),
                    format!("content of file {:02}", i).into_bytes(),
                )
            })
            .collect();
        let refs: Vec<(&str, &[u8])> = files
            .iter()
            .map(|(n, c)| (n.as_str(), c.as_slice()))
            .collect();
        let (dir, storage) = repo_with(&refs[..30], false).await;
        // Second half multipart, in the same repository.
        let (dir2, storage2) = repo_with(&refs[30..], true).await;
        let mut manifest: HashMap<PathBuf, FileMetadata> = HashMap::new();
        for s in [&storage, &storage2] {
            let snap = s.read("snapshots/2026-01-01T000000Z.toml").await.unwrap();
            let m: HashMap<PathBuf, FileMetadata> =
                toml::from_str(std::str::from_utf8(&snap).unwrap()).unwrap();
            manifest.extend(m);
        }
        for e in std::fs::read_dir(dir2.path().join("data/clear")).unwrap() {
            let e = e.unwrap();
            std::fs::copy(e.path(), dir.path().join("data/clear").join(e.file_name())).unwrap();
        }
        storage
            .write(
                "snapshots/2026-01-01T000000Z.toml",
                toml::to_string(&manifest).unwrap().as_bytes(),
            )
            .await
            .unwrap();
        // Break one single-blob file and the (unique) last chunk of a
        // multipart file.
        for name in ["d3/f10.bin", "d4/f46.bin"] {
            let meta = &manifest[Path::new(name)];
            let h = match &meta.chunks {
                Some(c) => c.last().unwrap().hash.clone(),
                None => meta.hash.clone(),
            };
            std::fs::write(dir.path().join("data/clear").join(h), b"garbage").unwrap();
        }
        (dir, storage, files)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn parallel_restore_matches_sequential_and_reports_in_path_order() {
        let (_repo, storage, files) = mixed_repo().await;
        let mut reports = Vec::new();
        for concurrency in [1, 3, 16] {
            let out = tempfile::tempdir().unwrap();
            let seen = Arc::new(Mutex::new(Vec::new()));
            let seen2 = seen.clone();
            let report = restore_from_storage(
                &storage,
                RestoreOptions {
                    concurrency: Some(concurrency),
                    on_progress: Some(Arc::new(move |i, total, msg| {
                        seen2.lock().unwrap().push((i, total, msg));
                    })),
                    ..RestoreOptions::new(out.path())
                },
            )
            .await
            .unwrap();
            assert_eq!(report.total_files, 60);
            assert_eq!(report.files_processed, 58, "{:?}", report.errors);
            assert_eq!(report.files_with_errors, 2);
            for (name, content) in &files {
                let p = out.path().join(name);
                if name == "d3/f10.bin" || name == "d4/f46.bin" {
                    assert!(!p.exists(), "{} must not be restored", name);
                } else {
                    assert_eq!(&std::fs::read(&p).unwrap(), content, "{}", name);
                }
            }
            // Progress: 0..60 in path order, whatever the concurrency.
            let seen = seen.lock().unwrap();
            let mut sorted: Vec<&String> = files.iter().map(|(n, _)| n).collect();
            sorted.sort();
            assert_eq!(seen.len(), 60);
            for (k, (i, total, msg)) in seen.iter().enumerate() {
                assert_eq!((*i, *total), (k, 60));
                assert_eq!(msg, &format!("Restoring: {}", sorted[k]));
            }
            // No temp files anywhere.
            for d in std::fs::read_dir(out.path()).unwrap() {
                for f in std::fs::read_dir(d.unwrap().path()).unwrap() {
                    let name = f.unwrap().file_name().to_string_lossy().to_string();
                    assert!(!name.starts_with('.'), "temp file left: {}", name);
                }
            }
            reports.push(report.errors);
        }
        // Same errors, same order, for every concurrency.
        assert!(reports[0][0].contains("d3/f10.bin"), "{:?}", reports[0]);
        assert!(reports[0][1].contains("d4/f46.bin"), "{:?}", reports[0]);
        assert_eq!(reports[0], reports[1]);
        assert_eq!(reports[0], reports[2]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancellation_stops_handing_out_files() {
        let (_repo, storage, _files) = mixed_repo().await;
        let out = tempfile::tempdir().unwrap();
        let token = CancellationToken::new();
        let t = token.clone();
        let report = restore_from_storage(
            &storage,
            RestoreOptions {
                concurrency: Some(8),
                cancellation_token: Some(token),
                on_progress: Some(Arc::new(move |i, _, _| {
                    if i == 4 {
                        t.cancel();
                    }
                })),
                ..RestoreOptions::new(out.path())
            },
        )
        .await
        .unwrap();
        // Entries 0..=4 were handed out before the cancellation was seen.
        assert_eq!(report.files_processed + report.files_with_errors, 5);
        assert_eq!(report.total_files, 60);
    }

    #[tokio::test]
    async fn missing_object_is_reported_without_a_head_per_file() {
        use crate::storage::InstrumentedStorage;
        let (repo, local) = repo_with(&[("a.txt", b"alpha"), ("b.txt", b"bravo")], false).await;
        let h = hash_file_content(b"bravo").unwrap();
        std::fs::remove_file(repo.path().join("data/clear").join(h)).unwrap();
        let storage = InstrumentedStorage::new(Arc::new(local));
        let out = tempfile::tempdir().unwrap();
        let report = restore_from_storage(&storage, RestoreOptions::new(out.path()))
            .await
            .unwrap();
        assert_eq!(report.files_processed, 1);
        assert_eq!(report.files_with_errors, 1);
        assert!(
            report.errors[0].contains("Missing data for file: b.txt"),
            "{:?}",
            report.errors
        );
        assert!(!out.path().join("b.txt").exists());
        // One GET per file and no HEAD per file.
        let c = storage.counts();
        assert_eq!(c.get, 2 + 1, "{}", c); // 2 objects + the manifest
        assert_eq!(c.head, 1, "{}", c); // the manifest size check
    }

    #[test]
    fn case_colliding_paths_are_restored_sequentially() {
        let m = |p: &str| {
            (
                PathBuf::from(p),
                FileMetadata::new("0".repeat(64), false, false),
            )
        };
        let entries = vec![m("A.txt"), m("a.txt"), m("b.txt"), m("dir/X"), m("dir/x")];
        let (parallel, serial) = split_case_collisions(&entries);
        assert_eq!(parallel, vec![2]);
        assert_eq!(serial, vec![0, 1, 3, 4]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn multipart_chunk_larger_than_manifest_says_is_streamed() {
        let content = b"0123456789abcdef".to_vec();
        let (repo, storage) = repo_with(&[("big.bin", &content)], true).await;
        // The manifest under-states a chunk's stored size: the prefetch
        // refuses to buffer it and the streaming path restores it.
        let snap = "snapshots/2026-01-01T000000Z.toml";
        let raw = storage.read(snap).await.unwrap();
        let mut m: HashMap<PathBuf, FileMetadata> =
            toml::from_str(std::str::from_utf8(&raw).unwrap()).unwrap();
        for c in m
            .get_mut(Path::new("big.bin"))
            .unwrap()
            .chunks
            .as_mut()
            .unwrap()
        {
            c.stored_size = 1;
        }
        storage
            .write(snap, toml::to_string(&m).unwrap().as_bytes())
            .await
            .unwrap();
        let out = tempfile::tempdir().unwrap();
        let report = run(&storage, out.path(), false).await;
        assert_eq!(report.files_with_errors, 0, "{:?}", report.errors);
        assert_eq!(std::fs::read(out.path().join("big.bin")).unwrap(), content);
        drop(repo);
    }
}
