use crate::backup::perform_backup;
use crate::config::Config;
use crate::utils::ensure_directory_exists;
use chrono::{DateTime, Utc};
use notify::{RecursiveMode, Result as NotifyResult, Watcher};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing;

/// changes detected in real-time
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ChangeType {
    Created,
    Modified,
    Deleted,
    Renamed,
}

/// File change detected in real-time
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileChange {
    pub path: PathBuf,
    pub change_type: ChangeType,
    pub timestamp: DateTime<Utc>,
    pub size: u64,
    pub hash: Option<String>,
}

/// Queue of changes to synchronize
#[derive(Clone)]
pub struct ChangeQueue {
    changes: Arc<RwLock<VecDeque<FileChange>>>,
    max_size: usize,
}

impl ChangeQueue {
    pub fn new(max_size: usize) -> Self {
        ChangeQueue {
            changes: Arc::new(RwLock::new(VecDeque::with_capacity(max_size))),
            max_size,
        }
    }

    pub async fn add_change(&self, change: FileChange) {
        let mut q = self.changes.write().await;
        if q.len() >= self.max_size {
            q.pop_front();
        }
        q.push_back(change);
    }

    pub async fn get_changes(&self) -> Vec<FileChange> {
        self.changes.read().await.iter().cloned().collect()
    }

    /// Removes and returns every queued change (the queue is left empty).
    pub async fn take_all(&self) -> Vec<FileChange> {
        std::mem::take(&mut *self.changes.write().await).into()
    }

    pub async fn clear(&self) {
        self.changes.write().await.clear();
    }

    pub async fn count(&self) -> usize {
        self.changes.read().await.len()
    }
}

/// File monitor in real-time
pub struct RealtimeWatcher {
    watcher: Option<notify::RecommendedWatcher>,
    queue: ChangeQueue,
    watched_paths: Arc<RwLock<Vec<PathBuf>>>,
}

impl RealtimeWatcher {
    pub fn new(queue: ChangeQueue) -> Self {
        RealtimeWatcher {
            watcher: None,
            queue,
            watched_paths: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub async fn start_watching(&mut self, root_path: &Path) -> NotifyResult<()> {
        let queue = self.queue.clone();
        let root = root_path.to_path_buf();
        // The notify callback runs on notify's own thread, outside the tokio
        // runtime: spawn through an explicit handle (tokio::spawn would panic).
        let rt = tokio::runtime::Handle::current();

        let mut watcher =
            notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
                match res {
                    Ok(event) => {
                        let change_type = match event.kind {
                            notify::EventKind::Create(_) => ChangeType::Created,
                            notify::EventKind::Modify(notify::event::ModifyKind::Name(_)) => {
                                ChangeType::Renamed
                            }
                            notify::EventKind::Modify(_) => ChangeType::Modified,
                            notify::EventKind::Remove(_) => ChangeType::Deleted,
                            // Ignore accesses and unknown events
                            _ => return,
                        };
                        let queue_clone = queue.clone();
                        rt.spawn(async move {
                            for path in &event.paths {
                                // Deleted paths (and the old side of a rename)
                                // no longer exist: record them with size 0
                                // instead of silently dropping them.
                                let size = match std::fs::symlink_metadata(path) {
                                    Ok(metadata) => metadata.len(),
                                    Err(_)
                                        if matches!(
                                            change_type,
                                            ChangeType::Deleted | ChangeType::Renamed
                                        ) =>
                                    {
                                        0
                                    }
                                    // Created/modified then removed before we
                                    // looked: nothing to sync.
                                    Err(_) => continue,
                                };

                                let change = FileChange {
                                    path: path.clone(),
                                    change_type: change_type.clone(),
                                    timestamp: Utc::now(),
                                    size,
                                    hash: None, // Calculated later
                                };

                                queue_clone.add_change(change).await;
                            }
                        });
                    }
                    Err(e) => eprintln!("Error monitoring files: {}", e),
                }
            })?;

        watcher.watch(&root, RecursiveMode::Recursive)?;
        self.watcher = Some(watcher);
        self.watched_paths.write().await.push(root);

        Ok(())
    }

    pub async fn stop_watching(&mut self) {
        self.watcher = None;
        self.watched_paths.write().await.clear();
    }

    pub async fn get_watched_paths(&self) -> Vec<PathBuf> {
        self.watched_paths.read().await.clone()
    }
}

/// Synchronization strategy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncStrategy {
    /// Sync immediately or in batch?
    pub immediate_sync: bool,
    /// Batch interval (seconds)
    pub batch_interval: u64,
    /// Maximum file size for immediate sync (bytes)
    pub immediate_threshold: u64,
    /// Ignore patterns (regex)
    pub ignore_patterns: Vec<String>,
    /// Direction: "uni" (source → destination) or "bi" (bidirectional)
    pub direction: String,
}

impl Default for SyncStrategy {
    fn default() -> Self {
        SyncStrategy {
            immediate_sync: true,
            batch_interval: 5,
            immediate_threshold: 10_485_760, // 10 MB
            ignore_patterns: vec![".*\\.tmp$".into(), ".*\\.lock$".into()],
            direction: "uni".into(),
        }
    }
}

/// Callback for when changes are processed
pub type OnChangeCallback = Box<dyn Fn(FileChange) + Send + Sync>;

/// Real-time synchronizer
pub struct RealtimeSync {
    watcher: RealtimeWatcher,
    pub queue: ChangeQueue,
    strategy: SyncStrategy,
    synced_count: Arc<RwLock<usize>>,
    failed_count: Arc<RwLock<usize>>,
    is_processing: Arc<RwLock<bool>>,
}

impl RealtimeSync {
    pub fn new(strategy: SyncStrategy) -> Self {
        let queue = ChangeQueue::new(1000);
        let watcher = RealtimeWatcher::new(queue.clone());

        RealtimeSync {
            watcher,
            queue,
            strategy,
            synced_count: Arc::new(RwLock::new(0)),
            failed_count: Arc::new(RwLock::new(0)),
            is_processing: Arc::new(RwLock::new(false)),
        }
    }

    pub async fn start(&mut self, source: &Path) -> NotifyResult<()> {
        self.watcher.start_watching(source).await
    }

    pub async fn stop(&mut self) {
        *self.is_processing.write().await = false;
        self.watcher.stop_watching().await;
    }

    /// Start automatic processing loop
    /// Processes changes every `batch_interval` seconds
    pub async fn start_processing_loop(self: Arc<Self>) {
        *self.is_processing.write().await = true;

        tokio::spawn(async move {
            loop {
                if !*self.is_processing.read().await {
                    break;
                }

                // Wait configured interval
                tokio::time::sleep(tokio::time::Duration::from_secs(
                    self.strategy.batch_interval,
                ))
                .await;

                // Process batch
                let changes = self.process_batch().await;
                for change in changes {
                    self.increment_synced().await;
                    // Log processed change
                    tracing::debug!("Change processed: {:?}", change);
                }
            }
        });
    }

    /// Stop processing loop
    pub async fn stop_processing(&self) {
        *self.is_processing.write().await = false;
    }

    /// Check if currently processing
    pub async fn is_processing(&self) -> bool {
        *self.is_processing.read().await
    }

    /// Process a single change with retry and error handling
    pub async fn process_single_change(
        &self,
        change: FileChange,
        max_retries: u32,
    ) -> Result<(), String> {
        if self.should_ignore(&change.path) {
            return Ok(());
        }

        let mut attempt = 0;

        loop {
            attempt += 1;

            match std::fs::metadata(&change.path) {
                Ok(_metadata) => {
                    self.increment_synced().await;
                    return Ok(());
                }
                Err(e) => {
                    if attempt < max_retries {
                        // wait before retrying
                        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                        continue;
                    } else {
                        self.increment_failed().await;
                        return Err(format!("Failed after {} attempts: {}", max_retries, e));
                    }
                }
            }
        }
    }

    pub async fn peek_pending_changes(&self) -> Vec<FileChange> {
        self.queue.get_changes().await
    }

    pub async fn get_detailed_stats(&self) -> DetailedSyncStats {
        let stats = self.get_stats().await;
        DetailedSyncStats {
            pending_changes: stats.pending_changes,
            synced: stats.synced,
            failed: stats.failed,
            sync_ratio: if stats.synced + stats.failed == 0 {
                0.0
            } else {
                (stats.synced as f64) / ((stats.synced + stats.failed) as f64)
            },
        }
    }

    /// Drains the queue and returns the changes that are not ignored.
    ///
    /// Previously this only *copied* the queue, so the same changes were
    /// returned (and counted) on every batch forever.
    pub async fn process_batch(&self) -> Vec<FileChange> {
        self.queue
            .take_all()
            .await
            .into_iter()
            .filter(|change| !self.should_ignore(&change.path))
            .collect()
    }

    fn should_ignore(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy();
        for pattern in &self.strategy.ignore_patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                if re.is_match(&path_str) {
                    return true;
                }
            }
        }
        false
    }

    pub async fn get_stats(&self) -> SyncStats {
        SyncStats {
            pending_changes: self.queue.count().await,
            synced: *self.synced_count.read().await,
            failed: *self.failed_count.read().await,
        }
    }

    pub async fn increment_synced(&self) {
        *self.synced_count.write().await += 1;
    }

    pub async fn increment_failed(&self) {
        *self.failed_count.write().await += 1;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetailedSyncStats {
    pub pending_changes: usize,
    pub synced: usize,
    pub failed: usize,
    pub sync_ratio: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncStats {
    pub pending_changes: usize,
    pub synced: usize,
    pub failed: usize,
}

pub async fn sync_all_files(src: &Path, dst: &Path) -> Result<usize, String> {
    let src = src.to_path_buf();
    let dst = dst.to_path_buf();

    tokio::task::spawn_blocking(move || {
        use std::fs;
        use walkdir::WalkDir;

        if !src.exists() {
            return Err("Source folder does not exist".to_string());
        }

        let dst_str = dst
            .to_str()
            .ok_or("Invalid path characters in destination")?;
        ensure_directory_exists(dst_str)?;

        let mut count = 0;
        let mut walk_errors: Vec<String> = Vec::new();
        let mut skipped_symlinks = 0usize;

        // follow_links(false) is the default; we additionally use the
        // entry's own file type (lstat) so symlinks are never followed on
        // the source side.
        for entry in WalkDir::new(&src).follow_links(false) {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    tracing::warn!("sync_all_files: walk error: {}", e);
                    walk_errors.push(e.to_string());
                    continue;
                }
            };
            let file_type = entry.file_type();
            if file_type.is_symlink() {
                skipped_symlinks += 1;
                continue;
            }
            if !file_type.is_file() {
                continue;
            }

            let path = entry.path();
            let relative = path.strip_prefix(&src).map_err(|e| e.to_string())?;
            let dst_file = dst.join(relative);

            if let Some(parent) = dst_file.parent() {
                // Plain mkdir: no ~/$VAR expansion of names taken from the source tree.
                fs::create_dir_all(parent)
                    .map_err(|e| format!("Error creating {}: {}", parent.display(), e))?;
            }

            // Never write through a symlink planted at the destination.
            if let Ok(meta) = fs::symlink_metadata(&dst_file) {
                if meta.file_type().is_symlink() {
                    return Err(format!(
                        "Refusing to overwrite symlink at destination: {}",
                        dst_file.display()
                    ));
                }
            }

            fs::copy(path, &dst_file).map_err(|e| format!("Error copying: {}", e))?;
            count += 1;
        }

        if skipped_symlinks > 0 {
            tracing::info!("sync_all_files: skipped {} symlinks", skipped_symlinks);
        }
        if !walk_errors.is_empty() {
            return Err(format!(
                "Copied {} files, but {} entries could not be read (first: {})",
                count,
                walk_errors.len(),
                walk_errors[0]
            ));
        }

        Ok(count)
    })
    .await
    .map_err(|e| format!("Error in synchronization task: {}", e))?
}

/// Create automatic backup with encryption and chunking
///
/// # Arguments
/// * `src` - Path of the source folder to backup
/// * `backup_dst` - Path of the backup destination folder
/// * `password` - Optional password for encryption
///
/// # Returns
/// Name/description of the backup created or error
pub async fn create_backup(
    src: &Path,
    backup_dst: &Path,
    password: Option<&str>,
) -> Result<String, String> {
    let src = src.to_path_buf();
    let backup_dst = backup_dst.to_path_buf();
    let password = password.map(|p| p.to_string());

    // Check if source exists
    if !src.exists() {
        return Err("Source does not exist".to_string());
    }

    // Create directory in blocking thread to avoid UI freeze
    let backup_dst_clone = backup_dst.clone();
    tokio::task::spawn_blocking(move || {
        let dst_str = backup_dst_clone
            .to_str()
            .ok_or("Invalid path characters in destination".to_string())?;
        ensure_directory_exists(dst_str).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("Error in backup task: {}", e))?
    .map_err(|e| e.to_string())?;

    let timestamp = chrono::Local::now().format("%Y-%m-%d_%H%M%S").to_string();

    // Create Config to use perform_backup from rsb-core
    // Chunking is done automatically (files > MULTIPART_THRESHOLD, CHUNK_SIZE chunks)
    let config = Config {
        source_path: src.to_string_lossy().to_string(),
        destination_path: backup_dst.to_string_lossy().to_string(),
        exclude_patterns: crate::config::DEFAULT_EXCLUDE_PATTERNS
            .iter()
            .map(|&s| s.to_string())
            .collect(),
        encryption_key: password.clone(),
        backup_mode: "incremental".to_string(),
        s3_bucket: None,
        s3_region: None,
        s3_endpoint: None,
        encrypt_patterns: Some(vec!["*".to_string()]), // Encrypt all files
        pause_on_low_battery: None,
        s3: None,
        s3_buckets: None,
        pause_on_high_cpu: None,
        compression_level: Some(3),
        max_threads: None,
        channel_buffer_size: 8192,
    };

    // Use perform_backup to create backup with encryption and chunking
    match perform_backup(
        &config,
        "incremental",
        password.as_deref(),
        false,
        false,
        None,
        None,
    )
    .await
    {
        Ok(report) => Ok(format!(
            "✅ Backup: {} with encryption\n📊 Files: {}/{}\n🔐 {}MB chunks applied",
            timestamp,
            report.files_processed,
            report.total_files,
            crate::core::types::CHUNK_SIZE / (1024 * 1024)
        )),
        Err(e) => Err(format!("Error creating backup: {}", e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn process_batch_drains_queue() {
        let sync = RealtimeSync::new(SyncStrategy::default());
        sync.queue
            .add_change(FileChange {
                path: PathBuf::from("/a.txt"),
                change_type: ChangeType::Deleted,
                timestamp: Utc::now(),
                size: 0,
                hash: None,
            })
            .await;
        assert_eq!(sync.process_batch().await.len(), 1);
        assert_eq!(sync.queue.count().await, 0);
        assert!(sync.process_batch().await.is_empty());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn sync_all_files_skips_symlinks_and_refuses_dst_symlinks() {
        let src = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret"), b"s").unwrap();
        std::fs::write(src.path().join("f.txt"), b"f").unwrap();
        std::os::unix::fs::symlink(outside.path().join("secret"), src.path().join("link"))
            .unwrap();
        assert_eq!(sync_all_files(src.path(), dst.path()).await.unwrap(), 1);
        assert!(!dst.path().join("link").exists());

        let victim = outside.path().join("victim");
        std::fs::write(&victim, b"untouched").unwrap();
        std::fs::remove_file(dst.path().join("f.txt")).unwrap();
        std::os::unix::fs::symlink(&victim, dst.path().join("f.txt")).unwrap();
        assert!(sync_all_files(src.path(), dst.path()).await.is_err());
        assert_eq!(std::fs::read(&victim).unwrap(), b"untouched");
    }
}
