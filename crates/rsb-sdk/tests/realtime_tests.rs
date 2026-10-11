// Tests for rsb-core/src/realtime.rs

use chrono::Utc;
use rsb_sdk::realtime::{
    ChangeQueue, ChangeType, FileChange, RealtimeSync, SyncStrategy, sync_all_files,
};
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

#[test]
fn test_file_change_creation() {
    let change = FileChange {
        path: PathBuf::from("/path/to/file.txt"),
        change_type: ChangeType::Created,
        timestamp: Utc::now(),
        size: 1024,
        hash: None,
    };

    assert_eq!(change.path, PathBuf::from("/path/to/file.txt"));
    assert!(matches!(change.change_type, ChangeType::Created));
    assert_eq!(change.size, 1024);
}

#[test]
fn test_file_change_types() {
    let created = FileChange {
        path: PathBuf::from("/new_file.txt"),
        change_type: ChangeType::Created,
        timestamp: Utc::now(),
        size: 512,
        hash: None,
    };

    let modified = FileChange {
        path: PathBuf::from("/existing_file.txt"),
        change_type: ChangeType::Modified,
        timestamp: Utc::now(),
        size: 1024,
        hash: None,
    };

    let deleted = FileChange {
        path: PathBuf::from("/old_file.txt"),
        change_type: ChangeType::Deleted,
        timestamp: Utc::now(),
        size: 0,
        hash: None,
    };

    assert!(matches!(created.change_type, ChangeType::Created));
    assert!(matches!(modified.change_type, ChangeType::Modified));
    assert!(matches!(deleted.change_type, ChangeType::Deleted));
}

#[tokio::test]
async fn test_change_queue_basic() {
    let queue = ChangeQueue::new(10);

    let change = FileChange {
        path: PathBuf::from("/test.txt"),
        change_type: ChangeType::Created,
        timestamp: Utc::now(),
        size: 256,
        hash: None,
    };

    queue.add_change(change.clone()).await;
    let changes = queue.get_changes().await;

    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].path, PathBuf::from("/test.txt"));
    assert!(matches!(changes[0].change_type, ChangeType::Created));
}

#[test]
fn test_realtime_watcher_creation() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");

    fs::write(temp_dir.path().join("test.txt"), "content").expect("Failed to create file");

    assert!(temp_dir.path().exists(), "Temp directory should exist");
}

#[test]
fn test_multiple_file_changes() {
    let changes = [
        FileChange {
            path: PathBuf::from("/file1.txt"),
            change_type: ChangeType::Created,
            timestamp: Utc::now(),
            size: 100,
            hash: None,
        },
        FileChange {
            path: PathBuf::from("/file2.txt"),
            change_type: ChangeType::Modified,
            timestamp: Utc::now(),
            size: 200,
            hash: None,
        },
        FileChange {
            path: PathBuf::from("/file3.txt"),
            change_type: ChangeType::Deleted,
            timestamp: Utc::now(),
            size: 0,
            hash: None,
        },
    ];

    assert_eq!(changes.len(), 3);
    assert_eq!(changes[0].path, PathBuf::from("/file1.txt"));
    assert_eq!(changes[1].path, PathBuf::from("/file2.txt"));
    assert_eq!(changes[2].path, PathBuf::from("/file3.txt"));
}

#[test]
fn test_change_timestamps() {
    let now = Utc::now();
    let change = FileChange {
        path: PathBuf::from("/test.txt"),
        change_type: ChangeType::Created,
        timestamp: now,
        size: 512,
        hash: None,
    };

    assert_eq!(change.timestamp, now);
}

#[test]
fn test_large_file_change() {
    let large_size = 1024 * 1024 * 1024;

    let change = FileChange {
        path: PathBuf::from("/large_file.iso"),
        change_type: ChangeType::Created,
        timestamp: Utc::now(),
        size: large_size,
        hash: None,
    };

    assert_eq!(change.size, large_size);
}

#[test]
fn test_nested_path_changes() {
    let paths = [
        "/root/subdir/file.txt",
        "/root/subdir/nested/deep/file.txt",
        "/another/path/file.txt",
    ];

    let changes: Vec<FileChange> = paths
        .iter()
        .map(|path| FileChange {
            path: PathBuf::from(path),
            change_type: ChangeType::Created,
            timestamp: Utc::now(),
            size: 100,
            hash: None,
        })
        .collect();

    assert_eq!(changes.len(), 3);
    assert!(changes[1].path.to_string_lossy().contains("nested/deep"));
}

#[test]
fn test_file_change_with_hash() {
    let change = FileChange {
        path: PathBuf::from("/file.txt"),
        change_type: ChangeType::Created,
        timestamp: Utc::now(),
        size: 512,
        hash: Some("abc123def456".to_string()),
    };

    assert!(change.hash.is_some());
    assert_eq!(change.hash.unwrap(), "abc123def456");
}

#[test]
fn test_rename_change_type() {
    let change = FileChange {
        path: PathBuf::from("/old_name.txt"),
        change_type: ChangeType::Renamed,
        timestamp: Utc::now(),
        size: 256,
        hash: None,
    };

    assert!(matches!(change.change_type, ChangeType::Renamed));
}

// Testes assíncronos para ChangeQueue

#[tokio::test]
async fn test_change_queue_multiple_adds() {
    let queue = ChangeQueue::new(100);

    for i in 0..5 {
        let change = FileChange {
            path: PathBuf::from(format!("/file{}.txt", i)),
            change_type: ChangeType::Created,
            timestamp: Utc::now(),
            size: 100 * (i as u64 + 1),
            hash: None,
        };
        queue.add_change(change).await;
    }

    let changes = queue.get_changes().await;
    assert_eq!(changes.len(), 5);
}

#[tokio::test]
async fn test_change_queue_max_size() {
    let queue = ChangeQueue::new(3);

    for i in 0..5 {
        let change = FileChange {
            path: PathBuf::from(format!("/file{}.txt", i)),
            change_type: ChangeType::Created,
            timestamp: Utc::now(),
            size: 100,
            hash: None,
        };
        queue.add_change(change).await;
    }

    let changes = queue.get_changes().await;
    // Queue has max_size=3, so it should keep only the last 3
    assert_eq!(changes.len(), 3);
    // The first one (file0.txt) should have been removed
    assert_eq!(changes[0].path, PathBuf::from("/file2.txt"));
    assert_eq!(changes[2].path, PathBuf::from("/file4.txt"));
}

#[tokio::test]
async fn test_change_queue_clear() {
    let queue = ChangeQueue::new(10);

    for i in 0..3 {
        let change = FileChange {
            path: PathBuf::from(format!("/file{}.txt", i)),
            change_type: ChangeType::Created,
            timestamp: Utc::now(),
            size: 100,
            hash: None,
        };
        queue.add_change(change).await;
    }

    assert_eq!(queue.count().await, 3);
    queue.clear().await;
    assert_eq!(queue.count().await, 0);
}

#[tokio::test]
async fn test_change_queue_count() {
    let queue = ChangeQueue::new(10);

    assert_eq!(queue.count().await, 0);

    for i in 0..4 {
        let change = FileChange {
            path: PathBuf::from(format!("/file{}.txt", i)),
            change_type: ChangeType::Created,
            timestamp: Utc::now(),
            size: 100,
            hash: None,
        };
        queue.add_change(change).await;
    }

    assert_eq!(queue.count().await, 4);
}

// Testes para RealtimeSync

#[tokio::test]
async fn test_realtime_sync_creation() {
    let strategy = SyncStrategy::default();
    let sync = RealtimeSync::new(strategy);

    let stats = sync.get_stats().await;
    assert_eq!(stats.pending_changes, 0);
    assert_eq!(stats.synced, 0);
    assert_eq!(stats.failed, 0);
}

#[tokio::test]
async fn test_realtime_sync_process_batch_with_ignore_patterns() {
    let strategy = SyncStrategy {
        ignore_patterns: vec![".*\\.tmp$".into()],
        ..Default::default()
    };
    let sync = RealtimeSync::new(strategy);

    // Adicionar mudança que não deve ser ignorada
    let change1 = FileChange {
        path: PathBuf::from("/file.txt"),
        change_type: ChangeType::Created,
        timestamp: Utc::now(),
        size: 100,
        hash: None,
    };

    // Adicionar mudança que pode ser ignorada
    let change2 = FileChange {
        path: PathBuf::from("/temp.tmp"),
        change_type: ChangeType::Created,
        timestamp: Utc::now(),
        size: 50,
        hash: None,
    };

    sync.queue.add_change(change1).await;
    sync.queue.add_change(change2).await;

    let processed = sync.process_batch().await;

    // Apenas a primeira mudança deve ser processada (tmp ignorada)
    assert_eq!(processed.len(), 1);
    assert_eq!(processed[0].path, PathBuf::from("/file.txt"));
}

#[tokio::test]
async fn test_sync_strategy_default() {
    let strategy = SyncStrategy::default();

    assert!(strategy.immediate_sync);
    assert_eq!(strategy.batch_interval, 5);
    assert_eq!(strategy.immediate_threshold, 10_485_760); // 10 MB
    assert_eq!(strategy.direction, "uni");
    assert!(!strategy.ignore_patterns.is_empty());
}

#[tokio::test]
async fn test_sync_strategy_custom() {
    let strategy = SyncStrategy {
        immediate_sync: false,
        batch_interval: 10,
        immediate_threshold: 5_000_000,
        ignore_patterns: vec![".*\\.lock".into()],
        direction: "bi".into(),
    };

    assert!(!strategy.immediate_sync);
    assert_eq!(strategy.batch_interval, 10);
    assert_eq!(strategy.immediate_threshold, 5_000_000);
    assert_eq!(strategy.direction, "bi");
}

// File system integration tests

#[tokio::test]
async fn test_file_sync_basic() {
    let src_dir = TempDir::new().expect("Failed to create source dir");
    let _dst_dir = TempDir::new().expect("Failed to create destination dir");

    // Create a test file
    let test_file = src_dir.path().join("test.txt");
    fs::write(&test_file, "test content").expect("Failed to write test file");

    // Use RealtimeSync in a simple mode
    let queue = ChangeQueue::new(100);

    let change = FileChange {
        path: test_file.clone(),
        change_type: ChangeType::Created,
        timestamp: Utc::now(),
        size: 12,
        hash: None,
    };

    queue.add_change(change).await;
    assert_eq!(queue.count().await, 1);

    let changes = queue.get_changes().await;
    assert_eq!(changes[0].size, 12);
}

// Tests for sync_all_files

#[tokio::test]
async fn test_sync_all_files_single_file() {
    let src_dir = TempDir::new().expect("Failed to create source dir");
    let dst_dir = TempDir::new().expect("Failed to create destination dir");

    // Create a test file
    let test_file = src_dir.path().join("test.txt");
    fs::write(&test_file, "test content").expect("Failed to write test file");

    // Synchronize
    let result = sync_all_files(src_dir.path(), dst_dir.path()).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 1);

    // Verify that the file was copied
    let dst_file = dst_dir.path().join("test.txt");
    assert!(dst_file.exists());
    let content = fs::read_to_string(&dst_file).expect("Failed to read destination file");
    assert_eq!(content, "test content");
}

#[tokio::test]
async fn test_sync_all_files_multiple_files() {
    let src_dir = TempDir::new().expect("Failed to create source dir");
    let dst_dir = TempDir::new().expect("Failed to create destination dir");

    // Create multiple files
    fs::write(src_dir.path().join("file1.txt"), "content1").expect("Failed to write file1");
    fs::write(src_dir.path().join("file2.txt"), "content2").expect("Failed to write file2");
    fs::write(src_dir.path().join("file3.txt"), "content3").expect("Failed to write file3");

    let result = sync_all_files(src_dir.path(), dst_dir.path()).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 3);

    // Verify that all files were copied
    assert!(dst_dir.path().join("file1.txt").exists());
    assert!(dst_dir.path().join("file2.txt").exists());
    assert!(dst_dir.path().join("file3.txt").exists());
}

#[tokio::test]
async fn test_sync_all_files_nested_directories() {
    let src_dir = TempDir::new().expect("Failed to create source dir");
    let dst_dir = TempDir::new().expect("Failed to create destination dir");

    // Create nested structure
    fs::create_dir_all(src_dir.path().join("subdir/nested")).expect("Failed to create dirs");
    fs::write(src_dir.path().join("file.txt"), "root").expect("Failed to write root file");
    fs::write(src_dir.path().join("subdir/file.txt"), "sub").expect("Failed to write sub file");
    fs::write(src_dir.path().join("subdir/nested/file.txt"), "nested")
        .expect("Failed to write nested file");

    let result = sync_all_files(src_dir.path(), dst_dir.path()).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 3);

    // Verify replicated structure
    assert!(dst_dir.path().join("file.txt").exists());
    assert!(dst_dir.path().join("subdir/file.txt").exists());
    assert!(dst_dir.path().join("subdir/nested/file.txt").exists());
}

#[tokio::test]
async fn test_sync_all_files_nonexistent_source() {
    let nonexistent = PathBuf::from("/nonexistent/path");
    let dst_dir = TempDir::new().expect("Failed to create destination dir");

    let result = sync_all_files(&nonexistent, dst_dir.path()).await;

    assert!(result.is_err());
    assert!(result.unwrap_err().contains("does not exist"));
}

#[tokio::test]
async fn test_sync_all_files_preserves_content() {
    let src_dir = TempDir::new().expect("Failed to create source dir");
    let dst_dir = TempDir::new().expect("Failed to create destination dir");

    let content = "Test content with special chars: áéíóú €";
    fs::write(src_dir.path().join("test.txt"), content).expect("Failed to write file");

    let result = sync_all_files(src_dir.path(), dst_dir.path()).await;
    assert!(result.is_ok());

    let dst_content = fs::read_to_string(dst_dir.path().join("test.txt"))
        .expect("Failed to read destination file");
    assert_eq!(dst_content, content);
}

#[tokio::test]
async fn test_sync_all_files_empty_directory() {
    let src_dir = TempDir::new().expect("Failed to create source dir");
    let dst_dir = TempDir::new().expect("Failed to create destination dir");

    // Create an empty subfolder
    fs::create_dir(src_dir.path().join("empty_subdir")).expect("Failed to create subdir");

    let result = sync_all_files(src_dir.path(), dst_dir.path()).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 0); // No files, only empty folders
}

// Tests for automatic processing with notify

#[tokio::test]
async fn test_realtime_sync_start_processing() {
    let strategy = SyncStrategy::default();
    let sync = std::sync::Arc::new(RealtimeSync::new(strategy));

    // Verify it is not processing initially
    assert!(!sync.is_processing().await);

    // Start processing
    let sync_clone = sync.clone();
    sync_clone.start_processing_loop().await;

    // Give some time for the task to start
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Stop processing
    sync.stop_processing().await;
    assert!(!sync.is_processing().await);
}

#[tokio::test]
async fn test_peek_pending_changes() {
    let _queue = ChangeQueue::new(10);
    let strategy = SyncStrategy::default();
    let sync = RealtimeSync::new(strategy);

    let change = FileChange {
        path: PathBuf::from("/test.txt"),
        change_type: ChangeType::Created,
        timestamp: Utc::now(),
        size: 100,
        hash: None,
    };

    sync.queue.add_change(change.clone()).await;

    // Peek should not remove
    let pending = sync.peek_pending_changes().await;
    assert_eq!(pending.len(), 1);

    // Peek again should return the same change
    let pending2 = sync.peek_pending_changes().await;
    assert_eq!(pending2.len(), 1);
}

#[tokio::test]
async fn test_get_detailed_stats_ratio_zero() {
    let strategy = SyncStrategy::default();
    let sync = RealtimeSync::new(strategy);

    let detailed = sync.get_detailed_stats().await;

    assert_eq!(detailed.synced, 0);
    assert_eq!(detailed.failed, 0);
    assert_eq!(detailed.sync_ratio, 0.0);
}

#[tokio::test]
async fn test_process_batch_filters_correctly() {
    let src_dir = TempDir::new().expect("Failed to create source dir");
    let strategy = SyncStrategy {
        immediate_sync: true,
        batch_interval: 5,
        immediate_threshold: 10_485_760,
        ignore_patterns: vec![".*\\.lock$".into(), ".*\\.tmp$".into()],
        direction: "uni".into(),
    };
    let sync = RealtimeSync::new(strategy);

    // Add changes
    let file1 = src_dir.path().join("important.txt");
    let file2 = src_dir.path().join("cache.lock");
    let file3 = src_dir.path().join("temp.tmp");

    fs::write(&file1, "important").expect("Failed to write file1");
    fs::write(&file2, "lock").expect("Failed to write file2");
    fs::write(&file3, "temp").expect("Failed to write file3");

    sync.queue
        .add_change(FileChange {
            path: file1,
            change_type: ChangeType::Created,
            timestamp: Utc::now(),
            size: 9,
            hash: None,
        })
        .await;

    sync.queue
        .add_change(FileChange {
            path: file2,
            change_type: ChangeType::Created,
            timestamp: Utc::now(),
            size: 4,
            hash: None,
        })
        .await;

    sync.queue
        .add_change(FileChange {
            path: file3,
            change_type: ChangeType::Created,
            timestamp: Utc::now(),
            size: 4,
            hash: None,
        })
        .await;

    let processed = sync.process_batch().await;

    // Only the important.txt file should be processed
    assert_eq!(processed.len(), 1);
    assert!(
        processed[0]
            .path
            .to_string_lossy()
            .contains("important.txt")
    );
}

// ---------------------------------------------------------------------------
// Real backups triggered by debounced batches
// ---------------------------------------------------------------------------

use rsb_sdk::config::Config;
use rsb_sdk::realtime::BackupRunner;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

fn change(path: impl Into<PathBuf>) -> FileChange {
    FileChange {
        path: path.into(),
        change_type: ChangeType::Modified,
        timestamp: Utc::now(),
        size: 1,
        hash: None,
    }
}

fn fast_strategy() -> SyncStrategy {
    SyncStrategy {
        batch_interval: 0,
        ..SyncStrategy::default()
    }
}

fn test_config(src: &std::path::Path, dst: &std::path::Path) -> Config {
    Config {
        source_path: src.to_string_lossy().to_string(),
        destination_path: dst.to_string_lossy().to_string(),
        exclude_patterns: vec![],
        encryption_key: None,
        backup_mode: "incremental".to_string(),
        s3_bucket: None,
        s3_region: None,
        s3_endpoint: None,
        encrypt_patterns: Some(vec!["*".to_string()]),
        pause_on_low_battery: None,
        s3: None,
        s3_buckets: None,
        pause_on_high_cpu: None,
        compression_level: Some(3),
        max_threads: Some(2),
        channel_buffer_size: 8192,
    }
}

fn snapshot_count(dst: &std::path::Path) -> usize {
    fs::read_dir(dst.join("snapshots"))
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter(|e| e.path().extension().is_some_and(|x| x == "toml"))
                .count()
        })
        .unwrap_or(0)
}

/// Fake runner: counts calls and the maximum number of runs in flight,
/// sleeps `delay`, and fails the first `fail_first` calls.
struct Probe {
    calls: Arc<AtomicUsize>,
    in_flight: Arc<AtomicUsize>,
    max_in_flight: Arc<AtomicUsize>,
}

fn probe_runner(fail_first: usize, delay: Duration) -> (BackupRunner, Probe) {
    let probe = Probe {
        calls: Arc::new(AtomicUsize::new(0)),
        in_flight: Arc::new(AtomicUsize::new(0)),
        max_in_flight: Arc::new(AtomicUsize::new(0)),
    };
    let (calls, in_flight, max_in_flight) = (
        probe.calls.clone(),
        probe.in_flight.clone(),
        probe.max_in_flight.clone(),
    );
    let runner: BackupRunner = Arc::new(move || {
        let (calls, in_flight, max_in_flight) =
            (calls.clone(), in_flight.clone(), max_in_flight.clone());
        Box::pin(async move {
            let n = calls.fetch_add(1, Ordering::SeqCst);
            let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            max_in_flight.fetch_max(now, Ordering::SeqCst);
            tokio::time::sleep(delay).await;
            in_flight.fetch_sub(1, Ordering::SeqCst);
            if n < fail_first {
                Err(format!("simulated failure #{}", n + 1))
            } else {
                Ok("ok".to_string())
            }
        })
    });
    (runner, probe)
}

async fn wait_until<F: Fn() -> bool>(timeout: Duration, f: F) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if f() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    f()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_realtime_batch_creates_snapshot_in_local_destination() {
    let src = TempDir::new().unwrap();
    let dst = TempDir::new().unwrap();
    fs::write(src.path().join("seed.txt"), b"seed").unwrap();

    let sync = Arc::new(RealtimeSync::for_profile(
        fast_strategy(),
        test_config(src.path(), dst.path()),
        Some("realtime-test-key".to_string()),
    ));
    sync.start(src.path()).await.expect("watch source");
    let handle = sync.clone().spawn_processing_loop();
    // Let the watcher settle before producing the burst.
    tokio::time::sleep(Duration::from_millis(300)).await;

    for i in 0..5 {
        fs::write(
            src.path().join(format!("file{}.txt", i)),
            format!("data {}", i),
        )
        .unwrap();
    }

    let dst_path = dst.path().to_path_buf();
    let mut ok = false;
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(60) {
        let stats = sync.get_stats().await;
        if snapshot_count(&dst_path) >= 1 && stats.synced > 0 && stats.pending_changes == 0 {
            ok = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let stats = sync.get_stats().await;
    sync.stop().await;
    handle.await.unwrap();

    assert!(
        ok,
        "expected a snapshot and no pending changes, got {} snapshot(s), stats {:?}",
        snapshot_count(&dst_path),
        stats
    );
    assert!(stats.backups_completed >= 1);
    assert_eq!(
        stats.backups_failed, 0,
        "last error: {:?}",
        stats.last_error
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_failed_profile_backup_keeps_changes_pending_then_succeeds() {
    let root = TempDir::new().unwrap();
    let src = root.path().join("src");
    let dst = root.path().join("dst");

    let sync = RealtimeSync::for_profile(
        fast_strategy(),
        test_config(&src, &dst),
        Some("realtime-test-key".to_string()),
    );
    sync.queue.add_change(change(src.join("a.txt"))).await;

    // Source doesn't exist yet: the backup must fail and nothing is synced.
    assert!(sync.sync_now().await.is_err());
    let stats = sync.get_stats().await;
    assert_eq!(stats.pending_changes, 1);
    assert_eq!(stats.synced, 0);
    assert_eq!(stats.backups_failed, 1);
    assert!(stats.last_error.is_some());
    assert_eq!(snapshot_count(&dst), 0);

    // Retry after the problem is fixed: now the change is confirmed.
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("a.txt"), b"hello").unwrap();
    assert_eq!(sync.sync_now().await.unwrap(), 1);
    let stats = sync.get_stats().await;
    assert_eq!(stats.pending_changes, 0);
    assert_eq!(stats.synced, 1);
    assert_eq!(stats.backups_completed, 1);
    assert!(stats.last_error.is_none());
    assert_eq!(snapshot_count(&dst), 1);
}

#[tokio::test]
async fn test_without_backup_target_nothing_is_reported_synced() {
    let sync = RealtimeSync::new(SyncStrategy::default());
    sync.queue.add_change(change("/x/a.txt")).await;
    assert!(sync.sync_now().await.is_err());
    let stats = sync.get_stats().await;
    assert_eq!(stats.pending_changes, 1);
    assert_eq!(stats.synced, 0);
    assert_eq!(stats.failed, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_no_concurrent_backups() {
    let (runner, probe) = probe_runner(0, Duration::from_millis(100));
    let sync = Arc::new(RealtimeSync::with_backup_runner(fast_strategy(), runner));
    let handle = sync.clone().spawn_processing_loop();

    let mut tasks = Vec::new();
    for i in 0..6 {
        let s = sync.clone();
        tasks.push(tokio::spawn(async move {
            s.queue.add_change(change(format!("/x/{}.txt", i))).await;
            s.sync_now().await
        }));
    }
    for t in tasks {
        t.await.unwrap().unwrap();
    }
    assert!(
        wait_until(Duration::from_secs(10), || !sync.is_backup_running()).await,
        "backup never finished"
    );
    sync.stop_processing().await;
    handle.await.unwrap();

    assert!(probe.calls.load(Ordering::SeqCst) >= 1);
    assert_eq!(probe.max_in_flight.load(Ordering::SeqCst), 1);
    let stats = sync.get_stats().await;
    assert_eq!(stats.pending_changes, 0);
    assert_eq!(stats.synced, 6);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_changes_during_backup_trigger_one_more_backup() {
    let (runner, probe) = probe_runner(0, Duration::from_millis(400));
    let sync = Arc::new(RealtimeSync::with_backup_runner(fast_strategy(), runner));
    sync.queue.add_change(change("/x/a.txt")).await;
    let handle = sync.clone().spawn_processing_loop();

    let s = sync.clone();
    assert!(wait_until(Duration::from_secs(5), move || s.is_backup_running()).await);
    // Arrives while the first backup runs: must not be marked synced by it.
    sync.queue.add_change(change("/x/b.txt")).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(sync.get_stats().await.pending_changes >= 1);

    let c = probe.calls.clone();
    assert!(
        wait_until(Duration::from_secs(10), move || c.load(Ordering::SeqCst)
            >= 2)
        .await
    );
    let s = sync.clone();
    assert!(wait_until(Duration::from_secs(5), move || !s.is_backup_running()).await);
    tokio::time::sleep(Duration::from_millis(200)).await;
    sync.stop_processing().await;
    handle.await.unwrap();

    let stats = sync.get_stats().await;
    assert_eq!(probe.calls.load(Ordering::SeqCst), 2);
    assert_eq!(probe.max_in_flight.load(Ordering::SeqCst), 1);
    assert_eq!(stats.pending_changes, 0);
    assert_eq!(stats.synced, 2);
    assert_eq!(stats.backups_completed, 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_loop_retries_failed_backup_with_backoff() {
    let (runner, probe) = probe_runner(2, Duration::from_millis(10));
    let sync = Arc::new(
        RealtimeSync::with_backup_runner(fast_strategy(), runner)
            .with_retry_backoff(Duration::from_millis(50), Duration::from_millis(200)),
    );
    sync.queue.add_change(change("/x/a.txt")).await;
    let handle = sync.clone().spawn_processing_loop();

    let c = probe.calls.clone();
    assert!(
        wait_until(Duration::from_secs(10), move || c.load(Ordering::SeqCst)
            >= 3)
        .await
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
    sync.stop_processing().await;
    handle.await.unwrap();

    let stats = sync.get_stats().await;
    assert_eq!(stats.backups_failed, 2);
    assert_eq!(stats.backups_completed, 1);
    assert_eq!(stats.synced, 1);
    assert_eq!(stats.pending_changes, 0);
    assert!(stats.last_error.is_none());
    let detailed = sync.get_detailed_stats().await;
    assert!((detailed.sync_ratio - 1.0 / 3.0).abs() < 1e-9);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_stop_lets_running_backup_finish() {
    let (runner, probe) = probe_runner(0, Duration::from_millis(400));
    let sync = Arc::new(RealtimeSync::with_backup_runner(fast_strategy(), runner));
    sync.queue.add_change(change("/x/a.txt")).await;
    let handle = sync.clone().spawn_processing_loop();

    let s = sync.clone();
    assert!(wait_until(Duration::from_secs(5), move || s.is_backup_running()).await);
    sync.stop().await;
    tokio::time::timeout(Duration::from_secs(5), handle)
        .await
        .expect("loop did not exit")
        .unwrap();

    assert!(!sync.is_backup_running());
    assert_eq!(probe.calls.load(Ordering::SeqCst), 1);
    let stats = sync.get_stats().await;
    assert_eq!(stats.backups_completed, 1);
    assert_eq!(stats.pending_changes, 0);
}

#[tokio::test]
async fn test_excluded_root_changes_are_ignored() {
    let (runner, probe) = probe_runner(0, Duration::from_millis(1));
    let sync = RealtimeSync::with_backup_runner(fast_strategy(), runner).exclude_root("/repo/dst");
    sync.queue
        .add_change(change("/repo/dst/snapshots/x.toml"))
        .await;
    assert_eq!(sync.sync_now().await.unwrap(), 0);
    assert_eq!(probe.calls.load(Ordering::SeqCst), 0);
    assert_eq!(sync.get_stats().await.pending_changes, 0);
}
