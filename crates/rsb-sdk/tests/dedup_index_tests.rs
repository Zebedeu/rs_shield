//! Local dedup index: fewer storage calls on incremental backups, and
//! never an object skipped that the repository does not have.

use rsb_sdk::backup::perform_backup;
use rsb_sdk::config::Config;
use rsb_sdk::core::dedup_index::{
    DedupIndexOptions, REPO_EPOCH_PATH, REPO_ID_PATH, bump_repo_epoch,
};
use rsb_sdk::core::restore::restore_from_storage;
use rsb_sdk::integrity::perform_verify;
use rsb_sdk::storage::{InstrumentedStorage, MemoryStorage, Storage};
use rsb_sdk::{BackupOptions, RestoreOptions, VerifyOptions};

use std::sync::Arc;
use std::time::Duration;

const FILES: usize = 40;

struct Repo {
    src: tempfile::TempDir,
    cache: tempfile::TempDir,
    mem: Arc<MemoryStorage>,
    storage: Arc<InstrumentedStorage>,
}

impl Repo {
    fn new() -> Self {
        let src = tempfile::tempdir().unwrap();
        for i in 0..FILES {
            std::fs::write(
                src.path().join(format!("f{:02}.txt", i)),
                format!("content {} ", i).repeat(i + 1),
            )
            .unwrap();
        }
        let mem = Arc::new(MemoryStorage::new());
        let storage = Arc::new(InstrumentedStorage::new(mem.clone()));
        Self {
            src,
            cache: tempfile::tempdir().unwrap(),
            mem,
            storage,
        }
    }

    fn config(&self) -> Config {
        Config {
            source_path: self.src.path().to_string_lossy().into_owned(),
            destination_path: self
                .src
                .path()
                .join("unused")
                .to_string_lossy()
                .into_owned(),
            exclude_patterns: vec![],
            compression_level: Some(3),
            ..Default::default()
        }
    }

    fn index(&self, sample_one_in: u32) -> DedupIndexOptions {
        DedupIndexOptions {
            dir: Some(self.cache.path().to_path_buf()),
            sample_one_in,
            ..DedupIndexOptions::default()
        }
    }

    /// Runs a backup and returns the number of HEAD requests it made.
    async fn backup_with(&self, key: Option<&str>, index: DedupIndexOptions) -> u64 {
        self.storage.reset();
        let report = perform_backup(
            &self.config(),
            BackupOptions {
                storage: Some(self.storage.clone() as Arc<dyn Storage>),
                max_threads: Some(4),
                dedup_index: index,
                ..Default::default()
            }
            .with_encryption_key(key),
        )
        .await
        .unwrap();
        assert_eq!(report.files_with_errors, 0, "{:?}", report.errors);
        self.storage.counts().head
    }

    async fn backup(&self, key: Option<&str>) -> u64 {
        self.backup_with(key, self.index(0)).await
    }

    fn data_objects(&self) -> Vec<String> {
        self.mem
            .keys()
            .into_iter()
            .filter(|k| k.starts_with("data/"))
            .collect()
    }

    async fn restore_ok(&self, key: Option<&str>) {
        let out = tempfile::tempdir().unwrap();
        let report = restore_from_storage(
            &*self.storage,
            RestoreOptions::new(out.path()).with_encryption_key(key),
        )
        .await
        .unwrap();
        assert_eq!(report.files_with_errors, 0, "{:?}", report.errors);
        assert_eq!(report.files_processed, FILES);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unchanged_backup_skips_heads_for_known_objects() {
    for key in [None, Some("pw")] {
        let repo = Repo::new();
        let first = repo.backup(key).await;
        assert!(
            first >= FILES as u64,
            "first backup HEADs every object: {}",
            first
        );
        let second = repo.backup(key).await;
        // Only non-object lookups remain (lock / manifest checks).
        assert!(second < 5, "second backup made {} HEADs", second);

        // Without the index, every object is HEADed again.
        let without = repo.backup_with(key, DedupIndexOptions::disabled()).await;
        assert!(without >= FILES as u64, "{}", without);
        repo.restore_ok(key).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repository_id_is_created_once_and_not_by_dry_runs() {
    let repo = Repo::new();
    let dry = perform_backup(
        &repo.config(),
        BackupOptions {
            storage: Some(repo.storage.clone() as Arc<dyn Storage>),
            dry_run: true,
            dedup_index: repo.index(0),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(dry.files_with_errors, 0);
    assert!(repo.mem.read(REPO_ID_PATH).await.is_err());
    repo.backup(None).await;
    let id = repo.mem.read(REPO_ID_PATH).await.unwrap();
    repo.backup(None).await;
    assert_eq!(repo.mem.read(REPO_ID_PATH).await.unwrap(), id);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deleted_object_found_by_sampling_is_uploaded_again() {
    let repo = Repo::new();
    repo.backup(None).await;
    // Someone deletes an object behind the index's back.
    let victim = repo.data_objects()[0].clone();
    repo.mem.delete(&victim).await.unwrap();
    // Every hit is checked (sample 1 in 1): the HEAD finds it missing.
    repo.backup_with(None, repo.index(1)).await;
    assert!(repo.mem.read(&victim).await.is_ok(), "object re-uploaded");
    repo.restore_ok(None).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stale_entries_are_checked_again() {
    let repo = Repo::new();
    repo.backup(None).await;
    let victim = repo.data_objects()[3].clone();
    repo.mem.delete(&victim).await.unwrap();
    // max_age 0: no entry is fresh enough to be trusted.
    let heads = repo
        .backup_with(
            None,
            DedupIndexOptions {
                max_age: Duration::ZERO,
                ..repo.index(0)
            },
        )
        .await;
    assert!(heads >= FILES as u64);
    assert!(repo.mem.read(&victim).await.is_ok(), "object re-uploaded");
    repo.restore_ok(None).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn epoch_change_invalidates_the_index() {
    let repo = Repo::new();
    repo.backup(None).await;
    // A destructive operation (prune, repair, migrate, rotate) bumps the
    // epoch before deleting anything.
    bump_repo_epoch(&*repo.mem).await.unwrap();
    let victim = repo.data_objects()[5].clone();
    repo.mem.delete(&victim).await.unwrap();
    let heads = repo.backup(None).await;
    assert!(heads >= FILES as u64, "index discarded: {}", heads);
    assert!(repo.mem.read(&victim).await.is_ok());
    assert!(repo.mem.read(REPO_EPOCH_PATH).await.is_ok());
    // ...and is rebuilt for the next backup.
    assert!(repo.backup(None).await < 5);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn removed_snapshot_invalidates_the_index() {
    let repo = Repo::new();
    repo.backup(None).await;
    repo.backup(None).await;
    // An older client prunes (no epoch change): a snapshot disappears.
    let snaps: Vec<String> = repo
        .mem
        .keys()
        .into_iter()
        .filter(|k| k.starts_with("snapshots/"))
        .collect();
    repo.mem.delete(&snaps[0]).await.unwrap();
    let heads = repo.backup(None).await;
    assert!(heads >= FILES as u64, "index discarded: {}", heads);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn corrupt_or_foreign_index_files_fall_back_to_storage() {
    let repo = Repo::new();
    repo.backup(None).await;
    let files: Vec<_> = std::fs::read_dir(repo.cache.path())
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(files.len(), 1, "{:?}", files);
    let mut raw = std::fs::read(&files[0]).unwrap();
    let mid = raw.len() / 2;
    raw[mid] ^= 0xFF;
    std::fs::write(&files[0], &raw).unwrap();
    let heads = repo.backup(None).await;
    assert!(heads >= FILES as u64, "corrupt index ignored: {}", heads);
    repo.restore_ok(None).await;

    // The same repository id in another location (a copied repository)
    // never uses this one's index.
    let copy = Repo::new();
    for k in repo.mem.keys() {
        if k.starts_with("meta/") || k.starts_with("snapshots/") || k.starts_with("data/") {
            let v = repo.mem.read(&k).await.unwrap();
            copy.mem.write(&k, &v).await.unwrap();
        }
    }
    let copy_with_cache = Repo {
        src: copy.src,
        cache: repo.cache,
        mem: copy.mem,
        storage: copy.storage,
    };
    let heads = copy_with_cache.backup(None).await;
    assert!(heads >= FILES as u64, "copy uses its own index: {}", heads);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repair_bumps_the_epoch_before_deleting() {
    let repo = Repo::new();
    repo.backup(None).await;
    // Corrupt one object so that verify --repair deletes it.
    let victim = repo.data_objects()[2].clone();
    repo.mem.write(&victim, b"garbage").await.unwrap();
    let before = repo.mem.read(REPO_EPOCH_PATH).await.ok();
    let report = perform_verify(
        &repo.config(),
        VerifyOptions {
            repair: true,
            quiet: true,
            storage: Some(repo.storage.clone() as Arc<dyn Storage>),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert!(
        report
            .errors
            .iter()
            .any(|e| e.contains("Deleted corrupt object"))
    );
    assert_ne!(repo.mem.read(REPO_EPOCH_PATH).await.ok(), before);
    // The next backup does not trust the index and re-uploads the object.
    repo.backup(None).await;
    assert!(repo.mem.read(&victim).await.unwrap() != b"garbage");
    repo.restore_ok(None).await;
}
