//! Streaming single-file restore: multi-MB round-trips (clear + encrypted)
//! and corrupt blobs never touching an existing target.

use rsb_sdk::RestoreOptions;
use rsb_sdk::core::restore::restore_from_storage;
use rsb_sdk::core::types::FileMetadata;
use rsb_sdk::crypto::{EncryptionKey, hash_file_content};
use rsb_sdk::report::ReportData;
use rsb_sdk::storage::{LocalStorage, Storage};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

const PASSWORD: &str = "correct horse battery staple";

/// Deterministic, partially compressible content.
fn content(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
    (0..len)
        .map(|i| {
            if (i / 4096) % 3 == 0 {
                (i % 7) as u8
            } else {
                x = x
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                (x >> 33) as u8
            }
        })
        .collect()
}

struct Entry<'a> {
    name: &'a str,
    data: &'a [u8],
    compressed: bool,
}

/// Builds a repo with single-blob (non-multipart) entries.
async fn repo(
    entries: &[Entry<'_>],
    key: Option<&EncryptionKey>,
) -> (tempfile::TempDir, LocalStorage, HashMap<String, String>) {
    let dir = tempfile::tempdir().unwrap();
    let storage = LocalStorage::new(dir.path().to_str().unwrap());
    let kind = if key.is_some() { "enc" } else { "clear" };
    let mut manifest = HashMap::new();
    let mut blob_paths = HashMap::new();
    for e in entries {
        let hash = hash_file_content(e.data).unwrap();
        let mut stored = if e.compressed {
            zstd::encode_all(e.data, 3).unwrap()
        } else {
            e.data.to_vec()
        };
        if let Some(k) = key {
            stored = k.encrypt(&stored).unwrap();
        }
        let path = format!("data/{}/{}", kind, hash);
        storage.write(&path, &stored).await.unwrap();
        blob_paths.insert(e.name.to_string(), path);
        manifest.insert(
            PathBuf::from(e.name),
            FileMetadata::new(hash, key.is_some(), e.compressed),
        );
    }
    let mut toml_bytes = toml::to_string(&manifest).unwrap().into_bytes();
    if let Some(k) = key {
        toml_bytes = k.encrypt(&toml_bytes).unwrap();
    }
    storage
        .write("snapshots/2026-01-01T000000Z.toml", &toml_bytes)
        .await
        .unwrap();
    (dir, storage, blob_paths)
}

async fn run(storage: &LocalStorage, target: &Path, key: Option<&str>, force: bool) -> ReportData {
    restore_from_storage(
        storage,
        RestoreOptions {
            force,
            ..RestoreOptions::new(target)
        }
        .with_encryption_key(key),
    )
    .await
    .unwrap()
}

fn assert_no_temp_files(dir: &Path) {
    let leftovers: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .filter(|n| n.starts_with('.'))
        .collect();
    assert!(leftovers.is_empty(), "temp files left: {:?}", leftovers);
}

#[tokio::test]
async fn multi_mb_unencrypted_restore_round_trips() {
    let a = content(6 * 1024 * 1024 + 123, 1);
    let b = content(3 * 1024 * 1024 + 7, 2);
    // Highly compressible: one input read expands to many output buffers.
    let zeros = vec![0u8; 24 * 1024 * 1024];
    let (_repo, storage, _) = repo(
        &[
            Entry {
                name: "a.bin",
                data: &a,
                compressed: true,
            },
            Entry {
                name: "dir/b.bin",
                data: &b,
                compressed: false,
            },
            Entry {
                name: "zeros.bin",
                data: &zeros,
                compressed: true,
            },
            Entry {
                name: "empty.bin",
                data: b"",
                compressed: true,
            },
        ],
        None,
    )
    .await;
    let out = tempfile::tempdir().unwrap();
    let report = run(&storage, out.path(), None, false).await;
    assert_eq!(report.files_with_errors, 0, "{:?}", report.errors);
    assert_eq!(report.files_processed, 4);
    assert_eq!(std::fs::read(out.path().join("a.bin")).unwrap(), a);
    assert_eq!(std::fs::read(out.path().join("dir/b.bin")).unwrap(), b);
    assert_eq!(std::fs::read(out.path().join("zeros.bin")).unwrap(), zeros);
    assert!(
        std::fs::read(out.path().join("empty.bin"))
            .unwrap()
            .is_empty()
    );
    assert_no_temp_files(out.path());
}

#[tokio::test]
async fn multi_mb_encrypted_restore_round_trips() {
    let key = EncryptionKey::new(PASSWORD.as_bytes()).unwrap();
    let a = content(5 * 1024 * 1024 + 99, 3);
    let b = content(2 * 1024 * 1024, 4);
    let (_repo, storage, _) = repo(
        &[
            Entry {
                name: "a.bin",
                data: &a,
                compressed: true,
            },
            Entry {
                name: "b.bin",
                data: &b,
                compressed: false,
            },
        ],
        Some(&key),
    )
    .await;
    let out = tempfile::tempdir().unwrap();
    let report = run(&storage, out.path(), Some(PASSWORD), false).await;
    assert_eq!(report.files_with_errors, 0, "{:?}", report.errors);
    assert_eq!(std::fs::read(out.path().join("a.bin")).unwrap(), a);
    assert_eq!(std::fs::read(out.path().join("b.bin")).unwrap(), b);
    assert_no_temp_files(out.path());

    // --force semantics unchanged: existing file refused without it.
    let report = run(&storage, out.path(), Some(PASSWORD), false).await;
    assert_eq!(report.files_with_errors, 2);
}

#[tokio::test]
async fn corrupt_unencrypted_blob_leaves_target_untouched() {
    let a = content(4 * 1024 * 1024, 5);
    let (repo_dir, storage, blobs) = repo(
        &[Entry {
            name: "a.bin",
            data: &a,
            compressed: true,
        }],
        None,
    )
    .await;
    let blob = repo_dir.path().join(&blobs["a.bin"]);

    let out = tempfile::tempdir().unwrap();
    let target = out.path().join("a.bin");

    // 1) Flipped byte in the middle of the zstd stream.
    let mut bytes = std::fs::read(&blob).unwrap();
    let original = bytes.clone();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0xFF;
    std::fs::write(&blob, &bytes).unwrap();
    std::fs::write(&target, b"precious").unwrap();
    let report = run(&storage, out.path(), None, true).await;
    assert_eq!(report.files_with_errors, 1);
    assert_eq!(std::fs::read(&target).unwrap(), b"precious");
    assert_no_temp_files(out.path());

    // 2) Truncated stream.
    std::fs::write(&blob, &original[..original.len() / 2]).unwrap();
    let report = run(&storage, out.path(), None, true).await;
    assert_eq!(report.files_with_errors, 1);
    assert_eq!(std::fs::read(&target).unwrap(), b"precious");
    assert_no_temp_files(out.path());

    // 3) Valid zstd, wrong content (full-file hash mismatch).
    std::fs::write(&blob, zstd::encode_all(&b"other content"[..], 3).unwrap()).unwrap();
    let report = run(&storage, out.path(), None, true).await;
    assert_eq!(report.files_with_errors, 1);
    assert_eq!(std::fs::read(&target).unwrap(), b"precious");
    assert_no_temp_files(out.path());

    // Restoring the original blob then succeeds over the target with --force.
    std::fs::write(&blob, &original).unwrap();
    let report = run(&storage, out.path(), None, true).await;
    assert_eq!(report.files_with_errors, 0, "{:?}", report.errors);
    assert_eq!(std::fs::read(&target).unwrap(), a);
}

#[tokio::test]
async fn corrupt_encrypted_blob_leaves_target_untouched() {
    let key = EncryptionKey::new(PASSWORD.as_bytes()).unwrap();
    let a = content(3 * 1024 * 1024, 6);
    let (repo_dir, storage, blobs) = repo(
        &[Entry {
            name: "a.bin",
            data: &a,
            compressed: true,
        }],
        Some(&key),
    )
    .await;
    let blob = repo_dir.path().join(&blobs["a.bin"]);
    let mut bytes = std::fs::read(&blob).unwrap();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0x01;
    std::fs::write(&blob, &bytes).unwrap();

    let out = tempfile::tempdir().unwrap();
    let target = out.path().join("a.bin");
    std::fs::write(&target, b"precious").unwrap();
    let report = run(&storage, out.path(), Some(PASSWORD), true).await;
    assert_eq!(report.files_with_errors, 1);
    assert_eq!(std::fs::read(&target).unwrap(), b"precious");
    assert_no_temp_files(out.path());
}
