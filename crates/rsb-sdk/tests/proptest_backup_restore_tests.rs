//! Property test: for random file trees, backup → restore on a
//! `MemoryStorage` gives back exactly the same paths and bytes, clear and
//! encrypted.
//!
//! Trees have unicode names, nested directories, sizes from 0 bytes to a
//! few MiB (including sizes at the 1 MiB read/chunk boundaries) and
//! duplicate contents (deduplication). 16 cases per mode by default; set
//! `PROPTEST_CASES` to run more. Encrypted repositories use the minimum
//! Argon2id parameters so a case takes well under a second.

use proptest::prelude::*;
use rsb_sdk::backup::perform_backup;
use rsb_sdk::config::Config;
use rsb_sdk::core::dedup_index::DedupIndexOptions;
use rsb_sdk::core::restore::restore_from_storage;
use rsb_sdk::crypto::keyfile::{self, KdfParams};
use rsb_sdk::storage::{MemoryStorage, Storage};
use rsb_sdk::{BackupOptions, RestoreOptions};
use std::collections::{BTreeMap, HashSet};
use std::path::Path;
use std::sync::Arc;

const MIB: usize = 1024 * 1024;
const PASSWORD: &str = "proptest password";

fn config() -> ProptestConfig {
    let cases = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(16);
    ProptestConfig::with_cases(cases)
}

/// Name stems: ASCII, accents, CJK, emoji, spaces, dots, dashes. Every
/// generated name gets a unique numeric suffix, so names never collide,
/// even on case- or normalization-insensitive file systems.
const STEMS: &[&str] = &[
    "a",
    "readme.txt",
    "Ünïcødé",
    "日本語",
    "emoji😀",
    "with space",
    "dash-name",
    "x.tar.gz",
    "ñandú",
    "Ελληνικά",
];

#[derive(Debug, Clone)]
enum Content {
    /// Pseudo-random bytes (incompressible).
    Random { len: usize, seed: u64 },
    /// One repeated byte (highly compressible).
    Fill { len: usize, byte: u8 },
    /// Same bytes as an earlier file (deduplication).
    CopyOf(usize),
}

#[derive(Debug, Clone)]
struct Entry {
    /// Directory stem indices (nesting depth 0..=3).
    dirs: Vec<(usize, usize)>,
    stem: usize,
    content: Content,
}

fn size() -> impl Strategy<Value = usize> {
    prop_oneof![
        6 => 0usize..=2048,
        1 => Just(0usize),
        2 => prop::sample::select(vec![
            MIB - 1,
            MIB,
            MIB + 1,
            2 * MIB - 1,
            2 * MIB,
            2 * MIB + 1,
            3 * MIB + 7,
        ]),
    ]
}

fn content() -> impl Strategy<Value = Content> {
    prop_oneof![
        4 => (size(), any::<u64>()).prop_map(|(len, seed)| Content::Random { len, seed }),
        2 => (size(), any::<u8>()).prop_map(|(len, byte)| Content::Fill { len, byte }),
        2 => any::<usize>().prop_map(Content::CopyOf),
    ]
}

fn entry() -> impl Strategy<Value = Entry> {
    (
        // Few distinct directories per level so that files share them.
        prop::collection::vec((0..STEMS.len(), 0usize..2), 0..=3),
        0..STEMS.len(),
        content(),
    )
        .prop_map(|(dirs, stem, content)| Entry {
            dirs,
            stem,
            content,
        })
}

fn bytes(len: usize, seed: u64) -> Vec<u8> {
    let mut s = seed | 1;
    let mut out = Vec::with_capacity(len + 8);
    while out.len() < len {
        s ^= s >> 12;
        s ^= s << 25;
        s ^= s >> 27;
        out.extend_from_slice(&s.wrapping_mul(0x2545_F491_4F6C_DD1D).to_le_bytes());
    }
    out.truncate(len);
    out
}

/// Materializes the tree under `root`; returns `relative path ('/') → bytes`.
fn write_tree(root: &Path, entries: &[Entry]) -> BTreeMap<String, Vec<u8>> {
    let mut files: Vec<(String, Vec<u8>)> = Vec::new();
    for (i, e) in entries.iter().enumerate() {
        let data = match &e.content {
            Content::Random { len, seed } => bytes(*len, *seed),
            Content::Fill { len, byte } => vec![*byte; *len],
            Content::CopyOf(j) if i > 0 => files[j % i].1.clone(),
            Content::CopyOf(_) => b"first".to_vec(),
        };
        // Directories are prefixed "d", files "f": a name is never both.
        let mut parts: Vec<String> = e
            .dirs
            .iter()
            .map(|(stem, n)| format!("d{n} {}", STEMS[*stem]))
            .collect();
        parts.push(format!("f{i} {}", STEMS[e.stem]));
        let rel = parts.join("/");
        let path = parts.iter().fold(root.to_path_buf(), |p, s| p.join(s));
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &data).unwrap();
        files.push((rel, data));
    }
    files.into_iter().collect()
}

/// Reads every file under `root`: `relative path ('/') → bytes`.
fn read_tree(root: &Path) -> BTreeMap<String, Vec<u8>> {
    walkdir::WalkDir::new(root)
        .into_iter()
        .map(|e| e.unwrap())
        .filter(|e| e.file_type().is_file())
        .map(|e| {
            let rel = e.path().strip_prefix(root).unwrap();
            let key = rel
                .components()
                .map(|c| c.as_os_str().to_str().unwrap().to_string())
                .collect::<Vec<_>>()
                .join("/");
            (key, std::fs::read(e.path()).unwrap())
        })
        .collect()
}

async fn round_trip(entries: Vec<Entry>, key: Option<&str>) -> Result<(), TestCaseError> {
    let src = tempfile::tempdir().unwrap();
    let out = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    let expected = write_tree(src.path(), &entries);

    let mem = Arc::new(MemoryStorage::new());
    let storage: Arc<dyn Storage> = mem.clone();
    if let Some(pw) = key {
        keyfile::init_repo_key(storage.clone(), pw.as_bytes(), KdfParams::MIN_CREATE)
            .await
            .unwrap();
    }
    let config = Config {
        source_path: src.path().to_string_lossy().into_owned(),
        destination_path: src.path().join("unused").to_string_lossy().into_owned(),
        exclude_patterns: vec![],
        encryption_key: key.map(str::to_string),
        compression_level: Some(1),
        ..Default::default()
    };
    let report = perform_backup(
        &config,
        BackupOptions {
            storage: Some(storage.clone()),
            max_threads: Some(2),
            dedup_index: DedupIndexOptions {
                dir: Some(cache.path().to_path_buf()),
                ..DedupIndexOptions::default()
            },
            ..Default::default()
        }
        .with_encryption_key(key),
    )
    .await
    .unwrap();
    prop_assert_eq!(report.files_with_errors, 0, "{:?}", report.errors);
    // Duplicates of content seen in this run count as skipped.
    prop_assert_eq!(
        report.files_processed + report.files_skipped,
        expected.len()
    );

    // Deduplication: one data object per distinct content.
    let distinct: HashSet<&Vec<u8>> = expected.values().collect();
    let (kind, other) = if key.is_some() {
        ("data/enc/", "data/clear/")
    } else {
        ("data/clear/", "data/enc/")
    };
    let objects = mem.keys().iter().filter(|k| k.starts_with(kind)).count();
    prop_assert_eq!(objects, distinct.len());
    let leaked = mem.keys().iter().any(|k| k.starts_with(other));
    prop_assert!(!leaked, "objects stored under {}", other);

    let report = restore_from_storage(
        &*storage,
        RestoreOptions::new(out.path()).with_encryption_key(key),
    )
    .await
    .unwrap();
    prop_assert_eq!(report.files_with_errors, 0, "{:?}", report.errors);

    let restored = read_tree(out.path());
    prop_assert_eq!(
        restored.keys().collect::<Vec<_>>(),
        expected.keys().collect::<Vec<_>>()
    );
    for (path, data) in &expected {
        // Compare lengths first: a failing multi-MiB diff is unreadable.
        prop_assert_eq!(restored[path].len(), data.len(), "{}", path);
        prop_assert!(&restored[path] == data, "content differs: {}", path);
    }
    Ok(())
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn clear_backup_restore_round_trip(entries in prop::collection::vec(entry(), 1..10)) {
        runtime().block_on(round_trip(entries, None))?;
    }

    #[test]
    fn encrypted_backup_restore_round_trip(entries in prop::collection::vec(entry(), 1..10)) {
        runtime().block_on(round_trip(entries, Some(PASSWORD)))?;
    }
}
