//! Shared fixtures and runners for the backup/restore benchmarks
//! (`backup_restore` for criterion, `perf_probe` for one-shot measurements
//! of wall time, peak RSS and storage calls).
//!
//! Fixtures are generated at runtime, deterministically (fixed seeds), so
//! every run measures the same bytes.
#![allow(dead_code)]

use rsb_sdk::backup::perform_backup;
use rsb_sdk::config::Config;
use rsb_sdk::core::dedup_index::DedupIndexOptions;
use rsb_sdk::core::restore::restore_from_storage;
use rsb_sdk::report::ReportData;
use rsb_sdk::storage::Storage;
use rsb_sdk::{BackupOptions, RestoreOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub const PASSWORD: &str = "bench password";
const MIB: u64 = 1024 * 1024;

/// Benchmark size profile. `quick` is the CI pull-request subset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    Quick,
    Full,
}

impl Profile {
    /// `RSB_BENCH_PROFILE=quick|full` (default `full`).
    pub fn from_env() -> Self {
        match std::env::var("RSB_BENCH_PROFILE").as_deref() {
            Ok("quick") => Profile::Quick,
            _ => Profile::Full,
        }
    }
}

/// What a fixture contains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixtureSpec {
    pub name: &'static str,
    pub files: usize,
    pub file_size: u64,
}

impl FixtureSpec {
    pub fn total_bytes(&self) -> u64 {
        self.files as u64 * self.file_size
    }
}

/// (a) many small files.
pub fn small_files(p: Profile) -> FixtureSpec {
    FixtureSpec {
        name: "small",
        files: env_usize("RSB_BENCH_SMALL_FILES").unwrap_or(match p {
            Profile::Quick => 500,
            Profile::Full => 20_000,
        }),
        file_size: 4 * 1024,
    }
}

/// Small files for the latency-injected storage (each file costs at least
/// one round trip per operation, so the count is smaller).
pub fn small_files_latency(p: Profile) -> FixtureSpec {
    FixtureSpec {
        name: "small-lat",
        files: env_usize("RSB_BENCH_SMALL_LAT_FILES").unwrap_or(match p {
            Profile::Quick => 200,
            Profile::Full => 2_000,
        }),
        file_size: 4 * 1024,
    }
}

/// (b) a few large files (alternating compressible / incompressible).
pub fn large_files(p: Profile) -> FixtureSpec {
    let mib = env_usize("RSB_BENCH_LARGE_MIB")
        .map(|m| m as u64)
        .unwrap_or(match p {
            Profile::Quick => 80,
            Profile::Full => 256,
        });
    FixtureSpec {
        name: "large",
        files: env_usize("RSB_BENCH_LARGE_FILES").unwrap_or(match p {
            Profile::Quick => 2,
            Profile::Full => 4,
        }),
        file_size: mib * MIB,
    }
}

fn env_usize(name: &str) -> Option<usize> {
    std::env::var(name).ok()?.parse().ok()
}

/// xorshift64*: fast deterministic bytes.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn fill(&mut self, buf: &mut [u8]) {
        for c in buf.chunks_mut(8) {
            let v = self.next().to_le_bytes();
            c.copy_from_slice(&v[..c.len()]);
        }
    }
}

const WORDS: &[&str] = &[
    "backup",
    "restore",
    "chunk",
    "storage",
    "manifest",
    "snapshot",
    "encrypt",
    "hash",
    "object",
    "repository",
    "verify",
    "prune",
    "the",
    "of",
    "and",
    "a",
    "to",
    "in",
    "is",
];

/// Text-like content (zstd level 3 ratio ~3-4x), unique per seed.
fn fill_compressible(rng: &mut Rng, buf: &mut [u8]) {
    let mut i = 0;
    while i < buf.len() {
        let r = rng.next();
        let w = WORDS[(r % WORDS.len() as u64) as usize].as_bytes();
        let sep: &[u8] = if r & 0x700 == 0 { b"\n" } else { b" " };
        for &b in w.iter().chain(sep) {
            if i == buf.len() {
                break;
            }
            buf[i] = b;
            i += 1;
        }
        // A number every few words keeps the content unique.
        if r & 0xF000 == 0 && i + 8 <= buf.len() {
            buf[i..i + 8].copy_from_slice(format!("{:08x}", r >> 32).as_bytes());
            i += 8;
        }
    }
}

/// Writes one file of `size` bytes: compressible when `compressible`,
/// random otherwise. Streams 1 MiB at a time.
pub fn write_file(path: &Path, size: u64, seed: u64, compressible: bool) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    let mut f = std::io::BufWriter::new(std::fs::File::create(path).unwrap());
    let mut rng = Rng::new(seed);
    let mut buf = vec![0u8; (MIB as usize).min(size as usize)];
    let mut left = size;
    while left > 0 {
        let n = left.min(buf.len() as u64) as usize;
        if compressible {
            fill_compressible(&mut rng, &mut buf[..n]);
        } else {
            rng.fill(&mut buf[..n]);
        }
        f.write_all(&buf[..n]).unwrap();
        left -= n as u64;
    }
    f.flush().unwrap();
}

/// Relative path of file `i` of a fixture (200 files per directory).
pub fn rel_path(i: usize) -> PathBuf {
    PathBuf::from(format!("d{:03}/f{:05}.dat", i / 200, i))
}

/// Generates `spec` under `dir` (half compressible, half random).
pub fn generate(spec: &FixtureSpec, dir: &Path) {
    for i in 0..spec.files {
        write_file(
            &dir.join(rel_path(i)),
            spec.file_size,
            i as u64 + 1,
            i.is_multiple_of(2),
        );
    }
}

/// Rewrites 1% of the files (at least one) with new content; `round`
/// makes the content different on every call.
pub fn mutate_one_percent(spec: &FixtureSpec, dir: &Path, round: u64) -> usize {
    let n = (spec.files / 100).max(1);
    let step = spec.files / n;
    for k in 0..n {
        let i = k * step;
        write_file(
            &dir.join(rel_path(i)),
            spec.file_size,
            (round << 32) ^ (i as u64 + 0xABCD),
            i.is_multiple_of(2),
        );
    }
    n
}

fn config(src: &Path) -> Config {
    Config {
        source_path: src.to_string_lossy().into_owned(),
        // Never used: the storage is injected.
        destination_path: src
            .join("unused-destination")
            .to_string_lossy()
            .into_owned(),
        exclude_patterns: vec![],
        compression_level: Some(3),
        ..Default::default()
    }
}

/// Backs `src` up into `storage`.
pub async fn backup(src: &Path, storage: Arc<dyn Storage>, key: Option<&str>) -> ReportData {
    let report = perform_backup(
        &config(src),
        BackupOptions {
            storage: Some(storage),
            max_threads: env_usize("RSB_BENCH_THREADS"),
            dedup_index: dedup_index_options(),
            ..Default::default()
        }
        .with_encryption_key(key),
    )
    .await
    .expect("backup");
    assert_eq!(report.files_with_errors, 0, "{:?}", report.errors);
    report
}

/// Dedup index settings: `RSB_BENCH_NO_INDEX=1` disables it,
/// `RSB_BENCH_INDEX_DIR` puts its files there (default: the user cache dir).
fn dedup_index_options() -> DedupIndexOptions {
    if std::env::var("RSB_BENCH_NO_INDEX").is_ok_and(|v| v == "1") {
        return DedupIndexOptions::disabled();
    }
    DedupIndexOptions {
        dir: std::env::var_os("RSB_BENCH_INDEX_DIR").map(PathBuf::from),
        ..DedupIndexOptions::default()
    }
}

/// Restores the latest snapshot of `storage` into `out` (overwriting).
pub async fn restore(storage: &dyn Storage, out: &Path, key: Option<&str>) -> ReportData {
    let report = restore_from_storage(
        storage,
        RestoreOptions {
            force: true,
            ..RestoreOptions::new(out)
        }
        .with_encryption_key(key),
    )
    .await
    .expect("restore");
    assert_eq!(report.files_with_errors, 0, "{:?}", report.errors);
    report
}

/// Peak resident set size of this process, in bytes (0 if unknown).
#[cfg(unix)]
pub fn peak_rss_bytes() -> u64 {
    // SAFETY: getrusage only writes into the zeroed struct we pass.
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) } != 0 {
        return 0;
    }
    let max = usage.ru_maxrss as u64;
    if cfg!(target_os = "macos") {
        max // bytes
    } else {
        max * 1024 // KiB
    }
}

/// Peak resident set size of this process, in bytes (0 if unknown).
#[cfg(not(unix))]
pub fn peak_rss_bytes() -> u64 {
    0
}

pub fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
}
