//! Criterion benchmarks of backup and restore.
//!
//! ```text
//! cargo bench -p rsb-sdk --bench backup_restore                      # full
//! RSB_BENCH_PROFILE=quick cargo bench -p rsb-sdk --bench backup_restore
//! ```
//!
//! Fixtures (generated at runtime, see `support`): (a) many small files,
//! (b) a few large files, (c) an incremental backup with 1% of the small
//! files changed. Each runs clear and encrypted. The full profile runs on
//! `LocalStorage` and `MemoryStorage` and adds a latency-injected storage
//! (20 ms per call, models S3) on a smaller small-files fixture; the quick
//! profile (pull requests) runs smaller fixtures on `MemoryStorage` only.
//!
//! Every iteration starts from the same state: backups go to an empty
//! repository, restores to an empty directory, and the incremental case
//! changes 1% of the files before each timed backup.

mod support;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use rsb_sdk::storage::{InstrumentedStorage, LocalStorage, MemoryStorage, Storage};
use std::sync::Arc;
use std::time::{Duration, Instant};
use support::*;

#[derive(Clone, Copy)]
enum Backend {
    Local,
    Memory,
    /// Local storage behind a fixed per-call latency.
    Latency(Duration),
}

impl Backend {
    fn name(self) -> &'static str {
        match self {
            Backend::Local => "local",
            Backend::Memory => "memory",
            Backend::Latency(_) => "latency20ms",
        }
    }

    /// A fresh, empty repository (the temp dir keeps a local one alive).
    fn open(self) -> (Option<tempfile::TempDir>, Arc<dyn Storage>) {
        match self {
            Backend::Memory => (None, Arc::new(MemoryStorage::new())),
            Backend::Local | Backend::Latency(_) => {
                let dir = tempfile::tempdir().unwrap();
                let local: Arc<dyn Storage> =
                    Arc::new(LocalStorage::new(dir.path().to_str().unwrap()));
                let storage: Arc<dyn Storage> = match self {
                    Backend::Latency(d) => Arc::new(InstrumentedStorage::with_latency(local, d)),
                    _ => local,
                };
                (Some(dir), storage)
            }
        }
    }
}

fn modes() -> [(&'static str, Option<&'static str>); 2] {
    [("clear", None), ("enc", Some(PASSWORD))]
}

fn bench_fixture(c: &mut Criterion, spec: FixtureSpec, backends: &[Backend]) {
    let rt = runtime();
    let src = tempfile::tempdir().unwrap();
    generate(&spec, src.path());

    let mut group = c.benchmark_group(format!("backup/{}", spec.name));
    group.sample_size(10);
    group.warm_up_time(warm_up());
    group.measurement_time(measurement());
    group.throughput(Throughput::Bytes(spec.total_bytes()));
    for &backend in backends {
        for (mode, key) in modes() {
            let id = BenchmarkId::new(mode, backend.name());
            group.bench_function(id, |b| {
                b.iter_custom(|iters| {
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        let (_dir, storage) = backend.open();
                        let t = Instant::now();
                        rt.block_on(backup(src.path(), storage, key));
                        total += t.elapsed();
                    }
                    total
                })
            });
        }
    }
    group.finish();

    let mut group = c.benchmark_group(format!("restore/{}", spec.name));
    group.sample_size(10);
    group.warm_up_time(warm_up());
    group.measurement_time(measurement());
    group.throughput(Throughput::Bytes(spec.total_bytes()));
    for &backend in backends {
        for (mode, key) in modes() {
            let (_dir, storage) = backend.open();
            rt.block_on(backup(src.path(), storage.clone(), key));
            let id = BenchmarkId::new(mode, backend.name());
            group.bench_function(id, |b| {
                b.iter_custom(|iters| {
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        let out = tempfile::tempdir().unwrap();
                        let t = Instant::now();
                        rt.block_on(restore(&*storage, out.path(), key));
                        total += t.elapsed();
                    }
                    total
                })
            });
        }
    }
    group.finish();
}

fn bench_incremental(c: &mut Criterion, spec: FixtureSpec, backends: &[Backend]) {
    let rt = runtime();
    let src = tempfile::tempdir().unwrap();
    generate(&spec, src.path());
    let changed = (spec.files / 100).max(1) as u64;

    let mut group = c.benchmark_group(format!("incremental/{}", spec.name));
    group.sample_size(10);
    group.warm_up_time(warm_up());
    group.measurement_time(measurement());
    group.throughput(Throughput::Bytes(changed * spec.file_size));
    let mut round = 0u64;
    for &backend in backends {
        for (mode, key) in modes() {
            let (_dir, storage) = backend.open();
            rt.block_on(backup(src.path(), storage.clone(), key));
            let id = BenchmarkId::new(mode, backend.name());
            group.bench_function(id, |b| {
                b.iter_custom(|iters| {
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        round += 1;
                        mutate_one_percent(&spec, src.path(), round);
                        let t = Instant::now();
                        rt.block_on(backup(src.path(), storage.clone(), key));
                        total += t.elapsed();
                    }
                    total
                })
            });
        }
    }
    group.finish();
}

fn benches(c: &mut Criterion) {
    let profile = Profile::from_env();
    // The quick (pull request) subset uses in-memory storage only: no
    // fsync noise from the runner's disk, so regressions stand out.
    let backends: &[Backend] = match profile {
        Profile::Quick => &[Backend::Memory],
        Profile::Full => &[Backend::Local, Backend::Memory],
    };
    bench_fixture(c, small_files(profile), backends);
    bench_fixture(c, large_files(profile), backends);
    bench_incremental(c, small_files(profile), backends);
    if profile == Profile::Full {
        let lat = [Backend::Latency(Duration::from_millis(20))];
        bench_fixture(c, small_files_latency(profile), &lat);
        bench_incremental(c, small_files_latency(profile), &lat);
    }
}

/// Warm-up per benchmark (shorter in the quick CI profile).
fn warm_up() -> Duration {
    match Profile::from_env() {
        Profile::Quick => Duration::from_millis(100),
        Profile::Full => Duration::from_millis(500),
    }
}

/// Target measurement time per benchmark (at least 10 iterations run
/// anyway); shorter in the quick CI profile.
fn measurement() -> Duration {
    match Profile::from_env() {
        Profile::Quick => Duration::from_secs(1),
        Profile::Full => Duration::from_secs(5),
    }
}

criterion_group!(backup_restore, benches);
criterion_main!(backup_restore);
