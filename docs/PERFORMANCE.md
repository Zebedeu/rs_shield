# Performance

How backup and restore performance is measured, the numbers recorded so
far, and how benchmarks run in CI.

## Harness

Two benchmark targets live in `crates/rsb-sdk/benches/` (both
`harness = false`; `cargo test` never runs them):

| Target | What it does |
|--------|--------------|
| `backup_restore` | Criterion benchmarks (wall time, throughput, statistics, saved baselines). |
| `perf_probe` | One-shot measurements for this document: wall time, throughput, **peak RSS** and **storage calls** per operation. Each operation runs in its own child process, so the peak RSS is that of the operation alone. |

Fixtures are generated at runtime with fixed seeds (`benches/support`):

| Fixture | Content |
|---------|---------|
| (a) `small` | 20 000 files × 4 KiB in 100 directories, half text-like (compressible), half random |
| (b) `large` | 4 files × 256 MiB, alternating text-like and random (multipart: 8 chunks each) |
| (c) `incr` | the `small` fixture, backed up once, then 1% of the files (200) rewritten and backed up again (only the second backup is measured) |
| `small-lat`, `large-lat`, `incr-lat` | the same on the latency-injected storage, with 2 000 small files |

Every fixture runs unencrypted (`clear`) and encrypted (`enc`, repository
key v3), with zstd level 3. Storage backends:

* `local`: `LocalStorage` in a temporary directory;
* `memory`: `MemoryStorage` (criterion only: it has no fsync and no
  syscalls, so it isolates CPU costs);
* `latency`: `LocalStorage` behind `InstrumentedStorage::with_latency`
  (20 ms before every call), a model of an S3 round trip.

`InstrumentedStorage` (`rsb_sdk::storage`) also counts calls by the S3
request they map to: PUT (`write`, `write_file`, `write_from_reader`), GET
(`read`, `read_stream`), HEAD (`size`, `exists`), LIST (`list`, counted in
pages of 1 000 keys) and DELETE.

### Running

```sh
# Release build without LTO (faster to build; numbers below use it)
export CARGO_PROFILE_BENCH_LTO=false CARGO_PROFILE_BENCH_CODEGEN_UNITS=16

cargo bench -p rsb-sdk --bench perf_probe                  # every fixture
cargo bench -p rsb-sdk --bench perf_probe -- --only large --enc 1
cargo bench -p rsb-sdk --bench backup_restore              # criterion, full
RSB_BENCH_PROFILE=quick cargo bench -p rsb-sdk --bench backup_restore
```

`perf_probe` options: `--only <fixture>` (repeatable), `--enc 0|1`,
`--latency-ms N` (default 20), `--dir PATH` (work directory; the large
fixture needs about 3 GiB). Fixture sizes can be overridden with
`RSB_BENCH_SMALL_FILES`, `RSB_BENCH_SMALL_LAT_FILES`,
`RSB_BENCH_LARGE_FILES`, `RSB_BENCH_LARGE_MIB`; `RSB_BENCH_THREADS` sets
the backup threads. `RSB_BENCH_PROFILE=quick` selects the reduced CI subset
(500 small files, 2 × 80 MiB, in-memory storage only).

## Baseline (before phase 4)

Commit `31f2ac7`. Apple M1 Pro (8 cores: 6P + 2E), 16 GiB, APFS on the
internal SSD, macOS 26. Release build without LTO. Peak RSS is the child
process's `ru_maxrss` and includes the Argon2id unlock (64 MiB) for
encrypted runs. Calls are those of the measured operation.

| Fixture | Op | Mode | Storage | Wall (s) | MiB/s | Peak RSS (MiB) | Storage calls |
|---|---|---|---|---:|---:|---:|---|
| small | backup | clear | local | 148.32 | 0.5 | 50 | PUT 20 002 / GET 0 / HEAD 20 001 / LIST 1 |
| small | backup | enc | local | 144.73 | 0.5 | 98 | PUT 20 004 / GET 3 / HEAD 20 002 / LIST 2 |
| small | restore | clear | local | 223.17 | 0.4 | 93 | GET 20 001 / HEAD 20 001 / LIST 3 |
| small | restore | enc | local | 213.94 | 0.4 | 162 | GET 20 002 / HEAD 20 001 / LIST 3 |
| large | backup | clear | local | 4.03 | 253.8 | 433 | PUT 34 / HEAD 33 / LIST 1 |
| large | backup | enc | local | 4.54 | 225.5 | 246 | PUT 36 / GET 3 / HEAD 34 / LIST 2 |
| large | restore | clear | local | 2.57 | 398.4 | 19 | GET 33 / HEAD 1 / LIST 3 |
| large | restore | enc | local | 3.48 | 294.4 | 82 | GET 34 / HEAD 1 / LIST 3 |
| incr (1%) | backup | clear | local | 4.26 | | 101 | PUT 202 / GET 1 / HEAD 20 002 / LIST 2 |
| incr (1%) | backup | enc | local | 4.38 | | 167 | PUT 202 / GET 2 / HEAD 20 002 / LIST 2 |
| small-lat | backup | clear | latency | 16.21 | 0.5 | 18 | PUT 2 002 / HEAD 2 001 / LIST 1 |
| small-lat | backup | enc | latency | 16.66 | 0.5 | 93 | PUT 2 004 / GET 3 / HEAD 2 002 / LIST 2 |
| small-lat | restore | clear | latency | 110.77 | 0.1 | 18 | GET 2 001 / HEAD 2 001 / LIST 3 |
| small-lat | restore | enc | latency | 111.86 | 0.1 | 87 | GET 2 002 / HEAD 2 001 / LIST 3 |
| large-lat | backup | clear | latency | 4.17 | 245.4 | 386 | PUT 34 / HEAD 33 / LIST 1 |
| large-lat | backup | enc | latency | 8.68 | 118.0 | 253 | PUT 36 / GET 3 / HEAD 34 / LIST 2 |
| large-lat | restore | clear | latency | 3.85 | 265.8 | 17 | GET 33 / HEAD 1 / LIST 3 |
| large-lat | restore | enc | latency | 3.73 | 274.2 | 83 | GET 34 / HEAD 1 / LIST 3 |
| incr-lat (1%) | backup | clear | latency | 4.23 | | 22 | PUT 22 / GET 1 / HEAD 2 002 / LIST 2 |
| incr-lat (1%) | backup | enc | latency | 4.37 | | 89 | PUT 22 / GET 2 / HEAD 2 002 / LIST 2 |

Observations:

* **Small files are fsync-bound.** Every object write on local storage is
  temp file → `fsync` → rename → `fsync(dir)`, and on macOS `fsync` from
  Rust is `F_FULLFSYNC` (a full drive cache flush, a few ms). Backup does
  that for 20 000 objects; restore does it for 20 000 files, one at a
  time.
* **Restore is sequential**: one file at a time, so every storage round
  trip is paid in series (2 per file: HEAD then GET, about 55 ms per file
  with 20 ms of latency).
* **Backup memory grows with the chunk/file size**: files up to 64 MiB are
  read whole, chunks of large files are read whole (32 MiB), and clear
  objects are compressed into a second whole-size buffer before upload.
  With 4 large files in flight that is about 430 MiB.
* **Incremental backups pay one HEAD per unchanged file** (20 000 HEADs for
  200 changed files), and every backup waits for the resource monitor's
  4 s sleep before it returns (the 4.2 s floor of the incremental runs).

## After phase 4

Same machine, build and fixtures (`perf_probe`, full profile). Backups
now also create `meta/repo-id` (1 extra PUT on the first backup, 2 GETs and
1 LIST per backup to open the dedup index).

| Fixture | Op | Mode | Storage | Wall (s) before → after | MiB/s after | Peak RSS (MiB) before → after | Storage calls after (before) |
|---|---|---|---|---:|---:|---:|---|
| small | backup | clear | local | 148.32 → 14.96 | 5.2 | 50 → 62 | PUT 20 003 / HEAD 20 001 (same) |
| small | backup | enc | local | 144.73 → 13.31 | 5.9 | 98 → 98 | PUT 20 005 / HEAD 20 002 (same) |
| small | restore | clear | local | 223.17 → 9.47 | 8.3 | 93 → 93 | GET 20 001 / **HEAD 1** (HEAD 20 001) |
| small | restore | enc | local | 213.94 → 9.91 | 7.9 | 162 → 160 | GET 20 002 / **HEAD 1** (HEAD 20 001) |
| large | backup | clear | local | 4.03 → 2.00 | 512.8 | **433 → 107** | PUT 35 / HEAD 33 (same) |
| large | backup | enc | local | 4.54 → 3.12 | 328.5 | **246 → 146** | PUT 37 / HEAD 34 (same) |
| large | restore | clear | local | 2.57 → 0.97 | 1050.3 | 19 → 214 | GET 33 / HEAD 1 (same) |
| large | restore | enc | local | 3.48 → 1.09 | 936.0 | 82 → 242 | GET 34 / HEAD 1 (same) |
| incr (1%) | backup | clear | local | 4.26 → 0.71 | | 101 → 103 | PUT 202 / **HEAD 394** (HEAD 20 002) |
| incr (1%) | backup | enc | local | 4.38 → 0.72 | | 167 → 166 | PUT 202 / **HEAD 401** (HEAD 20 002) |
| small-lat | backup | clear | latency | 16.21 → 6.80 | 1.1 | 18 → 22 | PUT 2 003 / HEAD 2 001 (same) |
| small-lat | backup | enc | latency | 16.66 → 7.00 | 1.1 | 93 → 97 | PUT 2 005 / HEAD 2 002 (same) |
| small-lat | restore | clear | latency | 110.77 → 4.44 | 1.8 | 18 → 36 | GET 2 001 / **HEAD 1** (HEAD 2 001) |
| small-lat | restore | enc | latency | 111.86 → 4.32 | 1.8 | 87 → 181 | GET 2 002 / **HEAD 1** (HEAD 2 001) |
| large-lat | backup | clear | latency | 4.17 → 2.29 | 447.7 | **386 → 160** | PUT 35 / HEAD 33 (same) |
| large-lat | backup | enc | latency | 8.68 → 2.56 | 400.8 | **253 → 148** | PUT 37 / HEAD 34 (same) |
| large-lat | restore | clear | latency | 3.85 → 0.78 | 1317.9 | 17 → 221 | GET 33 / HEAD 1 (same) |
| large-lat | restore | enc | latency | 3.73 → 0.92 | 1117.9 | 83 → 246 | GET 34 / HEAD 1 (same) |
| incr-lat (1%) | backup | clear | latency | 4.23 → 0.47 | | 22 → 29 | PUT 22 / **HEAD 40** (HEAD 2 002) |
| incr-lat (1%) | backup | enc | latency | 4.37 → 0.56 | | 89 → 96 | PUT 22 / **HEAD 53** (HEAD 2 002) |

Run-to-run noise on this laptop is ±20-30% for the fsync-bound cases.
Higher restore RSS on large files is the multipart prefetch (2 chunks
ahead per file), always within `RESTORE_MEM_BUDGET_MIB` (512 MiB).

What changed (one commit each, numbers in the commit messages):

1. **Resource monitor** (`perf(backup): wake the resource monitor…`):
   it slept 4 s and every backup joined it; now parked/unparked.
   Unchanged 20k-file backup 4.29 s → 0.62 s.
2. **Parallel restore** (`RestoreOptions::concurrency`, default 2 × CPUs,
   4..=64): scoped worker threads on a multi-threaded runtime (in-task
   concurrency otherwise), path-ordered progress and errors, cancellation
   stops handing out files, case-colliding paths restored sequentially,
   multipart chunks prefetched 2 ahead (never waiting for budget, so no
   deadlock) and written in order, one directory fsync per directory at
   the end. All per-file guarantees unchanged.
3. **No HEAD before GET on restore**: a missing object is reported by the
   GET with the same message. Requests per file 2 → 1.
4. **Streaming backup**: files > 1 MiB and multipart chunks are hashed in a
   1 MiB-buffer pass and, only if stored, streamed again through
   zstd → (v3) → hasher → spool with the hash re-checked before upload;
   clear objects use the spool too; classifying an existing encrypted
   object reads its 45-byte header. Peak memory is now per worker, not
   per file/chunk size.
5. **Local atomic writes in one blocking task** (1 MiB copy buffer instead
   of 8 KiB `tokio::fs` round trips).
6. **Ordered fsync + batched directory fsync**: `F_BARRIERFSYNC` before
   each rename on Apple (`sync_all` elsewhere), data objects written with
   `Storage::write_deferred`, and one `Storage::sync()` (directory
   `F_FULLFSYNC`) before the manifest. Same crash guarantees: never a
   renamed but incomplete object/file, and a manifest never references an
   object whose rename is not durable.
7. **Local dedup index** (below).

### Dedup index

`<user cache dir>/rs-shield/dedup-index/<key>.idx` (configurable with
`BackupOptions::dedup_index`) lists data objects this machine verified
(HEAD or upload) for manifests it then wrote: object key, stored size,
time of the check. A lookup answered by the index costs no request.

Safety rules (correctness over speed):

* keyed by `meta/repo-id` (a random id stored in the repository, created
  on the first non-dry-run backup) **and** the storage location
  (`Storage::cache_identity`: canonical path, S3 endpoint/region/bucket);
  storage without an identity gets no index;
* checksummed file; a corrupt, truncated, foreign or unknown-version file
  is ignored (cold start, plain storage lookups);
* discarded when `meta/epoch` changed (prune, `verify --repair`,
  `key migrate`, `key rotate` rewrite it before deleting or rewriting
  objects) or when a snapshot it saw no longer exists (a prune by an older
  version);
* an entry is trusted only if it was checked less than `max_age` ago
  (default 24 h) and agrees with the size the caller expects; trusted hits
  do not refresh it;
* 1 trusted hit in `sample_one_in` (default 100, random per backup) is
  checked anyway; any HEAD that contradicts the index distrusts it for the
  rest of the backup, every object it answered for is checked again
  before the manifest is written, and the files whose object is missing
  are processed again without the index;
* any error while opening it disables it for that backup.

Residual risk, by design: an object deleted behind the repository's back
(by hand, by a storage lifecycle rule, or by an older client's
`verify --repair`) less than `max_age` ago and not sampled is trusted;
`rsb verify` detects it. Set `max_age` to zero to disable trust.

## Benchmarks in CI

`.github/workflows/benchmark.yml`:

| Trigger | Runs | Baseline |
|---------|------|----------|
| pull request (touching `crates/rsb-sdk`, `Cargo.toml` or the workflow) | `quick` profile: criterion `backup_restore` with 500 small files, 2 × 80 MiB and the incremental case, clear and encrypted, in-memory storage only (about 35 s of benchmarks on an M1 Pro, plus the build; target < 5 min with a warm cache) | compared with the latest `quick` baseline from `main`; never saved |
| push to `main`, weekly schedule, manual | `quick` (refreshes the PR baseline) and `full` (every fixture on local, in-memory and 20 ms latency storage, then `perf_probe` for peak RSS and storage calls, appended to the job summary) | compared with the previous baseline of the same profile, then saved |

Baselines are the `github-action-benchmark` data file kept in the GitHub
Actions cache (`bench-baseline-<profile>-*`); raw criterion output
(`target/criterion`, with its own saved baselines), `output.txt` and
`probe.md` are uploaded as artifacts.

**Regression policy: warn for now.** A benchmark slower than 120% of its
baseline is reported in the job summary and log, but does not fail the
job (`fail-on-alert: false`). Once the runner noise is known (a few weeks
of `main` history), switch to failing by setting `fail-on-alert: true`
(optionally `fail-threshold`, e.g. `150%`) in the "Compare with baseline"
step.

Benchmarks are built without LTO (`CARGO_PROFILE_BENCH_LTO=false`,
`CARGO_PROFILE_BENCH_CODEGEN_UNITS=16`) to keep the build short; baselines
are built the same way, so comparisons stay valid. `CARGO_TARGET_DIR` is
set so criterion does not shell out to `cargo metadata` (which can block
on cargo's lock while `cargo bench` holds it).
