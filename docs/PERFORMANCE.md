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
