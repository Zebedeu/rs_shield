# rsb fuzzing harness

libFuzzer targets (via [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz))
for the parsers that read untrusted repository data. This crate is excluded
from the main workspace and needs a **nightly** toolchain.

| Target               | Input                                   | Code under test |
|----------------------|-----------------------------------------|-----------------|
| `blob_decrypt`       | encrypted blob (legacy / v2)            | `crypto::KeyCache::decrypt`, `decrypt_owned`, `decrypt_data` |
| `manifest_parse`     | manifest TOML / snapshot names / paths  | `toml` -> `HashMap<PathBuf, FileMetadata>`, `parse_snapshot_timestamp`, `validate_snapshot_id`, `validate_storage_path`, `validate_content_hash` |
| `zstd_stream_decode` | zstd stream                             | streaming decode loop used on restore (output capped at 8 MiB) |
| `lock_parse`         | `locks/*.lock` JSON                     | `storage::lock::parse_lock` + `LockInfo::liveness` |

The target bodies live in `rsb_sdk::fuzzing` (built only with the `fuzzing`
feature), so every target is also exercised on stable by
`cargo test -p rsb-sdk --lib fuzzing` with pseudo-random inputs.

Every target asserts: no panic, no hang, bounded allocation, plus
target-specific invariants (both decrypt paths agree, tampered blobs are
rejected, accepted paths have only normal components, streaming and one-shot
zstd decoding agree, unparseable locks fail closed, ...).

Notes:

* `blob_decrypt` uses a fixed password and splices a fixed salt / iteration
  count into most inputs, so PBKDF2 runs once per process rather than once per
  input. The first input byte selects the framing (see
  `rsb_sdk::fuzzing::fuzz_blob_decrypt`). Format v3 is in progress on another
  branch; add a `BlobDecryptor` for it there.
* `zstd_stream_decode` mirrors `core::restore::decode_into`, which is private;
  switch it to call the real function once that is exposed as `pub(crate)`.

## Running

```sh
rustup toolchain install nightly
cargo install cargo-fuzz

cd fuzz
cargo +nightly fuzz list
cargo +nightly fuzz run blob_decrypt -- -max_total_time=60
cargo +nightly fuzz run manifest_parse -- -max_total_time=60
cargo +nightly fuzz run zstd_stream_decode -- -max_total_time=60 -rss_limit_mb=1024
cargo +nightly fuzz run lock_parse -- -max_total_time=60
```

Useful libFuzzer flags: `-max_len=65536`, `-timeout=10` (per input, seconds),
`-rss_limit_mb=2048`, `-malloc_limit_mb=512`, `-jobs=4`.

A crash is written to `fuzz/artifacts/<target>/`. Reproduce and minimize it:

```sh
cargo +nightly fuzz run <target> fuzz/artifacts/<target>/crash-...
cargo +nightly fuzz tmin <target> fuzz/artifacts/<target>/crash-...
```

then add the minimized input as a regular unit test in `rsb-sdk` before fixing.

## Seed corpus

`corpus/<target>/` holds a few valid samples per target. They are produced by
`rsb_sdk::fuzzing::seed_corpus()`; regenerate them with:

```sh
RSB_FUZZ_CORPUS_DIR=$PWD/fuzz/corpus \
  cargo test -p rsb-sdk --lib fuzzing::tests::seed_corpus_is_accepted
```

libFuzzer adds new interesting inputs to the corpus directory while running;
only commit the hand-picked seeds.
