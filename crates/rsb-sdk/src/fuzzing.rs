//! Fuzzing entry points (not a stable API).
//!
//! Compiled only with the `fuzzing` cargo feature (used by the `fuzz/` crate)
//! or in tests. Each `fuzz_*` function takes arbitrary bytes and must never
//! panic, hang or allocate unboundedly; invariants are checked with
//! `assert!` so libFuzzer reports violations as crashes.

use crate::core::manifest::{parse_snapshot_timestamp, validate_snapshot_id};
use crate::core::types::FileMetadata;
use crate::crypto::{BLOB_MAGIC_V2, EncryptionKey, KeyCache, PBKDF2_ITERATIONS};
use crate::storage::lock::{
    HostIdentity, LockKind, LockLiveness, ProcessProbe, ProcessState, parse_lock,
};
use crate::storage::{validate_content_hash, validate_storage_path};
use std::collections::HashMap;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;

/// Fixed password used by the decrypt targets.
pub const FUZZ_PASSWORD: &[u8] = b"rsb-fuzz-password";
/// Fixed salt spliced into fuzzed blobs so the PBKDF2 key is derived once per
/// process (cached by [`KeyCache`]) instead of once per input.
const FUZZ_SALT: [u8; 16] = *b"rsb-fuzz-salt-16";
/// Minimum blob length for any format (salt + nonce + tag).
const MIN_BLOB_LEN: usize = 16 + 12 + 16;

// ---------------------------------------------------------------------------
// blob_decrypt
// ---------------------------------------------------------------------------

/// "Decrypt this blob": one implementation per supported on-disk format.
///
/// TODO(format-v3): the v3 encryption format is being written on another
/// branch; add a `BlobDecryptor` for it (and its seed corpus) once it lands.
pub trait BlobDecryptor {
    fn name(&self) -> &'static str;
    /// Decrypts a blob given by reference.
    fn decrypt(&self, blob: &[u8]) -> io::Result<Vec<u8>>;
    /// Decrypts a blob given by value (in-place path); must agree with
    /// [`BlobDecryptor::decrypt`].
    fn decrypt_owned(&self, blob: Vec<u8>) -> io::Result<Vec<u8>>;
}

/// Current formats (legacy + v2) through [`KeyCache`].
pub struct CurrentFormat {
    cache: KeyCache,
}

impl BlobDecryptor for CurrentFormat {
    fn name(&self) -> &'static str {
        "legacy+v2"
    }
    fn decrypt(&self, blob: &[u8]) -> io::Result<Vec<u8>> {
        self.cache.decrypt(blob)
    }
    fn decrypt_owned(&self, blob: Vec<u8>) -> io::Result<Vec<u8>> {
        self.cache.decrypt_owned(blob)
    }
}

fn current_format() -> &'static CurrentFormat {
    static D: OnceLock<CurrentFormat> = OnceLock::new();
    D.get_or_init(|| CurrentFormat {
        cache: KeyCache::new(FUZZ_PASSWORD),
    })
}

fn encryption_key() -> &'static EncryptionKey {
    static K: OnceLock<EncryptionKey> = OnceLock::new();
    K.get_or_init(|| EncryptionKey::new(FUZZ_PASSWORD).expect("key derivation"))
}

/// Runs `blob` through both decrypt paths and checks they agree.
pub fn check_decryptor(d: &dyn BlobDecryptor, blob: &[u8]) -> io::Result<Vec<u8>> {
    let a = d.decrypt(blob);
    let b = d.decrypt_owned(blob.to_vec());
    match (&a, &b) {
        (Ok(x), Ok(y)) => assert_eq!(x, y, "{}: decrypt paths disagree", d.name()),
        (Err(_), Err(_)) => {}
        _ => panic!(
            "{}: decrypt and decrypt_owned disagree: {:?} vs {:?}",
            d.name(),
            a.as_ref().map(Vec::len),
            b.as_ref().map(Vec::len)
        ),
    }
    if let Ok(p) = &a {
        assert!(p.len() <= blob.len(), "plaintext larger than blob");
    }
    a
}

/// Fuzz target: arbitrary bytes into the blob decrypt paths.
///
/// The first byte selects how the input is framed. Fully arbitrary blobs of
/// at least `MIN_BLOB_LEN` bytes would carry a random salt (and, for v2,
/// an arbitrary PBKDF2 iteration count up to 10M) and force a fresh PBKDF2
/// per input, which is a throughput problem rather than a bug, so those
/// cases splice in a fixed salt/iteration count instead.
pub fn fuzz_blob_decrypt(data: &[u8]) {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let d = current_format();
    match mode % 5 {
        // Short raw input: size/magic checks, including the slow
        // password-based entry point (fails before PBKDF2).
        0 => {
            let raw = &rest[..rest.len().min(MIN_BLOB_LEN - 1)];
            assert!(crate::crypto::decrypt_data(raw, FUZZ_PASSWORD).is_err());
            assert!(check_decryptor(d, raw).is_err());
        }
        // Legacy layout: salt | nonce | body+tag.
        1 => {
            let blob = [&FUZZ_SALT[..], rest].concat();
            let _ = check_decryptor(d, &blob);
        }
        // v2 layout with the default iteration count.
        2 => {
            let blob = [
                &BLOB_MAGIC_V2[..],
                &PBKDF2_ITERATIONS.to_be_bytes(),
                &FUZZ_SALT,
                rest,
            ]
            .concat();
            let _ = check_decryptor(d, &blob);
        }
        // v2 magic with an out-of-range iteration count: rejected as v2,
        // falls back to legacy parsing (with a fixed salt prefix).
        3 => {
            let iters: u32 = if rest.first().is_some_and(|b| b & 1 == 1) {
                u32::MAX
            } else {
                0
            };
            let blob = [&BLOB_MAGIC_V2[..], &iters.to_be_bytes(), &FUZZ_SALT, rest].concat();
            let _ = check_decryptor(d, &blob);
        }
        // Round trip: encrypt `rest`, decrypt it back, then corrupt one byte
        // and require authentication to fail.
        _ => {
            let blob = encryption_key().encrypt(rest).expect("encrypt");
            let plain = check_decryptor(d, &blob).expect("round trip must decrypt");
            assert_eq!(plain, rest);
            if let Some((&pos, _)) = rest.split_first() {
                let mut bad = blob.clone();
                let i = pos as usize % bad.len();
                bad[i] ^= 0x01;
                assert!(check_decryptor(d, &bad).is_err(), "tampered blob accepted");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// manifest_parse
// ---------------------------------------------------------------------------

/// Fuzz target: manifest TOML + snapshot-name parsing + restore validators.
pub fn fuzz_manifest_parse(data: &[u8]) {
    let text = String::from_utf8_lossy(data);

    let _ = parse_snapshot_timestamp(&text);
    check_snapshot_id(&text);
    check_storage_path(&text);
    let _ = validate_content_hash(&text);
    for line in text.lines().take(64) {
        let _ = parse_snapshot_timestamp(line);
        check_snapshot_id(line);
        check_storage_path(line);
    }

    if let Ok(manifest) = toml::from_str::<HashMap<PathBuf, FileMetadata>>(&text) {
        for (path, meta) in &manifest {
            if let Some(p) = path.to_str() {
                check_storage_path(p);
            }
            check_content_hash(&meta.hash);
            if let Some(h) = &meta.stored_hash {
                check_content_hash(h);
            }
            for c in meta.chunks.iter().flatten() {
                check_content_hash(&c.hash);
            }
        }
        // Must round-trip through the serializer used by backup.
        if let Ok(s) = toml::to_string(&manifest) {
            let again: HashMap<PathBuf, FileMetadata> =
                toml::from_str(&s).expect("re-serialized manifest must parse");
            assert_eq!(again, manifest);
        }
    }
}

fn check_snapshot_id(s: &str) {
    if let Ok(bare) = validate_snapshot_id(s) {
        assert!(!bare.is_empty() && bare.len() <= 128);
        assert!(!bare.contains('/') && !bare.contains('\\') && !bare.contains(".."));
        assert!(!bare.starts_with('.'));
    }
}

fn check_storage_path(s: &str) {
    if validate_storage_path(s).is_ok() {
        let p = Path::new(s);
        assert!(!p.is_absolute(), "absolute path accepted: {s:?}");
        assert!(
            p.components().all(|c| matches!(c, Component::Normal(_))),
            "non-normal component accepted: {s:?}"
        );
        assert!(!s.contains('\0') && !s.contains('\\'));
    }
}

fn check_content_hash(s: &str) {
    if validate_content_hash(s).is_ok() {
        assert_eq!(s.len(), 64);
        assert!(s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
    }
}

// ---------------------------------------------------------------------------
// zstd_stream_decode
// ---------------------------------------------------------------------------

/// Output cap for the streaming decoder in the fuzz harness.
pub const ZSTD_FUZZ_MAX_OUTPUT: usize = 8 * 1024 * 1024;

/// Synchronous mirror of the streaming decode loop used on restore
/// (`core::restore::decode_into`), with the same buffer handling and
/// truncation detection, writing into a `Vec` capped at `max_out` bytes.
///
/// TODO: `decode_into` is private to `core/restore.rs` (owned by the format
/// refactor); once it is exposed as `pub(crate)`, call it directly here
/// instead of mirroring it.
pub fn zstd_stream_decode(
    src: &[u8],
    read_chunk: usize,
    out_buf_len: usize,
    max_out: usize,
) -> io::Result<Vec<u8>> {
    use zstd::stream::raw::{Decoder, InBuffer, Operation, OutBuffer};
    let read_chunk = read_chunk.max(1);
    let mut outbuf = vec![0u8; out_buf_len.max(1)];
    let mut out = Vec::new();
    let mut decoder = Decoder::new()?;
    let mut saw_input = false;
    let mut frame_complete = false;
    for inbuf in src.chunks(read_chunk) {
        let n = inbuf.len();
        saw_input = true;
        let mut consumed = 0;
        loop {
            let (used, produced, hint) = {
                let mut input = InBuffer::around(&inbuf[consumed..n]);
                let mut output = OutBuffer::around(&mut outbuf[..]);
                let hint = decoder.run(&mut input, &mut output)?;
                (input.pos(), output.pos(), hint)
            };
            consumed += used;
            if used > 0 || produced > 0 {
                frame_complete = hint == 0;
            }
            if produced > 0 {
                if out.len() + produced > max_out {
                    return Err(io::Error::other("output limit reached"));
                }
                out.extend_from_slice(&outbuf[..produced]);
            }
            if consumed == n && produced == 0 {
                break;
            }
        }
    }
    if saw_input && !frame_complete {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Truncated or corrupt compressed data",
        ));
    }
    Ok(out)
}

/// Fuzz target: arbitrary bytes into the streaming zstd decoder. The first
/// two bytes choose the read chunk and output buffer sizes so buffer
/// boundaries are exercised too.
pub fn fuzz_zstd_stream_decode(data: &[u8]) {
    let (read_chunk, out_len, src) = match data {
        [a, b, rest @ ..] => (1 + *a as usize * 64, 1 + *b as usize * 512, rest),
        _ => (4096, 4096, data),
    };
    let streamed = zstd_stream_decode(src, read_chunk, out_len, ZSTD_FUZZ_MAX_OUTPUT);
    // Differential check against the one-shot decoder for complete frames.
    if let Ok(out) = &streamed {
        let mut reference = Vec::new();
        let mut limited = LimitedWriter {
            inner: &mut reference,
            left: ZSTD_FUZZ_MAX_OUTPUT,
        };
        if zstd::stream::copy_decode(src, &mut limited).is_ok() {
            assert_eq!(out, &reference, "streaming and one-shot decode disagree");
        }
    }
}

struct LimitedWriter<'a> {
    inner: &'a mut Vec<u8>,
    left: usize,
}

impl io::Write for LimitedWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.len() > self.left {
            return Err(io::Error::other("limit"));
        }
        self.left -= buf.len();
        self.inner.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// lock_parse
// ---------------------------------------------------------------------------

/// Deterministic process table for the lock target.
struct FuzzProbe(ProcessState);

impl ProcessProbe for FuzzProbe {
    fn state(&self, _pid: u32) -> ProcessState {
        self.0
    }
}

/// Fuzz target: lock object parsing + staleness decision.
pub fn fuzz_lock_parse(data: &[u8]) {
    let (ctl, raw) = match data.split_first() {
        Some((c, r)) => (*c, r),
        None => (0, data),
    };
    let now: u64 = 1_800_000_000;
    let lock = parse_lock("locks/fuzz.lock", raw, now);
    let host = HostIdentity {
        hostname: if ctl & 1 == 0 {
            lock.hostname.clone()
        } else {
            "fuzz-host".into()
        },
        machine_id: if ctl & 2 == 0 {
            lock.machine_id.clone()
        } else {
            None
        },
    };
    let probe = FuzzProbe(match (ctl >> 2) % 3 {
        0 => ProcessState::NotRunning,
        1 => ProcessState::Running { start_unix: None },
        _ => ProcessState::Running {
            start_unix: lock
                .process_start_unix
                .map(|s| s.wrapping_add((ctl >> 4) as u64)),
        },
    });
    let liveness = lock.liveness(now, &host, &probe);
    let _ = lock.holder_description(now);

    // Invariants of the decision.
    if lock.is_stale(now) {
        assert_eq!(liveness, LockLiveness::StaleHeartbeat);
    }
    if lock.process_start_unix.is_none() || !host.is_same_host(&lock) {
        assert_eq!(liveness.is_stale(), lock.is_stale(now));
    }
    if matches!(probe.0, ProcessState::Running { start_unix: None }) {
        assert_eq!(liveness.is_stale(), lock.is_stale(now));
    }
    // Unparseable input fails closed (exclusive, fresh, never stale).
    if serde_json::from_slice::<serde::de::IgnoredAny>(raw).is_err() {
        assert_eq!(lock.kind, LockKind::Exclusive);
        assert_eq!(liveness, LockLiveness::Live);
    }
}

/// Valid sample inputs per target (framing bytes included), used as the
/// seed corpus under `fuzz/corpus/<target>/`.
pub fn seed_corpus() -> Vec<(&'static str, &'static str, Vec<u8>)> {
    let h = "0123456789abcdef".repeat(4);
    let mut seeds = Vec::new();

    let key = encryption_key();
    let v2 = key.encrypt(b"hello rsb").expect("encrypt");
    // Strip the header+salt that the harness splices back in for mode 2.
    let mut v2_body = vec![2u8];
    v2_body.extend_from_slice(&v2[12 + 16..]);
    seeds.push(("blob_decrypt", "v2_header_spliced", v2_body));
    seeds.push((
        "blob_decrypt",
        "roundtrip",
        [&[4u8][..], b"plaintext"].concat(),
    ));
    seeds.push((
        "blob_decrypt",
        "legacy_shape",
        [&[1u8][..], &[0u8; 40]].concat(),
    ));
    seeds.push(("blob_decrypt", "short", vec![0u8, 1, 2, 3]));
    seeds.push((
        "blob_decrypt",
        "bad_iterations",
        [&[3u8][..], &[1u8; 40]].concat(),
    ));

    let manifest = format!(
        "[\"docs/a.txt\"]\nhash = \"{h}\"\nencrypted = false\ncompressed = true\nstored_hash = \"{h}\"\nstored_size = 12\n\n\
         [\"big.bin\"]\nhash = \"{h}\"\nencrypted = true\nstored_size = 64\n\n\
         [[\"big.bin\".chunks]]\nhash = \"{h}\"\nstored_size = 32\nstored_hash = \"{h}\"\n"
    );
    seeds.push(("manifest_parse", "manifest", manifest.into_bytes()));
    seeds.push((
        "manifest_parse",
        "snapshot_name",
        b"2026-02-07T103000.123Z".to_vec(),
    ));
    seeds.push((
        "manifest_parse",
        "snapshot_path",
        b"snapshots/2026-02-07T103000Z-2.toml".to_vec(),
    ));
    seeds.push((
        "manifest_parse",
        "rfc3339",
        b"2026-02-07T10:30:00Z".to_vec(),
    ));

    let plain = b"zstd seed data ".repeat(200);
    for (name, level) in [("level1", 1), ("level19", 19)] {
        let frame = zstd::stream::encode_all(&plain[..], level).expect("zstd");
        seeds.push((
            "zstd_stream_decode",
            name,
            [&[16u8, 8][..], &frame].concat(),
        ));
    }
    let two = [
        zstd::stream::encode_all(&b"a"[..], 3).expect("zstd"),
        zstd::stream::encode_all(&b"b"[..], 3).expect("zstd"),
    ]
    .concat();
    seeds.push((
        "zstd_stream_decode",
        "two_frames",
        [&[0u8, 0][..], &two].concat(),
    ));

    let lock_new = br#"{"id":"0f1e","kind":"exclusive","operation":"prune","hostname":"host-a","pid":4242,"created_unix":1800000000,"refreshed_unix":1800000000,"process_start_unix":1799990000,"holder_id":"9a8b","machine_id":"m1"}"#;
    let lock_old = br#"{"id":"0f1e","kind":"shared","operation":"backup","hostname":"host-a","pid":4242,"created_unix":1800000000,"refreshed_unix":1799000000}"#;
    seeds.push(("lock_parse", "new_format", [&[0u8][..], lock_new].concat()));
    seeds.push((
        "lock_parse",
        "new_other_host",
        [&[1u8][..], lock_new].concat(),
    ));
    seeds.push(("lock_parse", "old_format", [&[4u8][..], lock_old].concat()));
    seeds.push(("lock_parse", "torn", [&[0u8][..], &lock_new[..40]].concat()));
    seeds
}

/// Runs every target over pseudo-random inputs. Used by the stable test
/// suite as a smoke test (the real fuzzing needs nightly + cargo-fuzz).
#[cfg(test)]
mod tests {
    use super::*;

    /// Runs the seeds through their targets; with `RSB_FUZZ_CORPUS_DIR` set,
    /// also writes them to `<dir>/<target>/<name>`.
    #[test]
    fn seed_corpus_is_accepted() {
        let out = std::env::var_os("RSB_FUZZ_CORPUS_DIR").map(PathBuf::from);
        for (target, name, bytes) in seed_corpus() {
            match target {
                "blob_decrypt" => fuzz_blob_decrypt(&bytes),
                "manifest_parse" => fuzz_manifest_parse(&bytes),
                "zstd_stream_decode" => fuzz_zstd_stream_decode(&bytes),
                "lock_parse" => fuzz_lock_parse(&bytes),
                other => panic!("unknown target {other}"),
            }
            if let Some(dir) = &out {
                let d = dir.join(target);
                std::fs::create_dir_all(&d).unwrap();
                std::fs::write(d.join(name), &bytes).unwrap();
            }
        }
    }

    fn xorshift(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    fn random_inputs(seed: u64, count: usize, max_len: usize) -> Vec<Vec<u8>> {
        let mut s = seed;
        (0..count)
            .map(|_| {
                let len = (xorshift(&mut s) as usize) % max_len;
                (0..len).map(|_| xorshift(&mut s) as u8).collect()
            })
            .collect()
    }

    #[test]
    fn smoke_blob_decrypt() {
        for input in random_inputs(1, 300, 256) {
            fuzz_blob_decrypt(&input);
        }
        for mode in 0..5u8 {
            fuzz_blob_decrypt(&[mode]);
            fuzz_blob_decrypt(&[mode; 80]);
        }
    }

    #[test]
    fn smoke_manifest_parse() {
        let valid = format!(
            "[\"docs/a.txt\"]\nhash = \"{h}\"\nencrypted = false\n\n[\"b/c\"]\nhash = \"{h}\"\nencrypted = true\nstored_size = 3\n[[\"b/c\".chunks]]\nhash = \"{h}\"\nstored_size = 1\n",
            h = "a".repeat(64)
        );
        fuzz_manifest_parse(valid.as_bytes());
        fuzz_manifest_parse(
            b"2026-02-07T103000.123Z\n../x\n/etc/passwd\nsnapshots/2026-02-07T103000Z-2.toml",
        );
        for input in random_inputs(2, 2000, 256) {
            fuzz_manifest_parse(&input);
        }
    }

    #[test]
    fn smoke_zstd_stream_decode() {
        let frame = zstd::stream::encode_all(&b"hello zstd ".repeat(500)[..], 3).unwrap();
        assert_eq!(
            zstd_stream_decode(&frame, 7, 13, ZSTD_FUZZ_MAX_OUTPUT).unwrap(),
            b"hello zstd ".repeat(500)
        );
        assert!(zstd_stream_decode(&frame[..frame.len() - 1], 64, 64, usize::MAX).is_err());
        fuzz_zstd_stream_decode(&[[0u8, 0].as_slice(), &frame].concat());
        for input in random_inputs(3, 2000, 512) {
            fuzz_zstd_stream_decode(&input);
        }
        // Bit flips of a valid frame.
        let mut s = 4;
        for _ in 0..500 {
            let mut f = frame.clone();
            let i = xorshift(&mut s) as usize % f.len();
            f[i] ^= 1 << (xorshift(&mut s) % 8);
            fuzz_zstd_stream_decode(&[[3u8, 1].as_slice(), &f].concat());
        }
    }

    #[test]
    fn smoke_lock_parse() {
        let now = 1_800_000_000u64;
        let v = format!(
            r#"{{"id":"a","kind":"shared","operation":"backup","hostname":"h","pid":7,"created_unix":{now},"refreshed_unix":{now},"process_start_unix":5,"holder_id":"x"}}"#
        );
        for ctl in 0..=255u8 {
            fuzz_lock_parse(&[[ctl].as_slice(), v.as_bytes()].concat());
        }
        for input in random_inputs(5, 2000, 256) {
            fuzz_lock_parse(&input);
        }
    }
}
