//! Property tests for the v3 blob format and repository path validation.
//!
//! Case count: 32 by default (fast enough for `cargo test`); set
//! `PROPTEST_CASES` to run more.

use proptest::prelude::*;
use rsb_sdk::core::manifest::manifest_key;
use rsb_sdk::crypto::stream::{
    DEK_LEN, StreamDecryptor, StreamEncryptor, V3_DEFAULT_CHUNK_SIZE, V3_HEADER_LEN, decrypt_v3,
    encrypt_v3, key_id_of, v3_blob_len,
};
use rsb_sdk::storage::validate_storage_path;
use std::io::Write;
use std::path::{Component, Path, PathBuf};

const CS: usize = V3_DEFAULT_CHUNK_SIZE as usize;

fn config() -> ProptestConfig {
    let cases = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(32);
    ProptestConfig::with_cases(cases)
}

/// Deterministic pseudo-random bytes (xorshift64*), cheap to generate.
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

/// Payload sizes: small, or within a few bytes of a chunk boundary
/// (0..=3 chunks), where the final-chunk logic changes.
fn payload_len() -> impl Strategy<Value = usize> {
    prop_oneof![
        2 => 0usize..=300,
        3 => (0usize..=3, -20i64..=20)
            .prop_map(|(k, d)| (k as i64 * CS as i64 + d).max(0) as usize),
    ]
}

fn object_id() -> impl Strategy<Value = String> {
    prop_oneof!["[0-9a-f]{64}", "snapshots/[0-9A-Za-z:.-]{1,24}\\.toml",]
}

async fn stream_decrypt(dek: &[u8; DEK_LEN], id: &str, blob: &[u8]) -> std::io::Result<Vec<u8>> {
    // Hand over the magic as an already consumed prefix, like restore does.
    let (prefix, rest) = blob.split_at(8.min(blob.len()));
    let mut dec = StreamDecryptor::new(dek, id, prefix, rest).await?;
    let mut out = Vec::new();
    while let Some(chunk) = dec.next_chunk().await? {
        out.extend_from_slice(chunk);
    }
    Ok(out)
}

fn block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(f)
}

proptest! {
    #![proptest_config(config())]

    /// Encrypt → decrypt (one shot and streaming) returns the payload, and
    /// the stored length matches the documented formula.
    #[test]
    fn v3_round_trip(
        len in payload_len(),
        seed in any::<u64>(),
        dek in any::<[u8; DEK_LEN]>(),
        with_key_id in any::<bool>(),
        id in object_id(),
    ) {
        let data = bytes(len, seed);
        let key_id = with_key_id.then(|| key_id_of(&dek));
        let blob = encrypt_v3(&dek, key_id, &id, &data).unwrap();
        prop_assert_eq!(blob.len() as u64, v3_blob_len(len as u64, V3_DEFAULT_CHUNK_SIZE));
        prop_assert_eq!(&decrypt_v3(&dek, &id, &blob).unwrap(), &data);
        prop_assert_eq!(&block_on(stream_decrypt(&dek, &id, &blob)).unwrap(), &data);

        // Bound to the object id and the key.
        let other_id = format!("{id}x");
        prop_assert!(decrypt_v3(&dek, &other_id, &blob).is_err());
        let mut other_dek = dek;
        other_dek[0] ^= 1;
        prop_assert!(decrypt_v3(&other_dek, &id, &blob).is_err());
    }

    /// The streaming encryptor gives the same layout whatever the write
    /// sizes, and its output decrypts.
    #[test]
    fn v3_stream_encryptor_any_write_split(
        len in payload_len(),
        seed in any::<u64>(),
        dek in any::<[u8; DEK_LEN]>(),
        splits in prop::collection::vec(1usize..=(CS + 17), 1..8),
    ) {
        let data = bytes(len, seed);
        let mut enc = StreamEncryptor::new(&dek, None, "obj", Vec::new()).unwrap();
        let mut rest = &data[..];
        for s in splits.iter().cycle() {
            if rest.is_empty() {
                break;
            }
            let n = (*s).min(rest.len());
            enc.write_all(&rest[..n]).unwrap();
            rest = &rest[n..];
        }
        let blob = enc.finish().unwrap();
        prop_assert_eq!(blob.len() as u64, v3_blob_len(len as u64, V3_DEFAULT_CHUNK_SIZE));
        prop_assert_eq!(&decrypt_v3(&dek, "obj", &blob).unwrap(), &data);
    }

    /// Any single-bit flip anywhere in the blob (header, ciphertext or tag)
    /// is rejected, by the one-shot and the streaming reader alike, and the
    /// streaming reader never returns a chunk of a blob that fails.
    #[test]
    fn v3_rejects_any_single_bit_flip(
        len in payload_len(),
        seed in any::<u64>(),
        dek in any::<[u8; DEK_LEN]>(),
        bit in any::<prop::sample::Index>(),
    ) {
        let data = bytes(len, seed);
        let mut blob = encrypt_v3(&dek, Some(key_id_of(&dek)), "obj", &data).unwrap();
        let bit = bit.index(blob.len() * 8);
        blob[bit / 8] ^= 1 << (bit % 8);
        prop_assert!(decrypt_v3(&dek, "obj", &blob).is_err(), "flip of bit {} accepted", bit);
        prop_assert!(block_on(stream_decrypt(&dek, "obj", &blob)).is_err());
    }

    /// Truncation or appended bytes are rejected.
    #[test]
    fn v3_rejects_truncation_and_extension(
        len in payload_len(),
        seed in any::<u64>(),
        dek in any::<[u8; DEK_LEN]>(),
        cut in any::<prop::sample::Index>(),
        extra in prop::collection::vec(any::<u8>(), 1..64),
    ) {
        let data = bytes(len, seed);
        let blob = encrypt_v3(&dek, None, "obj", &data).unwrap();
        let cut = cut.index(blob.len());
        prop_assert!(decrypt_v3(&dek, "obj", &blob[..cut]).is_err(), "cut at {}", cut);
        prop_assert!(block_on(stream_decrypt(&dek, "obj", &blob[..cut])).is_err());
        let mut longer = blob.clone();
        longer.extend_from_slice(&extra);
        prop_assert!(decrypt_v3(&dek, "obj", &longer).is_err());
        prop_assert!(blob.len() >= V3_HEADER_LEN + 16);
    }
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

/// A path segment: plain names (incl. unicode, dots inside, spaces) or the
/// dangerous ones.
fn segment() -> impl Strategy<Value = String> {
    prop_oneof![
        4 => "[a-zA-Z0-9_ .\\-éçãü日本語😀]{1,10}",
        1 => Just("..".to_string()),
        1 => Just(".".to_string()),
        1 => Just(String::new()),
        1 => Just("C:".to_string()),
        1 => Just("a\\..".to_string()),
        1 => Just("..\\b".to_string()),
        1 => Just("x\0y".to_string()),
    ]
}

fn raw_path() -> impl Strategy<Value = String> {
    (
        prop_oneof![
            Just(""),
            Just("/"),
            Just("//"),
            Just("\\"),
            Just("C:\\"),
            Just("C:/")
        ],
        prop::collection::vec(segment(), 1..6),
        prop_oneof![Just(""), Just("/")],
    )
        .prop_map(|(lead, segs, tail)| format!("{lead}{}{tail}", segs.join("/")))
}

/// What an accepted path must look like: relative, made only of normal
/// components, so joining it to a base never leaves the base.
fn assert_contained(rel: &str) -> Result<(), TestCaseError> {
    prop_assert!(!rel.contains('\\') && !rel.contains('\0'), "{:?}", rel);
    prop_assert!(!rel.split('/').any(|s| s == ".."), "{:?}", rel);
    let p = Path::new(rel);
    prop_assert!(!p.is_absolute() && !p.has_root(), "{:?}", rel);
    for c in p.components() {
        prop_assert!(matches!(c, Component::Normal(_)), "{:?} in {:?}", c, rel);
    }
    let base = Path::new("base");
    let joined = base.join(p);
    prop_assert!(joined.starts_with(base));
    let depth = joined.components().count();
    prop_assert_eq!(depth, 1 + p.components().count());
    Ok(())
}

proptest! {
    #![proptest_config(config())]

    /// Structured paths with traversal pieces: accepted ⇒ contained, and
    /// any `..` segment, leading separator or backslash ⇒ rejected.
    #[test]
    fn storage_path_never_accepts_traversal(rel in raw_path()) {
        let ok = validate_storage_path(&rel).is_ok();
        if ok {
            assert_contained(&rel)?;
        }
        let dangerous = rel.split('/').any(|s| s == "..")
            || rel.starts_with('/')
            || rel.contains('\\')
            || rel.contains('\0')
            || rel.is_empty();
        if dangerous {
            prop_assert!(!ok, "accepted {:?}", rel);
        }
    }

    /// Arbitrary strings: whatever is accepted is contained.
    #[test]
    fn storage_path_arbitrary_strings(rel in any::<String>()) {
        if validate_storage_path(&rel).is_ok() {
            assert_contained(&rel)?;
        }
    }

    /// manifest_key joins normal components with `/` (on every platform)
    /// and the result validates; a path with a `..` component never yields
    /// an accepted key.
    #[test]
    fn manifest_key_is_portable_and_safe(
        names in prop::collection::vec("[a-zA-Z0-9_ \\-éçãü日本語😀][a-zA-Z0-9_ .\\-éçãü日本語😀]{0,9}", 1..6),
        parent_at in prop::option::of(any::<prop::sample::Index>()),
    ) {
        let rel: PathBuf = names.iter().collect();
        let key = manifest_key(&rel);
        let key_str = key.to_str().unwrap();
        // Names never start with '.', so components() keeps them all.
        prop_assert_eq!(key_str, names.join("/"));
        prop_assert!(validate_storage_path(key_str).is_ok(), "{:?}", key_str);

        if let Some(at) = parent_at {
            let mut with_parent = names.clone();
            with_parent.insert(at.index(names.len() + 1), "..".to_string());
            let rel: PathBuf = with_parent.iter().collect();
            let key = manifest_key(&rel);
            prop_assert!(
                validate_storage_path(&key.to_string_lossy()).is_err(),
                "{:?}",
                key
            );
        }
    }
}
