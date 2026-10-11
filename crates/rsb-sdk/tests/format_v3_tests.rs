// Format v3 end to end: repository key file, v3 objects/manifests,
// password change, migration of v1/v2 repositories (mixed manifests) and
// tamper resistance of restore. Runs on MemoryStorage and LocalStorage.

use rsb_sdk::backup::perform_backup;
use rsb_sdk::config::Config;
use rsb_sdk::core::manifest::write_manifest;
use rsb_sdk::core::perform_prune_with_storage;
use rsb_sdk::core::perform_restore;
use rsb_sdk::core::types::FileMetadata;
use rsb_sdk::crypto::keyfile::{self, KdfParams, REPO_KEY_PATH};
use rsb_sdk::crypto::{BLOB_MAGIC_V3, EncryptionKey, hash_file_content};
use rsb_sdk::integrity::perform_verify;
use rsb_sdk::storage::{LocalStorage, MemoryStorage, Storage};
use rsb_sdk::{BackupOptions, CryptoErrorKind, RestoreOptions, RsbError, VerifyOptions};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

const PW: &str = "correct horse battery staple";

fn config(src: &Path) -> Config {
    Config {
        source_path: src.to_string_lossy().into_owned(),
        destination_path: "/nonexistent/must-not-be-used".into(),
        exclude_patterns: vec![],
        compression_level: Some(3),
        max_threads: Some(2),
        ..Default::default()
    }
}

async fn backup(
    cfg: &Config,
    storage: &Arc<dyn Storage>,
    pw: Option<&str>,
) -> Result<(), RsbError> {
    let r = perform_backup(
        cfg,
        BackupOptions {
            mode: Some("incremental".into()),
            max_threads: Some(2),
            storage: Some(storage.clone()),
            ..Default::default()
        }
        .with_encryption_key(pw),
    )
    .await?;
    assert_eq!(r.files_with_errors, 0, "{:?}", r.errors);
    Ok(())
}

async fn restore(
    cfg: &Config,
    storage: &Arc<dyn Storage>,
    pw: &str,
    out: &Path,
) -> Result<rsb_sdk::report::ReportData, RsbError> {
    perform_restore(
        cfg,
        RestoreOptions {
            force: true,
            storage: Some(storage.clone()),
            ..RestoreOptions::new(out)
        }
        .with_encryption_key(Some(pw)),
    )
    .await
}

async fn verify(
    cfg: &Config,
    storage: &Arc<dyn Storage>,
    pw: &str,
) -> Result<Vec<String>, RsbError> {
    perform_verify(
        cfg,
        VerifyOptions {
            quiet: true,
            storage: Some(storage.clone()),
            ..Default::default()
        }
        .with_encryption_key(Some(pw)),
    )
    .await
    .map(|r| r.errors)
}

fn is_auth_failure(e: &RsbError) -> bool {
    matches!(
        e,
        RsbError::Crypto {
            kind: CryptoErrorKind::AuthenticationFailed,
            ..
        }
    )
}

async fn objects(storage: &dyn Storage, prefix: &str) -> Vec<String> {
    storage.list(prefix).await.unwrap_or_default()
}

/// Deterministic pseudo-random (incompressible) bytes.
fn noise(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

fn write_src(src: &Path, files: &[(&str, &[u8])]) {
    for (name, data) in files {
        let p = src.join(name);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, data).unwrap();
    }
}

fn assert_tree(out: &Path, files: &[(&str, &[u8])]) {
    for (name, data) in files {
        assert_eq!(
            &std::fs::read(out.join(name)).unwrap()[..],
            *data,
            "{}",
            name
        );
    }
}

// ---------------------------------------------------------------------------

async fn fresh_repo_cycle(storage: Arc<dyn Storage>) {
    let src = tempfile::tempdir().unwrap();
    let cfg = config(src.path());
    let chunk = rsb_sdk::crypto::V3_DEFAULT_CHUNK_SIZE as usize;
    let big = noise(3 * 1024 * 1024 + 123, 7);
    let exact = noise(chunk, 8);
    let plus1 = noise(chunk + 1, 9);
    let files: Vec<(&str, &[u8])> = vec![
        ("empty.txt", b""),
        ("one.bin", b"x"),
        ("exact.bin", &exact),
        ("plus1.bin", &plus1),
        ("big.bin", &big),
        ("dir/text.txt", b"hello hello hello hello"),
    ];
    write_src(src.path(), &files);

    backup(&cfg, &storage, Some(PW)).await.unwrap();
    assert!(storage.exists(REPO_KEY_PATH).await.unwrap());

    // Every object and the manifest are v3.
    for o in objects(&*storage, "data/enc").await {
        let raw = storage.read(&o).await.unwrap();
        assert!(raw.starts_with(BLOB_MAGIC_V3), "{} is not v3", o);
    }
    let snaps = objects(&*storage, "snapshots").await;
    assert_eq!(snaps.len(), 1);
    assert!(
        storage
            .read(&snaps[0])
            .await
            .unwrap()
            .starts_with(BLOB_MAGIC_V3)
    );

    let out = tempfile::tempdir().unwrap();
    let r = restore(&cfg, &storage, PW, out.path()).await.unwrap();
    assert_eq!(r.files_with_errors, 0, "{:?}", r.errors);
    assert_tree(out.path(), &files);
    assert!(verify(&cfg, &storage, PW).await.unwrap().is_empty());

    // Wrong password: typed error from the key file, on every entry point.
    let e = restore(&cfg, &storage, "wrong", tempfile::tempdir().unwrap().path())
        .await
        .unwrap_err();
    assert!(is_auth_failure(&e), "{e:?}");
    assert!(is_auth_failure(
        &verify(&cfg, &storage, "wrong").await.unwrap_err()
    ));
    assert!(is_auth_failure(
        &backup(&cfg, &storage, Some("wrong")).await.unwrap_err()
    ));
    // Prune with the wrong password deletes nothing.
    backup(&cfg, &storage, Some(PW)).await.unwrap();
    let before = objects(&*storage, "snapshots").await.len();
    let e = perform_prune_with_storage(storage.clone(), Some("wrong"), 1)
        .await
        .unwrap_err();
    assert!(is_auth_failure(&e), "{e:?}");
    assert_eq!(objects(&*storage, "snapshots").await.len(), before);

    // Change password, then the old snapshots restore with the new one.
    keyfile::change_password(
        storage.clone(),
        PW.as_bytes(),
        b"new password",
        Some(KdfParams::MIN_CREATE),
    )
    .await
    .unwrap();
    assert!(is_auth_failure(
        &restore(&cfg, &storage, PW, tempfile::tempdir().unwrap().path())
            .await
            .unwrap_err()
    ));
    let out = tempfile::tempdir().unwrap();
    let r = restore(&cfg, &storage, "new password", out.path())
        .await
        .unwrap();
    assert_eq!(r.files_with_errors, 0, "{:?}", r.errors);
    assert_tree(out.path(), &files);
    perform_prune_with_storage(storage.clone(), Some("new password"), 1)
        .await
        .unwrap();
    assert_eq!(objects(&*storage, "snapshots").await.len(), 1);
    assert!(
        verify(&cfg, &storage, "new password")
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fresh_repo_cycle_memory() {
    fresh_repo_cycle(Arc::new(MemoryStorage::new())).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fresh_repo_cycle_local() {
    let dir = tempfile::tempdir().unwrap();
    fresh_repo_cycle(Arc::new(LocalStorage::new(dir.path().to_str().unwrap()))).await;
}

// ---------------------------------------------------------------------------

/// Builds a pre-v3 repository: one v1 (header-less) object, one v2 object
/// and a v2 manifest, all with `pw`.
async fn legacy_repo(storage: &dyn Storage, pw: &str, a: &[u8], b: &[u8]) {
    let mut manifest = HashMap::new();
    // v2 object (compressed).
    let ha = hash_file_content(a).unwrap();
    let v2 = EncryptionKey::new(pw.as_bytes())
        .unwrap()
        .encrypt(&zstd::stream::encode_all(a, 3).unwrap())
        .unwrap();
    storage
        .write(&format!("data/enc/{}", ha), &v2)
        .await
        .unwrap();
    manifest.insert(PathBuf::from("a.txt"), FileMetadata::new(ha, true, true));
    // v1 object (uncompressed): v2 body without header and AAD is not v1, so
    // build it from the public legacy API on a header-stripped layout.
    let hb = hash_file_content(b).unwrap();
    let v1 = legacy_v1_encrypt(b, pw.as_bytes());
    storage
        .write(&format!("data/enc/{}", hb), &v1)
        .await
        .unwrap();
    manifest.insert(PathBuf::from("b.txt"), FileMetadata::new(hb, true, false));
    write_manifest(storage, &manifest, Some(pw), false)
        .await
        .unwrap();
}

/// v1 layout: salt(16) | nonce(12) | ct | tag, PBKDF2-HMAC-SHA256 600k, no AAD.
fn legacy_v1_encrypt(data: &[u8], pw: &[u8]) -> Vec<u8> {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};
    let salt = [3u8; 16];
    let nonce = [4u8; 12];
    let mut key = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(pw, &salt, 600_000, &mut key);
    let ct = Aes256Gcm::new_from_slice(&key)
        .unwrap()
        .encrypt(Nonce::from_slice(&nonce), data)
        .unwrap();
    [&salt[..], &nonce[..], &ct[..]].concat()
}

async fn mixed_repo_cycle(storage: Arc<dyn Storage>) {
    let a = b"alpha alpha alpha alpha alpha".repeat(50);
    let b = b"bravo (v1 object)".to_vec();
    legacy_repo(&*storage, PW, &a, &b).await;
    let src = tempfile::tempdir().unwrap();
    let cfg = config(src.path());

    // The pre-v3 repository restores without a key file.
    assert!(!storage.exists(REPO_KEY_PATH).await.unwrap());
    let out = tempfile::tempdir().unwrap();
    let r = restore(&cfg, &storage, PW, out.path()).await.unwrap();
    assert_eq!(r.files_with_errors, 0, "{:?}", r.errors);
    assert_tree(out.path(), &[("a.txt", &a), ("b.txt", &b)]);

    // Migration refuses a password that does not open the existing backups.
    let c = b"charlie, new in v3".to_vec();
    write_src(src.path(), &[("a.txt", &a), ("b.txt", &b), ("c.txt", &c)]);
    let e = backup(&cfg, &storage, Some("typo")).await.unwrap_err();
    assert!(is_auth_failure(&e), "{e:?}");
    assert!(!storage.exists(REPO_KEY_PATH).await.unwrap());

    // First backup with the right password creates the key file; a.txt and
    // b.txt dedup onto the v2/v1 objects, c.txt is written as v3.
    backup(&cfg, &storage, Some(PW)).await.unwrap();
    assert!(storage.exists(REPO_KEY_PATH).await.unwrap());
    let hc = hash_file_content(&c).unwrap();
    let ha = hash_file_content(&a).unwrap();
    let hb = hash_file_content(&b).unwrap();
    assert!(
        storage
            .read(&format!("data/enc/{}", hc))
            .await
            .unwrap()
            .starts_with(BLOB_MAGIC_V3)
    );
    assert!(
        storage
            .read(&format!("data/enc/{}", ha))
            .await
            .unwrap()
            .starts_with(b"RSBENCv2")
    );

    let files: Vec<(&str, &[u8])> = vec![("a.txt", &a), ("b.txt", &b), ("c.txt", &c)];
    let out = tempfile::tempdir().unwrap();
    let r = restore(&cfg, &storage, PW, out.path()).await.unwrap();
    assert_eq!(r.files_with_errors, 0, "{:?}", r.errors);
    assert_tree(out.path(), &files);
    assert!(verify(&cfg, &storage, PW).await.unwrap().is_empty());

    // Password change: v1/v2 objects stay readable (legacy secret).
    keyfile::change_password(
        storage.clone(),
        PW.as_bytes(),
        b"pw2",
        Some(KdfParams::MIN_CREATE),
    )
    .await
    .unwrap();
    let out = tempfile::tempdir().unwrap();
    let r = restore(&cfg, &storage, "pw2", out.path()).await.unwrap();
    assert_eq!(r.files_with_errors, 0, "{:?}", r.errors);
    assert_tree(out.path(), &files);
    assert!(verify(&cfg, &storage, "pw2").await.unwrap().is_empty());

    // Prune keeps the mixed snapshot and its v1/v2/v3 objects.
    perform_prune_with_storage(storage.clone(), Some("pw2"), 1)
        .await
        .unwrap();
    assert_eq!(objects(&*storage, "snapshots").await.len(), 1);
    let left = objects(&*storage, "data/enc").await;
    for h in [&ha, &hb, &hc] {
        assert!(left.iter().any(|o| o.ends_with(h.as_str())), "{h} pruned");
    }
    let out = tempfile::tempdir().unwrap();
    restore(&cfg, &storage, "pw2", out.path()).await.unwrap();
    assert_tree(out.path(), &files);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mixed_v2_v3_repo_memory() {
    mixed_repo_cycle(Arc::new(MemoryStorage::new())).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mixed_v2_v3_repo_local() {
    let dir = tempfile::tempdir().unwrap();
    mixed_repo_cycle(Arc::new(LocalStorage::new(dir.path().to_str().unwrap()))).await;
}

// ---------------------------------------------------------------------------

/// Restore of a tampered v3 object fails for that file, leaves no partial
/// output (no target, no temp file) and still restores the other files.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tampered_v3_objects_are_rejected_without_partial_output() {
    let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    let src = tempfile::tempdir().unwrap();
    let cfg = config(src.path());
    let victim = noise(2 * 1024 * 1024 + 99, 1); // 3 chunks, incompressible
    let other = noise(1500, 2);
    write_src(
        src.path(),
        &[("victim.bin", &victim), ("other.bin", &other)],
    );
    backup(&cfg, &storage, Some(PW)).await.unwrap();

    let hv = format!("data/enc/{}", hash_file_content(&victim).unwrap());
    let ho = format!("data/enc/{}", hash_file_content(&other).unwrap());
    let good = storage.read(&hv).await.unwrap();
    let good_other = storage.read(&ho).await.unwrap();
    let header = 45;
    let ct = rsb_sdk::crypto::V3_DEFAULT_CHUNK_SIZE as usize + 16;

    let mut cases: Vec<(&str, Vec<u8>)> = Vec::new();
    let mut b = good.clone();
    b[10] ^= 1;
    cases.push(("header byte", b));
    let mut b = good.clone();
    b[header + ct + 5] ^= 1;
    cases.push(("ciphertext byte", b));
    let mut b = good[..header].to_vec();
    b.extend_from_slice(&good[header + ct..header + 2 * ct]);
    b.extend_from_slice(&good[header..header + ct]);
    b.extend_from_slice(&good[header + 2 * ct..]);
    cases.push(("swapped chunks", b));
    cases.push(("dropped last chunk", good[..header + 2 * ct].to_vec()));
    let mut b = good.clone();
    b.extend_from_slice(&good[header..header + ct]);
    cases.push(("appended chunk", b));
    cases.push(("truncated mid-chunk", good[..header + ct + 1000].to_vec()));
    // Another valid blob moved under this name (wrong object id).
    cases.push(("wrong object id", good_other.clone()));

    for (what, bytes) in cases {
        storage.write(&hv, &bytes).await.unwrap();
        let out = tempfile::tempdir().unwrap();
        let r = restore(&cfg, &storage, PW, out.path()).await.unwrap();
        assert_eq!(r.files_with_errors, 1, "{what}: {:?}", r.errors);
        let names: Vec<String> = std::fs::read_dir(out.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["other.bin".to_string()], "{what}: leftovers");
        // Verify flags it as corrupt as well.
        let errs = verify(&cfg, &storage, PW).await.unwrap();
        assert!(
            errs.iter().any(|e| e.contains("Corrupt object")),
            "{what}: {errs:?}"
        );
    }

    // A tampered manifest is a typed authentication failure, not "wrong key".
    storage.write(&hv, &good).await.unwrap();
    let snap = objects(&*storage, "snapshots").await.remove(0);
    let mut m = storage.read(&snap).await.unwrap();
    let last = m.len() - 1;
    m[last] ^= 1;
    storage.write(&snap, &m).await.unwrap();
    let e = restore(&cfg, &storage, PW, tempfile::tempdir().unwrap().path())
        .await
        .unwrap_err();
    assert!(is_auth_failure(&e), "{e:?}");
    assert!(!e.to_string().contains("wrong key"));
    // A manifest renamed to another snapshot name does not open either.
    m[last] ^= 1;
    storage.delete(&snap).await.unwrap();
    storage
        .write("snapshots/2030-01-01T000000.000Z.toml", &m)
        .await
        .unwrap();
    let e = restore(&cfg, &storage, PW, tempfile::tempdir().unwrap().path())
        .await
        .unwrap_err();
    assert!(is_auth_failure(&e), "{e:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deleting_the_key_file_is_reported() {
    let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    let src = tempfile::tempdir().unwrap();
    let cfg = config(src.path());
    write_src(src.path(), &[("a.txt", b"data")]);
    backup(&cfg, &storage, Some(PW)).await.unwrap();
    storage.delete(REPO_KEY_PATH).await.unwrap();
    let e = restore(&cfg, &storage, PW, tempfile::tempdir().unwrap().path())
        .await
        .unwrap_err();
    assert!(matches!(e, RsbError::Crypto { .. }), "{e:?}");
    assert!(e.to_string().contains("keys/repo.key"), "{e}");
    // And a backup refuses to create a second key over v3 snapshots.
    assert!(backup(&cfg, &storage, Some(PW)).await.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unencrypted_backups_do_not_create_a_key_file() {
    let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    let src = tempfile::tempdir().unwrap();
    let cfg = config(src.path());
    write_src(src.path(), &[("a.txt", b"data")]);
    backup(&cfg, &storage, None).await.unwrap();
    assert!(!storage.exists(REPO_KEY_PATH).await.unwrap());
}
