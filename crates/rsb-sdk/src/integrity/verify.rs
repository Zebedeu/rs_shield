use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;
use std::time::Instant;
use tracing::{info, warn};

use crate::core::manifest::find_latest_snapshot_cached;
use crate::core::storage_backend::get_storage;
use crate::core::types::{FileMetadata, ProgressCallback};
use crate::crypto::{KeyCache, hash_file_content};
use crate::integrity::checksum::checksum;
use crate::options::VerifyOptions;
use crate::report::ReportData;
use crate::storage::Storage;
use crate::{CancellationToken, Config};

/// Verifies every object referenced by a snapshot (latest, or
/// `options.snapshot_id`).
///
/// - `fast`: only checks presence, stored size and stored hash (no
///   download-and-decode); cannot prove an object is corrupt.
/// - full (default): reads each referenced object once, decrypts and
///   decompresses it and checks the content hash, which detects objects
///   truncated or damaged by older versions even when their size looked
///   plausible.
/// - `repair`: implies a full check; objects whose content is proven
///   corrupt are **deleted** so that the next backup re-uploads them (the
///   backup re-checks that objects it dedups against still exist). Missing
///   objects are reported; the next backup re-uploads them if the source
///   file is still present. Without `repair` the repository is never
///   modified.
///
/// The key is `options.encryption_key`, falling back to
/// `config.encryption_key`.
pub async fn perform_verify(
    config: &Config,
    options: VerifyOptions,
) -> Result<ReportData, Box<dyn std::error::Error>> {
    let VerifyOptions {
        snapshot_id,
        quiet,
        fast,
        repair,
        encryption_key,
        on_progress,
        cancellation_token,
    } = options;
    let snapshot_id = snapshot_id.as_deref();
    let start_time = Instant::now();
    let storage = get_storage(config).await?;
    let key_cache = encryption_key
        .as_ref()
        .map(|k| k.as_str())
        .or(config.encryption_key.as_deref())
        .map(|k| KeyCache::new(k.as_bytes()));

    // Reading the manifest with the key also proves the key is correct, so
    // a later decryption failure on an object means the object is damaged.
    let (path, content) =
        find_latest_snapshot_cached(&*storage, snapshot_id, key_cache.as_ref()).await?;
    info!("Verifying snapshot: {}", path);
    let manifest: HashMap<PathBuf, FileMetadata> = toml::from_str(&content)?;

    let fast = fast && !repair;
    let outcome = verify_manifest_objects(
        &*storage,
        &manifest,
        key_cache.as_ref(),
        VerifyObjectsOptions { fast, repair },
        on_progress,
        cancellation_token,
    )
    .await?;

    let status = if outcome.errors.is_empty() {
        "Success"
    } else if repair && !outcome.deleted.is_empty() {
        "Repaired: run a backup to re-upload deleted objects"
    } else {
        "Failure with errors"
    }
    .to_string();

    if !quiet {
        info!("Verification completed.");
        info!("Total files: {}", manifest.len());
        info!("✅ Files successfully verified: {}", outcome.files_ok);
        info!(
            "Objects checked: {} | missing: {} | corrupt: {} | manifest flag mismatches: {}",
            outcome.objects_checked,
            outcome.missing.len(),
            outcome.corrupt.len(),
            outcome.flag_mismatches
        );
        if repair {
            info!("Corrupt objects deleted: {}", outcome.deleted.len());
        }
    }

    let mode = match (fast, repair) {
        (true, _) => "Fast (Lite)",
        (false, false) => "Full",
        (false, true) => "Full + repair",
    };

    Ok(ReportData {
        operation: "Verify".to_string(),
        profile_path: "".to_string(),
        timestamp: chrono::Local::now().to_rfc3339(),
        duration: start_time.elapsed(),
        mode: Some(mode.to_string()),
        files_processed: outcome.files_ok,
        files_skipped: 0,
        files_with_errors: outcome.files_with_errors,
        total_files: manifest.len(),
        errors: outcome.errors,
        status,
    })
}

/// Options for [`verify_manifest_objects`].
#[derive(Debug, Clone, Copy, Default)]
pub struct VerifyObjectsOptions {
    /// Presence + stored size/hash only (ignored when `repair` is set).
    pub fast: bool,
    /// Delete objects whose content is proven corrupt.
    pub repair: bool,
}

/// A referenced object whose content does not match its content hash.
#[derive(Debug, Clone)]
pub struct CorruptObject {
    /// Storage key, e.g. `data/enc/<hash>`.
    pub path: String,
    pub reason: String,
    /// Snapshot files that reference the object.
    pub files: Vec<PathBuf>,
}

/// Result of [`verify_manifest_objects`].
#[derive(Debug, Clone, Default)]
pub struct VerifyObjectsOutcome {
    pub objects_checked: usize,
    pub files_ok: usize,
    pub files_with_errors: usize,
    /// Storage keys of referenced objects that do not exist.
    pub missing: Vec<String>,
    pub corrupt: Vec<CorruptObject>,
    /// Corrupt objects deleted by repair.
    pub deleted: Vec<String>,
    /// Intact objects whose manifest entry has the wrong `compressed` flag
    /// (written by older versions); restore of those files fails.
    pub flag_mismatches: usize,
    /// Human-readable error lines (one per problem).
    pub errors: Vec<String>,
}

/// One reference from a manifest entry to an object.
struct ObjectRef {
    file: PathBuf,
    compressed: bool,
    expected_size: Option<u64>,
    expected_stored_hash: Option<String>,
}

/// How an object's content was found to be valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Decoded {
    Plain,
    Zstd,
}

enum ObjectCheck {
    Ok(Option<Decoded>),
    Corrupt {
        reason: String,
        decrypt_failed: bool,
    },
    Error(String),
}

fn content_matches(data: &[u8], expected: &str) -> bool {
    hash_file_content(data).is_ok_and(|h| h == expected)
}

/// Reads one object and checks that it decodes to `content_hash`, under
/// either interpretation (plain or zstd), so that the result says which
/// one the object really is.
async fn check_object_content(
    storage: &dyn Storage,
    path: &str,
    content_hash: &str,
    encrypted: bool,
    key: Option<&KeyCache>,
) -> ObjectCheck {
    let raw = match storage.read(path).await {
        Ok(r) => r,
        Err(e) => return ObjectCheck::Error(format!("Failed to read {}: {}", path, e)),
    };
    let payload = if encrypted {
        let Some(key) = key else {
            return ObjectCheck::Error(format!(
                "{} is encrypted but no encryption key was provided",
                path
            ));
        };
        match key.decrypt(&raw) {
            Ok(p) => p,
            Err(e) => {
                return ObjectCheck::Corrupt {
                    reason: format!("decryption failed ({} bytes stored): {}", raw.len(), e),
                    decrypt_failed: true,
                };
            }
        }
    } else {
        raw
    };

    let mut decoded = Vec::new();
    let zstd_ok = zstd::stream::copy_decode(&payload[..], &mut decoded).is_ok()
        && content_matches(&decoded, content_hash);
    if zstd_ok {
        return ObjectCheck::Ok(Some(Decoded::Zstd));
    }
    if content_matches(&payload, content_hash) {
        return ObjectCheck::Ok(Some(Decoded::Plain));
    }
    ObjectCheck::Corrupt {
        reason: format!(
            "content hash mismatch ({} bytes after decryption; truncated or damaged)",
            payload.len()
        ),
        decrypt_failed: false,
    }
}

/// Verifies the objects referenced by `manifest`, each object once.
pub async fn verify_manifest_objects(
    storage: &dyn Storage,
    manifest: &HashMap<PathBuf, FileMetadata>,
    key: Option<&KeyCache>,
    options: VerifyObjectsOptions,
    on_progress: Option<ProgressCallback>,
    cancellation_token: Option<CancellationToken>,
) -> Result<VerifyObjectsOutcome, Box<dyn std::error::Error>> {
    let fast = options.fast && !options.repair;

    // object path -> (content hash, encrypted, references)
    let mut objects: BTreeMap<String, (String, bool, Vec<ObjectRef>)> = BTreeMap::new();
    for (file, meta) in manifest {
        let kind = if meta.encrypted { "enc" } else { "clear" };
        let items: Vec<(String, Option<u64>, Option<String>)> = match &meta.chunks {
            Some(chunks) => chunks
                .iter()
                .map(|c| (c.hash.clone(), Some(c.stored_size), c.stored_hash.clone()))
                .collect(),
            None => vec![(
                meta.hash.clone(),
                meta.stored_size,
                meta.stored_hash.clone(),
            )],
        };
        for (hash, size, stored_hash) in items {
            let path = format!("data/{}/{}", kind, hash);
            objects
                .entry(path)
                .or_insert_with(|| (hash, meta.encrypted, Vec::new()))
                .2
                .push(ObjectRef {
                    file: file.clone(),
                    compressed: meta.compressed,
                    expected_size: size,
                    expected_stored_hash: stored_hash,
                });
        }
    }

    let mut out = VerifyObjectsOutcome::default();
    let mut bad_files: HashSet<PathBuf> = HashSet::new();
    let mut decrypted_any = false;
    let mut delete_candidates: Vec<(String, bool)> = Vec::new();
    let total = objects.len();

    for (i, (path, (content_hash, encrypted, refs))) in objects.iter().enumerate() {
        if cancellation_token
            .as_ref()
            .is_some_and(|t| t.is_cancelled())
        {
            info!("⏹️ Verification cancelled by the user");
            out.errors.push("Verification cancelled".to_string());
            break;
        }
        if let Some(cb) = &on_progress {
            cb(i, total, format!("Verifying: {}", refs[0].file.display()));
        }
        out.objects_checked += 1;
        let files_list = || {
            let mut v: Vec<String> = refs.iter().map(|r| r.file.display().to_string()).collect();
            v.sort();
            v.dedup();
            v.join(", ")
        };

        match storage.exists(path).await {
            Ok(true) => {}
            Ok(false) => {
                out.errors.push(format!(
                    "Missing object {} (used by: {})",
                    path,
                    files_list()
                ));
                out.missing.push(path.clone());
                bad_files.extend(refs.iter().map(|r| r.file.clone()));
                continue;
            }
            Err(e) => {
                out.errors.push(format!("Failed to access {}: {}", path, e));
                bad_files.extend(refs.iter().map(|r| r.file.clone()));
                continue;
            }
        }

        if fast {
            let data = match storage.read(path).await {
                Ok(d) => d,
                Err(e) => {
                    out.errors.push(format!("Failed to read {}: {}", path, e));
                    bad_files.extend(refs.iter().map(|r| r.file.clone()));
                    continue;
                }
            };
            for r in refs {
                if let Err(e) = checksum(
                    &data,
                    r.expected_size.filter(|s| *s != 0),
                    r.expected_stored_hash.as_ref(),
                ) {
                    out.errors
                        .push(format!("{} for {} ({})", e, r.file.display(), path));
                    bad_files.insert(r.file.clone());
                }
            }
            continue;
        }

        match check_object_content(storage, path, content_hash, *encrypted, key).await {
            ObjectCheck::Ok(decoded) => {
                if *encrypted {
                    decrypted_any = true;
                }
                for r in refs {
                    let flag_ok = match decoded {
                        Some(Decoded::Zstd) => r.compressed,
                        Some(Decoded::Plain) => !r.compressed,
                        None => true,
                    };
                    if !flag_ok {
                        out.flag_mismatches += 1;
                        out.errors.push(format!(
                            "Manifest entry for {} says compressed={} but object {} is {}; \
                             the object is intact but this snapshot entry cannot be restored",
                            r.file.display(),
                            r.compressed,
                            path,
                            if r.compressed {
                                "not compressed"
                            } else {
                                "compressed"
                            }
                        ));
                        bad_files.insert(r.file.clone());
                    }
                }
            }
            ObjectCheck::Corrupt {
                reason,
                decrypt_failed,
            } => {
                out.errors.push(format!(
                    "Corrupt object {}: {} (used by: {})",
                    path,
                    reason,
                    files_list()
                ));
                let mut files: Vec<PathBuf> = refs.iter().map(|r| r.file.clone()).collect();
                files.sort();
                files.dedup();
                bad_files.extend(files.iter().cloned());
                out.corrupt.push(CorruptObject {
                    path: path.clone(),
                    reason,
                    files,
                });
                delete_candidates.push((path.clone(), decrypt_failed));
            }
            ObjectCheck::Error(e) => {
                out.errors.push(e);
                bad_files.extend(refs.iter().map(|r| r.file.clone()));
            }
        }
    }

    if options.repair {
        // If no encrypted object could be decrypted at all, decryption
        // failures more likely mean a wrong key than corrupt data: never
        // delete on that evidence alone.
        let encrypted_failures = delete_candidates.iter().filter(|(_, d)| *d).count();
        let distrust_decrypt = encrypted_failures > 0 && !decrypted_any;
        if distrust_decrypt {
            warn!(
                "{} objects failed to decrypt and none succeeded; not deleting them (wrong key?)",
                encrypted_failures
            );
            out.errors.push(format!(
                "Repair skipped {} objects that failed decryption: no encrypted object could be \
                 decrypted, check the encryption key",
                encrypted_failures
            ));
        }
        for (path, decrypt_failed) in delete_candidates {
            if decrypt_failed && distrust_decrypt {
                continue;
            }
            match storage.delete(&path).await {
                Ok(()) => {
                    warn!("Deleted corrupt object {}", path);
                    out.errors.push(format!(
                        "Deleted corrupt object {} (the next backup will re-upload it)",
                        path
                    ));
                    out.deleted.push(path);
                }
                Err(e) => out
                    .errors
                    .push(format!("Failed to delete corrupt object {}: {}", path, e)),
            }
        }
    }

    out.files_with_errors = bad_files.len();
    out.files_ok = manifest.len().saturating_sub(bad_files.len());
    Ok(out)
}
