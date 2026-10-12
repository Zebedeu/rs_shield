// manifest.rs - Performance + reliability version
use super::types::{ChunkMetadata, FileMetadata};
use crate::crypto::KeyCache;
use crate::crypto::encrypt_data_with_key;
use crate::error::{CryptoErrorKind, RsbError};
use crate::storage::Storage;
use chrono::{DateTime, NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use tracing::{debug, error, info};
use zstd::stream::copy_decode;

/// Legacy snapshot name format (1-second resolution), e.g. `2026-02-07T103000Z`.
pub const SNAPSHOT_NAME_FORMAT_SECS: &str = "%Y-%m-%dT%H%M%SZ";
/// Current snapshot name format (millisecond resolution), e.g. `2026-02-07T103000.123Z`.
pub const SNAPSHOT_NAME_FORMAT: &str = "%Y-%m-%dT%H%M%S%.3fZ";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct ChunkReport {
    pub file_path: PathBuf,
    pub chunks: Vec<ChunkMetadata>,
    pub total_chunks: usize,
}

/// Manifest key of a source-relative path: components joined with `/`
/// whatever the platform, so a manifest written on Windows restores
/// everywhere (restore refuses `\` in entries).
pub fn manifest_key(rel: &std::path::Path) -> PathBuf {
    let parts: Vec<String> = rel
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    PathBuf::from(parts.join("/"))
}

/// Parses the timestamp encoded in a snapshot name or path.
///
/// Accepts `snapshots/<name>.toml` or a bare `<name>` in any of the formats
/// ever produced: `%Y-%m-%dT%H%M%SZ`, `%Y-%m-%dT%H%M%S.<frac>Z`, either one
/// followed by a `-<n>` collision suffix, or RFC3339 (`2026-02-07T10:30:00Z`).
pub fn parse_snapshot_timestamp(name: &str) -> Option<DateTime<Utc>> {
    let stem = name.rsplit('/').next().unwrap_or(name);
    let stem = stem.strip_suffix(".toml").unwrap_or(stem);

    if let Some(z) = stem.rfind('Z') {
        let (head, tail) = stem.split_at(z);
        let suffix = &tail[1..];
        let suffix_ok = suffix.is_empty()
            || (suffix.len() > 1
                && suffix.starts_with('-')
                && suffix[1..].bytes().all(|b| b.is_ascii_digit()));
        if suffix_ok {
            let (base, frac) = match head.split_once('.') {
                Some((b, f)) => (b, Some(f)),
                None => (head, None),
            };
            if let Ok(naive) = NaiveDateTime::parse_from_str(base, "%Y-%m-%dT%H%M%S") {
                let mut ts = naive.and_utc();
                match frac {
                    None => return Some(ts),
                    Some(f)
                        if !f.is_empty()
                            && f.len() <= 9
                            && f.bytes().all(|b| b.is_ascii_digit()) =>
                    {
                        let nanos: i64 = format!("{:0<9}", f).parse().ok()?;
                        ts += chrono::Duration::nanoseconds(nanos);
                        return Some(ts);
                    }
                    Some(_) => {}
                }
            }
        }
    }

    DateTime::parse_from_rfc3339(stem)
        .ok()
        .map(|t| t.with_timezone(&Utc))
}

/// Validates a user-supplied snapshot id before it is turned into a storage
/// key. Accepts an optional `.toml` suffix and returns the bare id.
pub fn validate_snapshot_id(id: &str) -> Result<&str, Box<dyn std::error::Error>> {
    let bare = id.strip_suffix(".toml").unwrap_or(id);
    let ok = !bare.is_empty()
        && bare.len() <= 128
        && !bare.starts_with('.')
        && !bare.contains("..")
        && bare
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':' | b'+'));
    if !ok {
        return Err(format!(
            "Invalid snapshot id '{}': expected a snapshot name such as 2026-02-07T103000.123Z",
            id
        )
        .into());
    }
    Ok(bare)
}

/// Picks a snapshot path that does not exist yet for `now`.
async fn unique_snapshot_path(
    storage: &dyn Storage,
    now: DateTime<Utc>,
) -> Result<String, Box<dyn std::error::Error>> {
    let base = now.format(SNAPSHOT_NAME_FORMAT).to_string();
    let first = format!("snapshots/{}.toml", base);
    if !storage.exists(&first).await? {
        return Ok(first);
    }
    for n in 1..1000u32 {
        let candidate = format!("snapshots/{}-{}.toml", base, n);
        if !storage.exists(&candidate).await? {
            return Ok(candidate);
        }
    }
    Err("Could not allocate a unique snapshot name".into())
}

/// Writes the manifest in an optimized way (compression + encryption)
pub async fn write_manifest(
    storage: &dyn Storage,
    manifest: &HashMap<PathBuf, FileMetadata>,
    encryption_key: Option<&str>,
    dry_run: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    let now = Utc::now();

    if dry_run {
        let snapshot_path = format!("snapshots/{}.toml", now.format(SNAPSHOT_NAME_FORMAT));
        info!("[Dry-run] Snapshot manifest not written: {}", snapshot_path);
        return Ok(snapshot_path);
    }

    // Millisecond resolution + existence check: two backups finishing in
    // the same second no longer overwrite each other's manifest.
    let snapshot_path = unique_snapshot_path(storage, now).await?;

    // TOML Serialization
    let content_str = toml::to_string(manifest)?;

    // Zstd Compression (efficient for text-based manifest)
    let mut compressed = Vec::new();
    {
        let mut encoder = zstd::Encoder::new(&mut compressed, 3)?; // level 3 = good compression/speed balance
        encoder.write_all(content_str.as_bytes())?;
        encoder.finish()?;
    }

    // Encryption (if applicable)
    let final_bytes = if let Some(key) = encryption_key {
        let enc_key = crate::crypto::EncryptionKey::new(key.as_bytes())
            .map_err(|e| format!("Failed to derive key for manifest: {}", e))?;
        encrypt_data_with_key(&compressed, &enc_key)?
    } else {
        compressed
    };

    // Storage::write is atomic + fsync'ed for local storage.
    storage.write(&snapshot_path, &final_bytes).await?;
    info!(
        "📸 Snapshot manifest written: {} ({} bytes → {} bytes)",
        snapshot_path,
        content_str.len(),
        final_bytes.len()
    );

    Ok(snapshot_path)
}

/// Reads the manifest with support for encryption + compression
pub async fn read_manifest(
    storage: &dyn Storage,
    path: &str,
    key: Option<&str>,
) -> Result<String, Box<dyn std::error::Error>> {
    let cache = key.map(|k| KeyCache::new(k.as_bytes()));
    read_manifest_cached(storage, path, cache.as_ref()).await
}

/// Like [`read_manifest`], but reuses derived keys across calls (one PBKDF2
/// per salt instead of one per manifest).
pub async fn read_manifest_cached(
    storage: &dyn Storage,
    path: &str,
    cache: Option<&KeyCache>,
) -> Result<String, Box<dyn std::error::Error>> {
    let raw = storage.read(path).await?;

    let decrypted = if let Some(cache) = cache {
        match cache.decrypt(&raw) {
            Ok(data) => data,
            Err(e) => {
                // 🐛 Fix: Provide more helpful error message.
                // Classificação tipada (não por texto da mensagem): tag AEAD
                // inválida ⇒ chave errada; dados mal formados ⇒ corrupção.
                let kind = if crate::crypto::is_authentication_error(&e) {
                    CryptoErrorKind::AuthenticationFailed
                } else if e.kind() == std::io::ErrorKind::InvalidData {
                    CryptoErrorKind::Corrupt
                } else {
                    CryptoErrorKind::Other
                };
                let user_message = match kind {
                    CryptoErrorKind::AuthenticationFailed => {
                        format!(
                            "❌ Decryption failed (wrong key)\n\n\
                        The backup is encrypted but the key provided is incorrect.\n\
                        Use the SAME encryption key that was used when creating this backup.\n\n\
                        Technical: {}",
                            e
                        )
                    }
                    CryptoErrorKind::Corrupt => {
                        format!(
                            "⚠️  Backup metadata may be corrupted\n\n\
                        The backup data cannot be read, even with the provided key.\n\
                        This may indicate:\n\
                        - Incomplete backup copy\n\
                        - Corrupted backup files\n\
                        - Wrong backup directory\n\n\
                        Try: rsb verify --backup /path/to/backup\n\n\
                        Technical: {}",
                            e
                        )
                    }
                    CryptoErrorKind::Other => {
                        format!(
                            "❌ Decryption error\n\n\
                        Could not decrypt backup metadata.\n\
                        Ensure:\n\
                        - The backup is not corrupted\n\
                        - The correct encryption key is provided\n\
                        - The entire backup folder was copied\n\n\
                        Technical: {}",
                            e
                        )
                    }
                };
                error!("Decryption error for {}: {}", path, e);
                return Err(Box::new(RsbError::crypto(kind, user_message)));
            }
        }
    } else {
        raw
    };

    // Tries to decompress (Zstd) - check magic number or just try decoding
    let mut decompressed = Vec::new();
    if copy_decode(&decrypted[..], &mut decompressed).is_ok() {
        return String::from_utf8(decompressed).map_err(|e| {
            debug!("Manifest UTF-8 decode failed after decompression: {:?}", e);

            "Backup metadata is corrupted or unreadable".into()
        });
    }

    // Fallback: it wasn't compressed, try reading as raw string
    String::from_utf8(decrypted).map_err(|_| {
        debug!("Manifest parsing failed: {}", path);

        "Backup metadata is corrupted or unreadable".into()
    })
}

/// Sorts snapshot paths newest first: by parsed timestamp, then by name
/// (collision suffixes / unparseable names fall back to lexicographic order).
pub fn sort_snapshots_newest_first(snapshots: &mut [String]) {
    snapshots.sort_by(|a, b| {
        let ka = (parse_snapshot_timestamp(a), collision_suffix(a));
        let kb = (parse_snapshot_timestamp(b), collision_suffix(b));
        kb.cmp(&ka).then_with(|| b.cmp(a))
    });
}

/// `-<n>` suffix added by [`write_manifest`] on name collisions (0 if none).
fn collision_suffix(name: &str) -> u32 {
    let stem = name.rsplit('/').next().unwrap_or(name);
    let stem = stem.strip_suffix(".toml").unwrap_or(stem);
    stem.rfind('Z')
        .and_then(|z| stem[z + 1..].strip_prefix('-'))
        .and_then(|n| n.parse().ok())
        .unwrap_or(0)
}

/// Efficiently finds the most recent snapshot
pub async fn find_latest_snapshot(
    storage: &dyn Storage,
    snapshot_id: Option<&str>,
    key: Option<&str>,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    let cache = key.map(|k| KeyCache::new(k.as_bytes()));
    find_latest_snapshot_cached(storage, snapshot_id, cache.as_ref()).await
}

/// Like [`find_latest_snapshot`], sharing a key cache with the caller.
pub async fn find_latest_snapshot_cached(
    storage: &dyn Storage,
    snapshot_id: Option<&str>,
    cache: Option<&KeyCache>,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    if let Some(id) = snapshot_id {
        let id = validate_snapshot_id(id)?;
        let path = format!("snapshots/{}.toml", id);
        if storage.exists(&path).await? {
            let content = read_manifest_cached(storage, &path, cache).await?;
            return Ok((path, content));
        }
        return Err("Snapshot ID not found".into());
    }

    // Full listing (S3 is paginated) + timestamp-aware sorting
    let mut snapshots = storage.list("snapshots").await?;
    snapshots.retain(|s| s.ends_with(".toml"));

    if snapshots.is_empty() {
        return Err("No snapshots found".into());
    }

    sort_snapshots_newest_first(&mut snapshots);
    let latest = snapshots.into_iter().next().unwrap();

    let content = read_manifest_cached(storage, &latest, cache).await?;
    Ok((latest, content))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::LocalStorage;

    #[test]
    fn parses_all_snapshot_name_formats() {
        let legacy = parse_snapshot_timestamp("snapshots/2026-02-07T103000Z.toml").unwrap();
        assert_eq!(legacy.to_rfc3339(), "2026-02-07T10:30:00+00:00");
        let ms = parse_snapshot_timestamp("2026-02-07T103000.250Z").unwrap();
        assert_eq!(ms.timestamp_subsec_millis(), 250);
        assert!(parse_snapshot_timestamp("2026-02-07T103000.250Z-2.toml").is_some());
        assert!(parse_snapshot_timestamp("2026-02-07T10:30:00Z").is_some());
        assert!(parse_snapshot_timestamp("garbage.toml").is_none());
        // Names produced by the writer round-trip through the parser.
        let now = Utc::now();
        let name = now.format(SNAPSHOT_NAME_FORMAT).to_string();
        let parsed = parse_snapshot_timestamp(&name).unwrap();
        assert_eq!(parsed.timestamp_millis(), now.timestamp_millis());
    }

    #[test]
    fn snapshot_id_validation() {
        assert_eq!(
            validate_snapshot_id("2026-02-07T103000Z").unwrap(),
            "2026-02-07T103000Z"
        );
        assert_eq!(
            validate_snapshot_id("2026-02-07T103000.1Z.toml").unwrap(),
            "2026-02-07T103000.1Z"
        );
        assert!(validate_snapshot_id("../../etc/passwd").is_err());
        assert!(validate_snapshot_id("a/b").is_err());
        assert!(validate_snapshot_id("..").is_err());
        assert!(validate_snapshot_id("").is_err());
        assert!(validate_snapshot_id("x\\y").is_err());
    }

    #[tokio::test]
    async fn manifests_written_in_same_instant_do_not_collide() {
        let dir = tempfile::tempdir().unwrap();
        let storage = LocalStorage::new(dir.path().to_str().unwrap());
        let m = HashMap::new();
        let a = write_manifest(&storage, &m, None, false).await.unwrap();
        let b = write_manifest(&storage, &m, None, false).await.unwrap();
        assert_ne!(a, b);
        assert_eq!(storage.list("snapshots").await.unwrap().len(), 2);
        let (latest, _) = find_latest_snapshot(&storage, None, None).await.unwrap();
        assert_eq!(latest, b, "the most recently written manifest must win");
    }

    #[test]
    fn manifest_key_uses_forward_slashes() {
        let rel: PathBuf = ["sub", "dir", "b.txt"].iter().collect();
        assert_eq!(manifest_key(&rel), PathBuf::from("sub/dir/b.txt"));
        assert_eq!(
            manifest_key(std::path::Path::new("a.txt")),
            PathBuf::from("a.txt")
        );
    }
}
