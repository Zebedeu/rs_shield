//! Local dedup index: a per-repository cache of data objects this machine
//! has seen in the repository (object key → stored size, time of the last
//! check), so a backup does not need one HEAD per unchanged file.
//!
//! # Safety rules
//!
//! The index is an optimisation only. A wrong entry could make a backup
//! skip an upload whose object is missing from the repository, so it is
//! trusted only when every rule below holds, and the repository is asked
//! otherwise:
//!
//! * **Identity.** The cache file is keyed by the repository id
//!   ([`REPO_ID_PATH`], created by the first backup that uses the index)
//!   *and* the storage location ([`Storage::cache_identity`]), so a copied
//!   repository or a new repository at an old location never reuses
//!   another one's cache. Storage without a location identity gets no
//!   index.
//! * **Integrity.** The file ends with a BLAKE3 checksum; a corrupt,
//!   truncated, unknown-version or foreign file is ignored (cold cache).
//! * **Destructive operations.** Prune, `verify --repair`, `key migrate`
//!   and `key rotate` change the repository epoch ([`REPO_EPOCH_PATH`])
//!   before they delete or rewrite anything; an index written under another
//!   epoch is discarded. An index also records the snapshots that existed
//!   when it was written and is discarded if any of them is gone (catches
//!   a prune by an older version that does not change the epoch).
//! * **Only verified facts.** Entries come from this machine's own HEADs and
//!   uploads, and only for objects referenced by a manifest that was then
//!   written successfully. A hit served from the index does not refresh
//!   the entry's timestamp, so an entry is never older than one check.
//! * **Age.** An entry older than [`DedupIndexOptions::max_age`] is
//!   re-checked with a HEAD.
//! * **Sampling.** One trusted hit in [`DedupIndexOptions::sample_one_in`]
//!   (random per backup) is re-checked anyway. Any HEAD that contradicts
//!   the index marks the whole index as distrusted: later lookups go to
//!   storage, every object trusted earlier in the same backup is checked
//!   again before the manifest is written (files whose object is missing
//!   are processed again without the index), and the old entries are
//!   dropped.
//! * **Fallback.** Any error while opening the index (no repository id,
//!   unreadable epoch or listing, no cache directory) disables it for the
//!   backup: dedup then works exactly as without an index.

use crate::core::types::FileMetadata;
use crate::storage::Storage;
use dashmap::DashMap;
use std::collections::{HashMap, HashSet};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::runtime::Handle;
use tracing::{debug, warn};

/// Random id of the repository (UUID, text). Created when missing.
pub const REPO_ID_PATH: &str = "meta/repo-id";
/// Changed (random value) by every operation that deletes or rewrites data
/// objects, so local dedup indexes notice.
pub const REPO_EPOCH_PATH: &str = "meta/epoch";

const FILE_MAGIC: &[u8; 8] = b"RSBDIDX1";
/// Index files not written for this long are removed from the cache dir.
const STALE_FILE_AGE: Duration = Duration::from_secs(30 * 24 * 3600);
/// Upper bound on what is read back from a cache file (≈ 10 M objects).
const MAX_FILE_LEN: u64 = 512 * 1024 * 1024;

/// Settings of the local dedup index (see the module docs).
#[derive(Debug, Clone)]
pub struct DedupIndexOptions {
    /// Use the index (default `true`).
    pub enabled: bool,
    /// Directory of the index files; `None` = `<user cache dir>/rs-shield/dedup-index`.
    pub dir: Option<PathBuf>,
    /// Entries older than this are re-checked with a HEAD (default 24 h).
    pub max_age: Duration,
    /// One trusted hit in this many is re-checked anyway (default 100;
    /// 0 disables sampling, 1 checks every hit).
    pub sample_one_in: u32,
}

impl Default for DedupIndexOptions {
    fn default() -> Self {
        Self {
            enabled: true,
            dir: None,
            max_age: Duration::from_secs(24 * 3600),
            sample_one_in: 100,
        }
    }
}

impl DedupIndexOptions {
    /// Options with the index disabled.
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            ..Self::default()
        }
    }
}

/// Reads the repository id; creates one if missing and `create` is set.
pub async fn repo_id(storage: &dyn Storage, create: bool) -> io::Result<Option<String>> {
    match storage.read(REPO_ID_PATH).await {
        Ok(raw) => {
            let id = String::from_utf8_lossy(&raw).trim().to_string();
            if id.is_empty() || id.len() > 128 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid repository id",
                ));
            }
            Ok(Some(id))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            if !create {
                return Ok(None);
            }
            // Two first backups racing may each write an id: the last one
            // wins and the other's index is simply never used again.
            let id = uuid::Uuid::new_v4().to_string();
            storage.write(REPO_ID_PATH, id.as_bytes()).await?;
            Ok(Some(id))
        }
        Err(e) => Err(e),
    }
}

async fn read_epoch(storage: &dyn Storage) -> io::Result<Option<String>> {
    match storage.read(REPO_EPOCH_PATH).await {
        Ok(raw) => Ok(Some(String::from_utf8_lossy(&raw).trim().to_string())),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Changes the repository epoch. Called (under the exclusive lock) by
/// every operation that deletes or rewrites data objects, before it does.
pub async fn bump_repo_epoch(storage: &dyn Storage) -> io::Result<()> {
    let epoch = format!(
        "{} {}",
        uuid::Uuid::new_v4().simple(),
        chrono::Utc::now().to_rfc3339()
    );
    storage.write(REPO_EPOCH_PATH, epoch.as_bytes()).await
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Entry {
    size: u64,
    verified_at: u64,
}

/// Counters of one backup's index use.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DedupIndexStats {
    /// Lookups answered by the index (no storage call).
    pub hits: u64,
    /// Lookups that went to storage.
    pub misses: u64,
    /// Trusted hits re-checked by sampling.
    pub sampled: u64,
}

/// An open dedup index (see the module docs).
pub struct DedupIndex {
    file: PathBuf,
    key: [u8; 32],
    epoch: Option<String>,
    snapshots: Vec<String>,
    entries: HashMap<String, Entry>,
    max_age_secs: u64,
    sample_one_in: u32,
    seed: [u8; 32],
    started_at: u64,
    distrusted: AtomicBool,
    /// Sizes seen by HEAD or upload during this backup (`None` = missing).
    session: DashMap<String, Option<u64>>,
    /// Objects answered from the index without a storage call.
    trusted: DashMap<String, u64>,
    hits: AtomicU64,
    misses: AtomicU64,
    sampled: AtomicU64,
}

impl DedupIndex {
    /// Opens the index of the repository behind `storage`, or returns
    /// `None` (index disabled, the caller falls back to plain storage
    /// lookups). Never fails the backup.
    pub async fn open(
        storage: &dyn Storage,
        opts: &DedupIndexOptions,
        dry_run: bool,
    ) -> Option<Self> {
        if !opts.enabled {
            return None;
        }
        let identity = storage.cache_identity()?;
        let dir = opts
            .dir
            .clone()
            .or_else(|| dirs::cache_dir().map(|d| d.join("rs-shield").join("dedup-index")))?;
        let result: io::Result<Option<Self>> = async {
            let Some(id) = repo_id(storage, !dry_run).await? else {
                return Ok(None);
            };
            let epoch = read_epoch(storage).await?;
            let mut snapshots: Vec<String> = match storage.list("snapshots").await {
                Ok(list) => list,
                Err(e) if e.kind() == io::ErrorKind::NotFound => Vec::new(),
                Err(e) => return Err(e),
            };
            snapshots.retain(|s| s.ends_with(".toml"));
            snapshots.sort();

            let mut h = blake3::Hasher::new();
            h.update(b"rsb dedup index v1\0");
            h.update(id.as_bytes());
            h.update(b"\0");
            h.update(identity.as_bytes());
            let key = *h.finalize().as_bytes();
            let file = dir.join(format!("{}.idx", hex::encode(&key[..16])));

            let mut seed = [0u8; 32];
            ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut seed)
                .map_err(|_| io::Error::other("random seed"))?;
            let mut index = Self {
                file,
                key,
                epoch,
                snapshots,
                entries: HashMap::new(),
                max_age_secs: opts.max_age.as_secs(),
                sample_one_in: opts.sample_one_in,
                seed,
                started_at: now_secs(),
                distrusted: AtomicBool::new(false),
                session: DashMap::new(),
                trusted: DashMap::new(),
                hits: AtomicU64::new(0),
                misses: AtomicU64::new(0),
                sampled: AtomicU64::new(0),
            };
            index.entries = index.load().unwrap_or_else(|why| {
                debug!("Dedup index not used ({}): {}", index.file.display(), why);
                HashMap::new()
            });
            Ok(Some(index))
        }
        .await;
        match result {
            Ok(index) => index,
            Err(e) => {
                warn!("Dedup index disabled for this backup: {}", e);
                None
            }
        }
    }

    /// Number of entries loaded from the cache file.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn stats(&self) -> DedupIndexStats {
        DedupIndexStats {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            sampled: self.sampled.load(Ordering::Relaxed),
        }
    }

    /// True once a storage check contradicted the index.
    pub fn is_distrusted(&self) -> bool {
        self.distrusted.load(Ordering::Relaxed)
    }

    fn sampled(&self, path: &str) -> bool {
        match self.sample_one_in {
            0 => false,
            1 => true,
            n => {
                let mut h = blake3::Hasher::new_keyed(&self.seed);
                h.update(path.as_bytes());
                let b = h.finalize();
                let v = u64::from_le_bytes(b.as_bytes()[..8].try_into().unwrap_or([0; 8]));
                v % n as u64 == 0
            }
        }
    }

    /// Size of the object at `path`, or `None` if it does not exist: from
    /// the index when an entry may be trusted (and matches `expected`, the
    /// stored size the caller already knows, if any), else from storage.
    pub fn size(
        &self,
        storage: &Arc<dyn Storage>,
        rt: &Handle,
        path: &str,
        expected: Option<u64>,
    ) -> io::Result<Option<u64>> {
        let entry = self.entries.get(path).copied();
        if let Some(e) = entry
            && !self.is_distrusted()
            && self.started_at.saturating_sub(e.verified_at) < self.max_age_secs
            && e.verified_at <= self.started_at
            && expected.is_none_or(|x| x == 0 || x == e.size)
        {
            if !self.sampled(path) {
                self.hits.fetch_add(1, Ordering::Relaxed);
                self.trusted.insert(path.to_string(), e.size);
                return Ok(Some(e.size));
            }
            self.sampled.fetch_add(1, Ordering::Relaxed);
        }
        self.misses.fetch_add(1, Ordering::Relaxed);
        let actual = rt.block_on(storage.size(path))?;
        if let Some(e) = entry
            && actual != Some(e.size)
        {
            warn!(
                "Dedup index entry for {} contradicted by storage ({:?} != {}); \
                 not trusting the index for the rest of this backup",
                path, actual, e.size
            );
            self.distrusted.store(true, Ordering::Relaxed);
        }
        self.session.insert(path.to_string(), actual);
        Ok(actual)
    }

    /// Records an object written by this backup.
    pub fn record_upload(&self, path: &str, size: u64) {
        self.session.insert(path.to_string(), Some(size));
    }

    /// When the index was contradicted during this backup, checks again
    /// every object it answered for, and returns those that are missing
    /// or have another size (their files must be processed again).
    pub async fn recheck_trusted(&self, storage: &dyn Storage) -> io::Result<HashSet<String>> {
        use futures_util::{StreamExt, stream};
        let mut bad = HashSet::new();
        if !self.is_distrusted() {
            return Ok(bad);
        }
        let trusted: Vec<(String, u64)> = self
            .trusted
            .iter()
            .map(|e| (e.key().clone(), *e.value()))
            .collect();
        let mut checks = stream::iter(trusted)
            .map(|(path, size)| async move {
                let actual = storage.size(&path).await;
                (path, size, actual)
            })
            .buffer_unordered(16);
        while let Some((path, size, actual)) = checks.next().await {
            let actual = actual?;
            if actual != Some(size) {
                bad.insert(path.clone());
            }
            self.session.insert(path, actual);
        }
        Ok(bad)
    }

    /// Writes the index after a successful backup whose manifest
    /// (`manifest`, stored as `snapshot`) references the objects to keep.
    pub fn save(
        &self,
        manifest: &HashMap<PathBuf, FileMetadata>,
        snapshot: &str,
    ) -> io::Result<()> {
        let now = now_secs();
        let mut entries: HashMap<String, Entry> = if self.is_distrusted() {
            HashMap::new()
        } else {
            self.entries
                .iter()
                .filter(|(_, e)| now.saturating_sub(e.verified_at) < self.max_age_secs)
                .map(|(k, e)| (k.clone(), *e))
                .collect()
        };
        for (path, size) in manifest_objects(manifest) {
            match self.session.get(&path).map(|s| *s) {
                Some(Some(seen)) if seen == size => {
                    entries.insert(
                        path,
                        Entry {
                            size,
                            verified_at: self.started_at,
                        },
                    );
                }
                Some(_) => {
                    entries.remove(&path);
                }
                None => {}
            }
        }
        for item in self.session.iter() {
            if item.value().is_none() {
                entries.remove(item.key());
            }
        }
        let mut snapshots = self.snapshots.clone();
        if !snapshots.iter().any(|s| s == snapshot) {
            snapshots.push(snapshot.to_string());
            snapshots.sort();
        }
        let bytes = encode(&self.key, self.epoch.as_deref(), &snapshots, &entries)?;
        write_atomic(&self.file, &bytes)?;
        remove_stale_files(self.file.parent(), &self.file);
        Ok(())
    }

    /// Reads the cache file; errors (missing, corrupt, other repository,
    /// other epoch, pruned snapshots) mean "start empty".
    fn load(&self) -> Result<HashMap<String, Entry>, String> {
        let meta = std::fs::metadata(&self.file).map_err(|e| e.to_string())?;
        if meta.len() > MAX_FILE_LEN {
            return Err("file too large".into());
        }
        let raw = std::fs::read(&self.file).map_err(|e| e.to_string())?;
        let decoded = decode(&raw).ok_or("corrupt or unknown format")?;
        if decoded.key != self.key {
            return Err("belongs to another repository".into());
        }
        if decoded.epoch.as_deref() != self.epoch.as_deref() {
            return Err("repository changed by prune/repair/migrate/rotate".into());
        }
        let current: HashSet<&str> = self.snapshots.iter().map(String::as_str).collect();
        if let Some(gone) = decoded
            .snapshots
            .iter()
            .find(|s| !current.contains(s.as_str()))
        {
            return Err(format!("snapshot {} was removed", gone));
        }
        Ok(decoded.entries)
    }
}

/// (object key, stored size) of every data object a manifest references
/// with a known stored size.
fn manifest_objects(manifest: &HashMap<PathBuf, FileMetadata>) -> Vec<(String, u64)> {
    let mut out = Vec::with_capacity(manifest.len());
    for meta in manifest.values() {
        let kind = if meta.encrypted { "enc" } else { "clear" };
        match &meta.chunks {
            Some(chunks) => {
                for c in chunks {
                    if c.stored_size > 0 {
                        out.push((format!("data/{}/{}", kind, c.hash), c.stored_size));
                    }
                }
            }
            None => {
                if let Some(size) = meta.stored_size.filter(|&s| s > 0) {
                    out.push((format!("data/{}/{}", kind, meta.hash), size));
                }
            }
        }
    }
    out
}

/// Object paths of a manifest entry.
pub fn entry_objects(meta: &FileMetadata) -> Vec<String> {
    let kind = if meta.encrypted { "enc" } else { "clear" };
    match &meta.chunks {
        Some(chunks) => chunks
            .iter()
            .map(|c| format!("data/{}/{}", kind, c.hash))
            .collect(),
        None => vec![format!("data/{}/{}", kind, meta.hash)],
    }
}

// ------------------------------------------------------------ file format
//
// magic "RSBDIDX1" | key (32) | epoch: u8 present + u16 len + bytes |
// snapshots: u32 count + (u16 len + bytes)* |
// entries: u64 count + (kind u8 | hash 32 | size u64 | verified_at u64)* |
// BLAKE3 of everything before (32). Integers are little-endian.

struct Decoded {
    key: [u8; 32],
    epoch: Option<String>,
    snapshots: Vec<String>,
    entries: HashMap<String, Entry>,
}

fn encode(
    key: &[u8; 32],
    epoch: Option<&str>,
    snapshots: &[String],
    entries: &HashMap<String, Entry>,
) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(64 + entries.len() * 49);
    out.extend_from_slice(FILE_MAGIC);
    out.extend_from_slice(key);
    let put_str = |out: &mut Vec<u8>, s: &str| -> io::Result<()> {
        let len = u16::try_from(s.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "string too long"))?;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(s.as_bytes());
        Ok(())
    };
    match epoch {
        Some(e) => {
            out.push(1);
            put_str(&mut out, e)?;
        }
        None => out.push(0),
    }
    out.extend_from_slice(&(snapshots.len() as u32).to_le_bytes());
    for s in snapshots {
        put_str(&mut out, s)?;
    }
    let mut packed = Vec::with_capacity(entries.len());
    for (path, e) in entries {
        if let Some((kind, hash)) = split_object_path(path) {
            packed.push((kind, hash, e));
        }
    }
    out.extend_from_slice(&(packed.len() as u64).to_le_bytes());
    for (kind, hash, e) in packed {
        out.push(kind);
        out.extend_from_slice(&hash);
        out.extend_from_slice(&e.size.to_le_bytes());
        out.extend_from_slice(&e.verified_at.to_le_bytes());
    }
    let sum = blake3::hash(&out);
    out.extend_from_slice(sum.as_bytes());
    Ok(out)
}

/// `data/<clear|enc>/<64 hex>` → (kind, hash bytes).
fn split_object_path(path: &str) -> Option<(u8, [u8; 32])> {
    let (kind, hash) = if let Some(h) = path.strip_prefix("data/clear/") {
        (0u8, h)
    } else {
        (1u8, path.strip_prefix("data/enc/")?)
    };
    crate::storage::validate_content_hash(hash).ok()?;
    let mut out = [0u8; 32];
    hex::decode_to_slice(hash, &mut out).ok()?;
    Some((kind, out))
}

fn decode(raw: &[u8]) -> Option<Decoded> {
    let body_len = raw.len().checked_sub(32)?;
    let (body, sum) = raw.split_at(body_len);
    if blake3::hash(body).as_bytes() != sum {
        return None;
    }
    let mut r = Reader(body);
    if r.take(8)? != FILE_MAGIC {
        return None;
    }
    let key: [u8; 32] = r.take(32)?.try_into().ok()?;
    let epoch = match r.u8()? {
        0 => None,
        1 => Some(r.string()?),
        _ => return None,
    };
    let n_snap = r.u32()? as usize;
    let mut snapshots = Vec::with_capacity(n_snap.min(1 << 16));
    for _ in 0..n_snap {
        snapshots.push(r.string()?);
    }
    let n = r.u64()?;
    if n > (r.0.len() / 49) as u64 {
        return None;
    }
    let mut entries = HashMap::with_capacity(n as usize);
    for _ in 0..n {
        let kind = match r.u8()? {
            0 => "clear",
            1 => "enc",
            _ => return None,
        };
        let hash = hex::encode(r.take(32)?);
        let size = r.u64()?;
        let verified_at = r.u64()?;
        entries.insert(
            format!("data/{}/{}", kind, hash),
            Entry { size, verified_at },
        );
    }
    if !r.0.is_empty() {
        return None;
    }
    Some(Decoded {
        key,
        epoch,
        snapshots,
        entries,
    })
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Some(a)
    }
    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_le_bytes(self.take(2)?.try_into().ok()?))
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }
    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }
    fn string(&mut self) -> Option<String> {
        let n = self.u16()? as usize;
        String::from_utf8(self.take(n)?.to_vec()).ok()
    }
}

/// Temp file + rename in the same directory: readers see the old or the
/// new index, never a partial one (and a partial one fails its checksum).
fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "index path has no parent"))?;
    std::fs::create_dir_all(dir)?;
    let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
    tmp.write_all(bytes)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|e| e.error)?;
    Ok(())
}

/// Removes index files of this directory not written for
/// [`STALE_FILE_AGE`] (repositories that are gone or not used any more).
fn remove_stale_files(dir: Option<&Path>, keep: &Path) {
    let Some(dir) = dir else { return };
    let Ok(read) = std::fs::read_dir(dir) else {
        return;
    };
    let now = SystemTime::now();
    for entry in read.flatten() {
        let path = entry.path();
        if path == keep || path.extension().and_then(|e| e.to_str()) != Some("idx") {
            continue;
        }
        let old = entry
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|m| now.duration_since(m).ok())
            .is_some_and(|age| age > STALE_FILE_AGE);
        if old {
            let _ = std::fs::remove_file(&path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries() -> HashMap<String, Entry> {
        let mut m = HashMap::new();
        m.insert(
            format!("data/enc/{}", "ab".repeat(32)),
            Entry {
                size: 1234,
                verified_at: 99,
            },
        );
        m.insert(
            format!("data/clear/{}", "0f".repeat(32)),
            Entry {
                size: 7,
                verified_at: 100,
            },
        );
        m
    }

    #[test]
    fn file_format_round_trips_and_rejects_corruption() {
        let key = [7u8; 32];
        let snaps = vec!["snapshots/a.toml".to_string()];
        let bytes = encode(&key, Some("e1"), &snaps, &entries()).unwrap();
        let d = decode(&bytes).unwrap();
        assert_eq!(d.key, key);
        assert_eq!(d.epoch.as_deref(), Some("e1"));
        assert_eq!(d.snapshots, snaps);
        assert_eq!(d.entries, entries());

        // Every single-byte change and every truncation is rejected.
        for i in 0..bytes.len() {
            let mut b = bytes.clone();
            b[i] ^= 0x01;
            assert!(decode(&b).is_none(), "flip at {}", i);
        }
        for n in 0..bytes.len() {
            assert!(decode(&bytes[..n]).is_none(), "truncated to {}", n);
        }
        // Paths that are not data objects are never stored.
        let mut odd = HashMap::new();
        odd.insert(
            "snapshots/x.toml".to_string(),
            Entry {
                size: 1,
                verified_at: 1,
            },
        );
        let d = decode(&encode(&key, None, &[], &odd).unwrap()).unwrap();
        assert!(d.entries.is_empty() && d.epoch.is_none());
    }

    #[test]
    fn contradiction_distrusts_the_index_and_rechecks_trusted_hits() {
        use crate::storage::MemoryStorage;
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let mem = Arc::new(MemoryStorage::new());
        let storage: Arc<dyn Storage> = mem.clone();
        let a = format!("data/clear/{}", "aa".repeat(32));
        let b = format!("data/clear/{}", "bb".repeat(32));
        let c = format!("data/clear/{}", "cc".repeat(32));
        rt.block_on(storage.write(&b, &[0u8; 99])).unwrap();
        rt.block_on(storage.write(&c, &[0u8; 30])).unwrap();
        let now = now_secs();
        let mut idx = rt
            .block_on(DedupIndex::open(
                &*mem,
                &DedupIndexOptions {
                    dir: Some(std::env::temp_dir()),
                    sample_one_in: 0,
                    ..DedupIndexOptions::default()
                },
                false,
            ))
            .unwrap_or_else(|| panic!("index"));
        // a: trusted (fresh) but missing; b: stale and contradicted by
        // storage; c: trusted and present.
        idx.entries.insert(
            a.clone(),
            Entry {
                size: 10,
                verified_at: now,
            },
        );
        idx.entries.insert(
            b.clone(),
            Entry {
                size: 20,
                verified_at: 0,
            },
        );
        idx.entries.insert(
            c.clone(),
            Entry {
                size: 30,
                verified_at: now,
            },
        );
        idx.started_at = now;
        assert_eq!(idx.size(&storage, rt.handle(), &a, None).unwrap(), Some(10));
        assert_eq!(
            idx.size(&storage, rt.handle(), &c, Some(30)).unwrap(),
            Some(30)
        );
        assert!(!idx.is_distrusted());
        // Stale entry: HEAD, which disagrees with the index.
        assert_eq!(idx.size(&storage, rt.handle(), &b, None).unwrap(), Some(99));
        assert!(idx.is_distrusted());
        // From now on nothing is trusted, even fresh entries.
        assert_eq!(idx.size(&storage, rt.handle(), &a, None).unwrap(), None);
        // Earlier trusted hits are checked again: `a` is missing.
        let bad = rt.block_on(idx.recheck_trusted(&*storage)).unwrap();
        assert_eq!(bad, HashSet::from([a.clone()]));
        assert_eq!(idx.stats().hits, 2);
    }

    #[test]
    fn sampling_extremes() {
        let mut idx_seed = [0u8; 32];
        idx_seed[0] = 1;
        let make = |n| DedupIndex {
            file: PathBuf::new(),
            key: [0; 32],
            epoch: None,
            snapshots: vec![],
            entries: HashMap::new(),
            max_age_secs: 0,
            sample_one_in: n,
            seed: idx_seed,
            started_at: 0,
            distrusted: AtomicBool::new(false),
            session: DashMap::new(),
            trusted: DashMap::new(),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            sampled: AtomicU64::new(0),
        };
        assert!(!make(0).sampled("data/enc/x"));
        assert!(make(1).sampled("data/enc/x"));
        let idx = make(10);
        let hits = (0..10_000)
            .filter(|i| idx.sampled(&format!("data/enc/{}", i)))
            .count();
        assert!((700..1300).contains(&hits), "{}", hits);
    }
}
