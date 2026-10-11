use crate::core::types::FileMetadata;
use crate::crypto::{KeyCache, RepoKey};
use crate::storage::Storage;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::debug;

/// Loads metadata from previous snapshots and indexes by file hash for deduplication
/// The hash is the content hash of the original file, used for fast deduplication
pub async fn load_previous_metadata(
    storage: &dyn Storage,
    key: Option<&KeyCache>,
) -> Result<HashMap<String, FileMetadata>, Box<dyn std::error::Error>> {
    let mut metadata_by_hash = HashMap::new();

    if let Ok((_, content)) =
        crate::core::manifest::find_latest_snapshot_cached(storage, None, key).await
        && let Ok(prev) = toml::from_str::<HashMap<PathBuf, FileMetadata>>(&content)
    {
        metadata_by_hash.reserve(prev.len());
        // Index by hash for fast O(1) deduplication lookups during backup
        for (_, meta) in prev {
            metadata_by_hash.insert(meta.hash.clone(), meta);
        }
        debug!(
            "✅ Loaded {} file hashes from previous snapshot for deduplication",
            metadata_by_hash.len()
        );
    }

    Ok(metadata_by_hash)
}

/// Repository key shared by every worker of one backup session.
///
/// The key is unlocked (or created) once per backup by
/// [`crate::crypto::keyfile::open_or_init_repo_key`]; every object gets
/// its own HKDF subkey from it, so nothing is derived per file.
pub struct CachedEncryptionKey {
    key: Option<Arc<RepoKey>>,
}

impl CachedEncryptionKey {
    /// Wraps the unlocked repository key (`None` = unencrypted backup).
    pub fn new(key: Option<Arc<RepoKey>>) -> Self {
        Self { key }
    }

    pub fn as_ref(&self) -> Option<Arc<RepoKey>> {
        self.key.clone()
    }

    pub fn is_some(&self) -> bool {
        self.key.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cached_encryption_key_none() {
        let key = CachedEncryptionKey::new(None);
        assert!(!key.is_some());
    }

    #[test]
    fn test_cached_encryption_key_some() {
        let key = CachedEncryptionKey::new(Some(Arc::new(RepoKey::generate().unwrap())));
        assert!(key.is_some());
    }
}
