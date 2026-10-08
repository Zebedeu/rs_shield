use super::key_cache::DecryptionKeyCache;
use super::manifest::{parse_snapshot_timestamp, read_manifest_cached, sort_snapshots_newest_first};
use crate::config::Config;
use crate::core::types::FileMetadata;
use crate::storage::{LockKind, RepoLock, Storage};
use std::collections::{HashMap, HashSet};
use std::io::ErrorKind;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{info, warn};

pub async fn perform_prune(
    config: &Config,
    keep_last: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let deleted = plan_prune_by_count(config, keep_last).await?;
    if deleted.is_empty() {
        info!("Nothing to prune.");
        return Ok(());
    }
    apply_prune_deletion(config, &deleted).await
}

/// Planeia sem deletar (para --dry-run / preview na UI).
pub async fn plan_prune_by_count(
    config: &Config,
    keep_last: usize,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    // Fail before touching storage: keep_last == 0 would delete everything.
    check_keep_last(keep_last)?;
    let storage = super::storage_backend::get_storage(config).await;
    let snapshots = list_snapshots(&*storage).await?;
    select_by_count(snapshots, keep_last)
}

fn check_keep_last(keep_last: usize) -> Result<(), Box<dyn std::error::Error>> {
    if keep_last == 0 {
        return Err(
            "Refusing to prune with keep_last = 0: that would delete every snapshot. \
             Use keep_last >= 1."
                .into(),
        );
    }
    Ok(())
}

/// Returns the snapshots to delete so that the newest `keep_last` remain.
pub fn select_by_count(
    mut snapshots: Vec<String>,
    keep_last: usize,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    check_keep_last(keep_last)?;
    if snapshots.len() <= keep_last {
        return Ok(vec![]);
    }
    sort_snapshots_newest_first(&mut snapshots);
    Ok(snapshots.split_off(keep_last))
}

/// Returns the snapshots older than `cutoff`, never including the newest one.
/// Snapshots whose name cannot be parsed are kept (fail-closed).
pub fn select_by_age(
    mut snapshots: Vec<String>,
    cutoff: chrono::DateTime<chrono::Utc>,
) -> Vec<String> {
    if snapshots.is_empty() {
        return vec![];
    }
    sort_snapshots_newest_first(&mut snapshots);
    snapshots
        .into_iter()
        .skip(1) // nunca apaga o mais recente (disponibilidade)
        .filter(|snap| matches!(parse_snapshot_timestamp(snap), Some(ts) if ts < cutoff))
        .collect()
}

/// Retenção por idade: mantém sempre o snapshot mais recente + os dos
/// últimos `retention_days` dias. Corrige o bug da UI que passava "dias"
/// como `keep_last` (contagem), o que deletava demais ou de menos.
pub async fn perform_prune_by_age(
    config: &Config,
    retention_days: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    let storage = super::storage_backend::get_storage(config).await;
    let snapshots = list_snapshots(&*storage).await?;
    let cutoff = chrono::Utc::now() - chrono::Duration::days(retention_days as i64);
    // Snapshot names are `%Y-%m-%dT%H%M%S[.mmm]Z` (not RFC3339); the shared
    // parser handles every format ever written. Unparseable names are kept.
    let to_delete = select_by_age(snapshots, cutoff);
    if to_delete.is_empty() {
        info!("Nothing to prune by age.");
        return Ok(());
    }
    apply_prune_deletion(config, &to_delete).await
}

async fn list_snapshots(storage: &dyn Storage) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut snapshots = storage.list("snapshots").await?;
    snapshots.retain(|s| s.ends_with(".toml"));
    Ok(snapshots)
}

async fn apply_prune_deletion(
    config: &Config,
    delete_snapshots: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    let storage = super::storage_backend::get_storage(config).await;
    prune_with_storage(storage, config.encryption_key.as_deref(), delete_snapshots).await
}

/// Deletes `delete_snapshots` and garbage-collects unreferenced data,
/// holding the exclusive repository lock so no backup can be writing data
/// objects whose manifest does not exist yet.
pub async fn prune_with_storage(
    storage: Arc<dyn Storage>,
    encryption_key: Option<&str>,
    delete_snapshots: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    let lock = RepoLock::acquire(storage.clone(), LockKind::Exclusive, "prune").await?;
    let result = prune_locked(&*storage, encryption_key, delete_snapshots).await;
    if let Err(e) = lock.release().await {
        warn!("Failed to release repository lock after prune: {}", e);
    }
    result
}

async fn prune_locked(
    storage: &dyn Storage,
    encryption_key: Option<&str>,
    delete_snapshots: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut deleted_count = 0;

    // 1) Delete the snapshot manifests first. If we crash afterwards the
    //    worst case is unreferenced data (reclaimed by the next prune), never
    //    a manifest pointing at deleted data.
    for snap in delete_snapshots {
        if !snap.starts_with("snapshots/") || !snap.ends_with(".toml") {
            warn!("Skipping unexpected snapshot path during prune: {}", snap);
            continue;
        }
        info!("Pruning snapshot: {}", snap);
        match storage.delete(snap).await {
            Ok(()) => deleted_count += 1,
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }

    // 2) Garbage-collect data not referenced by any remaining snapshot.
    let keep_snapshots = list_snapshots(storage).await?;
    if keep_snapshots.is_empty() {
        warn!("No snapshots left after prune; skipping data garbage collection.");
        info!("Prune completed. Deleted {} items.", deleted_count);
        return Ok(());
    }

    let cache = encryption_key.map(|k| DecryptionKeyCache::new(k.as_bytes()));
    let mut keep_hashes = HashSet::new();
    for snap in keep_snapshots {
        // Any unreadable manifest aborts GC (fail-closed: we cannot know
        // what it references).
        let content = read_manifest_cached(storage, &snap, cache.as_ref()).await?;
        let manifest: HashMap<PathBuf, FileMetadata> = toml::from_str(&content)?;

        for metadata in manifest.values() {
            keep_hashes.insert(metadata.hash.clone());
            if let Some(chunks) = &metadata.chunks {
                for chunk in chunks {
                    keep_hashes.insert(chunk.hash.clone());
                }
            }
        }
    }

    let mut all_data = Vec::new();
    for prefix in ["data/clear", "data/enc"] {
        match storage.list(prefix).await {
            Ok(list) => all_data.extend(list),
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }

    for data_file in all_data {
        // Sem unwrap: filename estranho/unicode não deve abortar o prune
        // no meio (deleção parcial = perda de disponibilidade).
        let fname = match PathBuf::from(&data_file).file_name() {
            Some(n) => n.to_string_lossy().to_string(),
            None => {
                warn!("Skipping odd data path during prune: {}", data_file);
                continue;
            }
        };
        if !keep_hashes.contains(&fname) {
            info!("Pruning data: {}", data_file);
            match storage.delete(&data_file).await {
                Ok(()) => deleted_count += 1,
                Err(e) if e.kind() == ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
    }

    info!("Prune completed. Deleted {} items.", deleted_count);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::types::FileMetadata;
    use crate::storage::LocalStorage;

    fn snaps(names: &[&str]) -> Vec<String> {
        names.iter().map(|n| format!("snapshots/{}.toml", n)).collect()
    }

    #[test]
    fn keep_last_zero_is_rejected() {
        let s = snaps(&["2026-01-01T000000Z", "2026-01-02T000000Z"]);
        assert!(select_by_count(s, 0).is_err());
    }

    #[test]
    fn keep_last_keeps_newest_across_name_formats() {
        let s = snaps(&[
            "2026-01-03T000000.500Z",
            "2026-01-01T000000Z",
            "2026-01-02T000000Z",
        ]);
        let del = select_by_count(s, 1).unwrap();
        assert_eq!(del.len(), 2);
        assert!(!del.contains(&"snapshots/2026-01-03T000000.500Z.toml".to_string()));
    }

    #[test]
    fn prune_by_age_matches_real_snapshot_names() {
        let now = chrono::Utc::now();
        let old = (now - chrono::Duration::days(40))
            .format(crate::core::manifest::SNAPSHOT_NAME_FORMAT_SECS)
            .to_string();
        let old_ms = (now - chrono::Duration::days(35))
            .format(crate::core::manifest::SNAPSHOT_NAME_FORMAT)
            .to_string();
        let recent = (now - chrono::Duration::days(1))
            .format(crate::core::manifest::SNAPSHOT_NAME_FORMAT_SECS)
            .to_string();
        let s = snaps(&[&old, &old_ms, &recent, "not-a-date"]);
        let cutoff = now - chrono::Duration::days(30);
        let mut del = select_by_age(s, cutoff);
        del.sort();
        let mut expected = snaps(&[&old, &old_ms]);
        expected.sort();
        assert_eq!(del, expected);
    }

    #[test]
    fn prune_by_age_never_deletes_latest() {
        let now = chrono::Utc::now();
        let old = (now - chrono::Duration::days(400))
            .format(crate::core::manifest::SNAPSHOT_NAME_FORMAT_SECS)
            .to_string();
        assert!(select_by_age(snaps(&[&old]), now).is_empty());
    }

    #[tokio::test]
    async fn prune_deletes_manifests_then_unreferenced_data_only() {
        let dir = tempfile::tempdir().unwrap();
        let storage: Arc<dyn Storage> = Arc::new(LocalStorage::new(dir.path().to_str().unwrap()));
        let keep_hash = "a".repeat(64);
        let drop_hash = "b".repeat(64);
        let mk = |h: &str| {
            let mut m = HashMap::new();
            m.insert(PathBuf::from("f"), FileMetadata::new(h.to_string(), false, false));
            toml::to_string(&m).unwrap()
        };
        storage
            .write("snapshots/2026-01-01T000000Z.toml", mk(&drop_hash).as_bytes())
            .await
            .unwrap();
        storage
            .write("snapshots/2026-01-02T000000Z.toml", mk(&keep_hash).as_bytes())
            .await
            .unwrap();
        storage.write(&format!("data/clear/{}", keep_hash), b"k").await.unwrap();
        storage.write(&format!("data/clear/{}", drop_hash), b"d").await.unwrap();

        prune_with_storage(
            storage.clone(),
            None,
            &["snapshots/2026-01-01T000000Z.toml".to_string()],
        )
        .await
        .unwrap();

        assert!(!storage.exists("snapshots/2026-01-01T000000Z.toml").await.unwrap());
        assert!(storage.exists(&format!("data/clear/{}", keep_hash)).await.unwrap());
        assert!(!storage.exists(&format!("data/clear/{}", drop_hash)).await.unwrap());
    }

    #[tokio::test]
    async fn prune_refuses_while_backup_holds_lock() {
        let dir = tempfile::tempdir().unwrap();
        let storage: Arc<dyn Storage> = Arc::new(LocalStorage::new(dir.path().to_str().unwrap()));
        let backup = RepoLock::acquire(storage.clone(), LockKind::Shared, "backup")
            .await
            .unwrap();
        assert!(prune_with_storage(storage.clone(), None, &[]).await.is_err());
        backup.release().await.unwrap();
        let prune = RepoLock::acquire(storage.clone(), LockKind::Exclusive, "prune").await;
        assert!(prune.is_ok(), "lock must be free once the backup released it");
    }
}
