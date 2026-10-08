use crate::config::Config;
use tracing::info;

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
    let storage = super::storage_backend::get_storage(config).await;
    let mut snapshots = storage.list("snapshots").await?;
    snapshots.retain(|s| s.ends_with(".toml"));

    if snapshots.len() <= keep_last {
        return Ok(vec![]);
    }
    snapshots.sort();
    let to_delete = snapshots.len() - keep_last;
    Ok(snapshots.drain(0..to_delete).collect())
}

/// Retenção por idade: mantém sempre o snapshot mais recente + os dos
/// últimos `retention_days` dias. Corrige o bug da UI que passava "dias"
/// como `keep_last` (contagem), o que deletava demais ou de menos.
pub async fn perform_prune_by_age(
    config: &Config,
    retention_days: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    let storage = super::storage_backend::get_storage(config).await;
    let mut snapshots = storage.list("snapshots").await?;
    snapshots.retain(|s| s.ends_with(".toml"));
    if snapshots.is_empty() {
        return Ok(());
    }
    snapshots.sort();
    let latest = snapshots.last().cloned();
    let cutoff = chrono::Utc::now() - chrono::Duration::days(retention_days as i64);
    let mut to_delete = Vec::new();
    for snap in &snapshots {
        if Some(snap) == latest.as_ref() {
            continue; // nunca apaga o mais recente (disponibilidade)
        }
        let fname = snap
            .rsplit('/')
            .next()
            .unwrap_or(snap)
            .trim_end_matches(".toml");
        // Filenames são RFC3339 (`2026-02-07T10:30:00Z`); se não parsear,
        // mantém por segurança (fail-closed, não deleta desconhecido).
        if let Ok(ts) = chrono::DateTime::parse_from_rfc3339(fname) {
            if ts.with_timezone(&chrono::Utc) < cutoff {
                to_delete.push(snap.clone());
            }
        }
    }
    if to_delete.is_empty() {
        info!("Nothing to prune by age.");
        return Ok(());
    }
    apply_prune_deletion(config, &to_delete).await
}

async fn apply_prune_deletion(
    config: &Config,
    delete_snapshots: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::core::types::FileMetadata;
    use std::collections::{HashMap, HashSet};
    use std::path::PathBuf;
    let storage = super::storage_backend::get_storage(config).await;
    let mut snapshots = storage.list("snapshots").await?;
    snapshots.retain(|s| s.ends_with(".toml"));
    let delete_set: HashSet<&str> = delete_snapshots.iter().map(|s| s.as_str()).collect();
    let keep_snapshots: Vec<String> = snapshots
        .into_iter()
        .filter(|s| !delete_set.contains(s.as_str()))
        .collect();

    let mut keep_hashes = HashSet::new();

    for snap in keep_snapshots {
        let content =
            super::manifest::read_manifest(&*storage, &snap, config.encryption_key.as_deref())
                .await?;
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

    let all_clear = storage.list("data/clear").await.unwrap_or_default();
    let all_enc = storage.list("data/enc").await.unwrap_or_default();
    let all_data = all_clear.into_iter().chain(all_enc);

    let mut deleted_count = 0;

    for data_file in all_data {
        // Sem unwrap: filename estranho/unicode não deve abortar o prune
        // no meio (deleção parcial = perda de disponibilidade).
        let fname = match PathBuf::from(&data_file).file_name() {
            Some(n) => n.to_string_lossy().to_string(),
            None => {
                tracing::warn!("Skipping odd data path during prune: {}", data_file);
                continue;
            }
        };
        if !keep_hashes.contains(&fname) {
            info!("Pruning data: {}", data_file);
            storage.delete(&data_file).await?;
            deleted_count += 1;
        }
    }

    for snap in delete_snapshots {
        info!("Pruning snapshot: {}", snap);
        storage.delete(&snap).await?;
        deleted_count += 1;
    }

    info!("Prune completed. Deleted {} items.", deleted_count);

    Ok(())
}
