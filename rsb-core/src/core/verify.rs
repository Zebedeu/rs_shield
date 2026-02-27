use super::cancellation::CancellationToken;
use super::manifest::find_latest_snapshot;
use super::types::{FileMetadata, ProgressCallback};
use crate::config::Config;
use crate::crypto::decrypt_data;
use crate::report::ReportData;
use indicatif::{ProgressBar, ProgressStyle};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Instant;
use tracing::info;
use zstd::stream::copy_decode;

pub async fn perform_verify(
    config: &Config,
    snapshot_id: Option<&str>,
    quiet: bool,
    fast: bool,
    on_progress: Option<ProgressCallback>,
) -> Result<ReportData, Box<dyn std::error::Error>> {
    perform_verify_with_cancellation(config, snapshot_id, quiet, fast, on_progress, None).await
}

pub async fn perform_verify_with_cancellation(
    config: &Config,
    snapshot_id: Option<&str>,
    quiet: bool,
    fast: bool,
    on_progress: Option<ProgressCallback>,
    cancellation_token: Option<CancellationToken>,
) -> Result<ReportData, Box<dyn std::error::Error>> {
    let start_time = Instant::now();
    let storage = super::storage_backend::get_storage(config).await;

    let (path, content) =
        find_latest_snapshot(&*storage, snapshot_id, config.encryption_key.as_deref()).await?;
    info!("Verifying snapshot: {}", path);

    let manifest: HashMap<PathBuf, FileMetadata> = toml::from_str(&content)?;

    let pb = ProgressBar::new(manifest.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta}) {msg}")
            .unwrap()
            .progress_chars("#>-"),
    );

    let mut errors = Vec::new();
    let mut stats_missing = 0;
    let mut stats_size_error = 0;
    let mut stats_hash_error = 0;
    let mut stats_ok = 0;

    let total_files = manifest.len();
    let mut current_files = 0;

    for (rel_path, metadata) in manifest {
        // Verificar se a operação foi cancelada
        if let Some(token) = &cancellation_token {
            if token.is_cancelled() {
                info!("⏹️ Verificação cancelada pelo usuário");
                break;
            }
        }

        pb.set_message(format!("Verifying: {}", rel_path.display()));
        if let Some(cb) = &on_progress {
            cb(
                current_files,
                total_files,
                format!("Verifying: {}", rel_path.display()),
            );
        }

        if let Some(chunks) = &metadata.chunks {
            for chunk in chunks {
                let data_path = format!(
                    "data/{}/{}",
                    if metadata.encrypted { "enc" } else { "clear" },
                    chunk.hash
                );

                if !storage.exists(&data_path).await? {
                    let msg = format!("Missing chunk for {}: {}", rel_path.display(), chunk.hash);
                    errors.push(msg);
                    stats_missing += 1;
                    continue;
                }

                if fast {
                    let data = storage.read(&data_path).await?;
                    if data.len() as u64 != chunk.stored_size {
                        let msg = format!(
                            "Chunk size mismatch for {}: expected {}, got {}",
                            rel_path.display(),
                            chunk.stored_size,
                            data.len()
                        );
                        errors.push(msg);
                        stats_size_error += 1;
                    }
                    if let Some(expected) = &chunk.stored_hash {
                        let hash = crate::crypto::hash_file_content(&data)?;
                        if hash != *expected {
                            let msg = format!(
                                "Chunk stored hash mismatch for {}: expected {}, got {}",
                                rel_path.display(),
                                expected,
                                hash
                            );
                            errors.push(msg);
                            stats_hash_error += 1;
                        }
                    }
                }
            }
        } else {
            let data_path = format!(
                "data/{}/{}",
                if metadata.encrypted { "enc" } else { "clear" },
                metadata.hash
            );

            if !storage.exists(&data_path).await? {
                let msg = format!("Missing data for {}: {}", rel_path.display(), metadata.hash);
                errors.push(msg);
                stats_missing += 1;
                continue;
            }

            if fast {
                let data = storage.read(&data_path).await?;
                let size = data.len() as u64;
                let hash = crate::crypto::hash_file_content(&data)?;

                if let Some(expected_size) = metadata.stored_size {
                    if size != expected_size {
                        let msg = format!(
                            "Size mismatch for {}: expected {}, got {}",
                            rel_path.display(),
                            expected_size,
                            size
                        );
                        errors.push(msg);
                        stats_size_error += 1;
                    }
                }

                if let Some(expected_hash) = &metadata.stored_hash {
                    if &hash != expected_hash {
                        let msg = format!(
                            "Stored hash mismatch for {}: expected {}, got {}",
                            rel_path.display(),
                            expected_hash,
                            hash
                        );
                        errors.push(msg);
                        stats_hash_error += 1;
                    }
                }
            } else {
                // Full verify
                let data = storage.read(&data_path).await?;
                let decrypted = if metadata.encrypted {
                    if let Some(k) = config.encryption_key.as_deref() {
                        match decrypt_data(&data, k.as_bytes()) {
                            Ok(d) => d,
                            Err(e) => {
                                let msg =
                                    format!("Decryption failed for {}: {}", rel_path.display(), e);
                                errors.push(msg);
                                continue;
                            }
                        }
                    } else {
                        data
                    }
                } else {
                    data
                };

                let final_data = if metadata.compressed {
                    let mut decompressed = Vec::new();
                    if copy_decode(&decrypted[..], &mut decompressed).is_err() {
                        let msg = format!("Decompression failed for {}", rel_path.display());
                        errors.push(msg);
                        continue;
                    }
                    decompressed
                } else {
                    decrypted
                };

                let computed_hash = crate::crypto::hash_file_content(&final_data)?;
                if computed_hash != metadata.hash {
                    let msg = format!(
                        "Hash mismatch for {}: expected {}, got {}",
                        rel_path.display(),
                        metadata.hash,
                        computed_hash
                    );
                    errors.push(msg);
                    stats_hash_error += 1;
                } else {
                    stats_ok += 1;
                }
            }
        }

        current_files += 1;
        pb.inc(1);
    }

    pb.finish_and_clear();

    let status = if errors.is_empty() {
        "Success"
    } else {
        "Failure with errors"
    }
    .to_string();

    if !quiet {
        info!("✅ Arquivos verificados com sucesso: {}", stats_ok);
    }

    let report_data = ReportData {
        operation: "Verify".to_string(),
        profile_path: "".to_string(),
        timestamp: chrono::Local::now().to_rfc3339(),
        duration: start_time.elapsed(),
        mode: Some(if fast { "Fast (Lite)" } else { "Full" }.to_string()),
        files_processed: stats_ok,
        files_skipped: 0,
        files_with_errors: errors.len(),
        total_files,
        errors,
        status,
    };

    if !quiet {
        info!("Verification completed.");
        info!("Total files: {}", total_files);
        if fast {
            info!("- Missing: {}", stats_missing);
            info!("- Size errors: {}", stats_size_error);
            info!("- Hash errors: {}", stats_hash_error);
        }
    }

    Ok(report_data)
}
