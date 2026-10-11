// storage_backend.rs - Performance + robustness version
use crate::config::Config;
use crate::credentials::CredentialsManager;
use crate::storage::{LocalStorage, S3Storage, Storage};
use std::io::IsTerminal;
use std::sync::{Arc, RwLock};
use tracing::{error, info, warn};
use zeroize::Zeroizing;

/// S3 credentials supplied in memory by an interactive front-end (e.g. the
/// desktop app's form). Never written to disk; cleared on request.
static SESSION_S3_CREDENTIALS: RwLock<Option<(Zeroizing<String>, Zeroizing<String>)>> =
    RwLock::new(None);

/// Use these S3 credentials for this process (after env vars, before the
/// encrypted credentials file). Empty values clear them.
pub fn set_session_s3_credentials(access_key: &str, secret_key: &str) {
    let value = if access_key.trim().is_empty() || secret_key.trim().is_empty() {
        None
    } else {
        Some((
            Zeroizing::new(access_key.trim().to_string()),
            Zeroizing::new(secret_key.trim().to_string()),
        ))
    };
    if let Ok(mut slot) = SESSION_S3_CREDENTIALS.write() {
        *slot = value;
    }
}

/// Forget credentials set with [`set_session_s3_credentials`].
pub fn clear_session_s3_credentials() {
    if let Ok(mut slot) = SESSION_S3_CREDENTIALS.write() {
        *slot = None;
    }
}

/// Returns the appropriate storage backend (Local or S3).
///
/// Fails (instead of panicking) when S3 is configured but no credentials are
/// available: release builds use `panic = "abort"`, so a panic here used to
/// kill the whole desktop app.
pub async fn get_storage(config: &Config) -> Result<Arc<dyn Storage>, String> {
    // Priority: nested or flat S3 configuration (backward compatibility)
    let s3_config = config.s3.as_ref();

    let bucket = s3_config
        .and_then(|s| s.bucket.clone())
        .or_else(|| config.s3_bucket.clone());

    let region = s3_config
        .and_then(|s| s.region.clone())
        .or_else(|| config.s3_region.clone());

    let endpoint = s3_config
        .and_then(|s| s.endpoint.clone())
        .or_else(|| config.s3_endpoint.clone());

    match bucket {
        Some(bucket) if !bucket.trim().is_empty() => {
            match load_s3_credentials_securely(config).await {
                Ok(credentials) => {
                    info!(
                        "☁️  Using S3 storage → bucket: {} | region: {:?} | endpoint: {:?}",
                        bucket, region, endpoint
                    );
                    let s3 = S3Storage::new(&bucket, region, endpoint, credentials).await;
                    Ok(Arc::new(s3) as Arc<dyn Storage>)
                }
                Err(e) => {
                    error!("❌ Failed to load S3 credentials: {}", e);
                    Err(format!(
                        "S3 bucket '{}' is configured but credentials are unavailable: {}",
                        bucket, e
                    ))
                }
            }
        }
        _ => {
            info!("📁 Using Local storage → path: {}", config.destination_path);
            Ok(Arc::new(LocalStorage::new(&config.destination_path)))
        }
    }
}

/// Uses `injected` when given, otherwise builds the backend from `config`
/// with [`get_storage`]. Lets callers reuse one `Arc<dyn Storage>` across
/// operations (or inject e.g. [`crate::storage::MemoryStorage`]).
pub async fn storage_or_from_config(
    injected: Option<Arc<dyn Storage>>,
    config: &Config,
) -> Result<Arc<dyn Storage>, String> {
    match injected {
        Some(storage) => Ok(storage),
        None => get_storage(config).await,
    }
}

/// Secure and prioritized loading of S3 credentials
async fn load_s3_credentials_securely(
    config: &Config,
) -> Result<aws_credential_types::Credentials, String> {
    use std::env;

    // 1. Environment variables (faster and recommended for production/CI)
    if let (Ok(access_key), Ok(secret_key)) = (
        env::var("AWS_ACCESS_KEY_ID"),
        env::var("AWS_SECRET_ACCESS_KEY"),
    ) && !access_key.is_empty()
        && !secret_key.is_empty()
    {
        let session_token = env::var("AWS_SESSION_TOKEN").ok();
        info!("🔑 S3 credentials loaded from environment variables");
        return Ok(aws_credential_types::Credentials::new(
            access_key,
            secret_key,
            session_token,
            None,
            "rsb-env",
        ));
    }

    // 2. Credentials entered in an interactive front-end (memory only)
    if let Ok(slot) = SESSION_S3_CREDENTIALS.read()
        && let Some((ak, sk)) = slot.as_ref()
    {
        info!("🔑 S3 credentials loaded from the current session");
        return Ok(aws_credential_types::Credentials::new(
            ak.as_str(),
            sk.as_str(),
            None,
            None,
            "rsb-session",
        ));
    }

    // 3. Encrypted file (persistent)
    if let Ok(home) = env::var("HOME") {
        let cred_path = format!("{}/.rs-shield/s3_credentials.enc", home);
        if std::path::Path::new(&cred_path).exists() {
            match CredentialsManager::load_encrypted(&cred_path) {
                Ok(creds) => {
                    info!("🔑 S3 credentials loaded from encrypted file");
                    return Ok(aws_credential_types::Credentials::new(
                        creds.access_key.as_str(),
                        creds.secret_key.as_str(),
                        creds.session_token.as_ref().map(|s| s.to_string()),
                        None,
                        "rsb-encrypted",
                    ));
                }
                Err(e) => warn!("Failed to load encrypted credentials: {}", e),
            }
        }
    }

    // 4. Interactive prompt (last resort) — only with a terminal; a GUI or
    // cron job has no one to answer it.
    if !std::io::stdin().is_terminal() {
        return Err("No S3 credentials found. Provide AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY, enter them in the app, or run `rsb config s3-credentials` (encrypted).".to_string());
    }
    match CredentialsManager::prompt_for_credentials() {
        Ok(creds) => {
            info!("🔑 S3 credentials configured interactively");
            return Ok(aws_credential_types::Credentials::new(
                creds.access_key.as_str(),
                creds.secret_key.as_str(),
                creds.session_token.as_ref().map(|s| s.to_string()),
                None,
                "rsb-interactive",
            ));
        }
        Err(e) => warn!("Interactive credential prompt failed: {}", e),
    }

    // 5. Config file REMOVIDO por segurança (era plaintext sem chmod).
    // Para migração legada, o operador pode optar explicitamente com
    // RSB_ALLOW_CONFIG_CREDS=1 — e mesmo assim alertamos.
    if std::env::var("RSB_ALLOW_CONFIG_CREDS").as_deref() == Ok("1")
        && let Some(s3) = config.s3.as_ref()
        && let (Some(ak), Some(sk)) = (&s3.access_key, &s3.secret_key)
        && !ak.is_empty()
        && !sk.is_empty()
    {
        warn!(
            "⚠️ SECURITY: using S3 secrets from TOML because RSB_ALLOW_CONFIG_CREDS=1. Migrate to env/s3_credentials.enc and unset the flag."
        );
        return Ok(aws_credential_types::Credentials::new(
            ak.clone(),
            sk.clone(),
            None,
            None,
            "rsb-config-legacy-optin",
        ));
    }

    Err("No S3 credentials found. Provide AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY or run `rsb config s3-credentials` (encrypted).".to_string())
}

#[cfg(test)]
mod session_credentials_tests {
    use super::*;

    #[tokio::test]
    async fn session_credentials_are_used_and_clearable() {
        if std::env::var("AWS_ACCESS_KEY_ID").is_ok() {
            return; // env vars take precedence; nothing to assert here
        }
        let cfg = crate::portable_restore::config_for_s3_restore("bucket", None, None).unwrap();

        set_session_s3_credentials("AKIATEST", "secret-test");
        let creds = load_s3_credentials_securely(&cfg).await.unwrap();
        assert_eq!(creds.secret_access_key(), "secret-test");
        assert_eq!(creds.access_key_id(), "AKIATEST");

        // Empty values clear instead of storing blanks.
        set_session_s3_credentials("", "");
        assert!(SESSION_S3_CREDENTIALS.read().unwrap().is_none());
        clear_session_s3_credentials();
    }
}
