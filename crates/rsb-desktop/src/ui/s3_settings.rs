//! Definições S3 partilhadas pelos ecrãs de backup, restore, verify e prune.
//!
//! Lê bucket/região/endpoint do [`AppConfig`], aplica as chaves digitadas
//! como credenciais **de sessão** (só em memória) e preenche os campos S3 do
//! [`Config`]. As chaves nunca são copiadas para o `Config` (nem, portanto,
//! para TOML ou logs): o `storage_backend` lê-as da sessão, das variáveis
//! de ambiente ou do ficheiro cifrado `~/.rs-shield/s3_credentials.enc`.

use crate::ui::app::AppConfig;
use rsb_sdk::config::{Config, S3Config};
use rsb_sdk::core::storage_backend::set_session_s3_credentials;
use rsb_sdk::credentials::credentials_manager::{CredentialsManager, S3Credentials};
use std::path::PathBuf;

/// Bucket/região/endpoint escolhidos no ecrã (vazio ⇒ `None`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct S3Settings {
    pub bucket: Option<String>,
    pub region: Option<String>,
    pub endpoint: Option<String>,
}

fn non_empty(s: String) -> Option<String> {
    if s.is_empty() { None } else { Some(s) }
}

impl S3Settings {
    pub fn from_values(bucket: String, region: String, endpoint: String) -> Self {
        Self {
            bucket: non_empty(bucket),
            region: non_empty(region),
            endpoint: non_empty(endpoint),
        }
    }

    /// Lê as definições do `AppConfig` e aplica as chaves digitadas como
    /// credenciais de sessão (se ambas estiverem preenchidas).
    pub fn from_app(app_config: &AppConfig) -> Self {
        apply_session_credentials(app_config);
        Self::from_values(
            app_config.s3_bucket(),
            app_config.s3_region(),
            app_config.s3_endpoint(),
        )
    }

    /// Há um bucket S3 configurado?
    pub fn is_enabled(&self) -> bool {
        self.bucket.is_some()
    }

    /// Bloco `[s3]` do `Config` (sem segredos).
    pub fn s3_config(&self) -> Option<S3Config> {
        self.bucket.as_ref().map(|bucket| S3Config {
            bucket: Some(bucket.clone()),
            region: self.region.clone(),
            endpoint: self.endpoint.clone(),
            access_key: None,
            secret_key: None,
        })
    }

    /// Preenche os campos S3 de `config`.
    pub fn apply_to(&self, config: &mut Config) {
        config.s3_bucket = self.bucket.clone();
        config.s3_region = self.region.clone();
        config.s3_endpoint = self.endpoint.clone();
        config.s3 = self.s3_config();
    }
}

/// Usa as chaves digitadas no ecrã como credenciais S3 desta sessão
/// (memória apenas). Não faz nada se alguma estiver vazia.
pub fn apply_session_credentials(app_config: &AppConfig) {
    let access_key = app_config.s3_access_key();
    let secret_key = app_config.s3_secret_key();
    if !access_key.is_empty() && !secret_key.is_empty() {
        set_session_s3_credentials(&access_key, &secret_key);
    }
}

/// Ação opt-in "lembrar credenciais": grava as chaves no ficheiro cifrado
/// (`~/.rs-shield/s3_credentials.enc`, password mestra no keyring) que o
/// `storage_backend` já lê, e usa-as também nesta sessão.
///
/// Bloqueante (keyring + PBKDF2): chamar fora da thread da UI.
pub fn remember_credentials(access_key: &str, secret_key: &str) -> Result<PathBuf, String> {
    let credentials = S3Credentials::from_keys(access_key, secret_key);
    credentials.validate()?;
    let path = CredentialsManager::save_default(&credentials)?;
    set_session_s3_credentials(
        credentials.access_key.as_str(),
        credentials.secret_key.as_str(),
    );
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_values_disable_s3() {
        let s = S3Settings::from_values(String::new(), String::new(), String::new());
        assert!(!s.is_enabled());
        assert!(s.s3_config().is_none());
        let mut cfg = Config::default();
        s.apply_to(&mut cfg);
        assert!(cfg.s3_bucket.is_none() && cfg.s3.is_none());
    }

    #[test]
    fn settings_fill_config_without_secrets() {
        let s = S3Settings::from_values(
            "bucket".into(),
            String::new(),
            "https://s3.example.com".into(),
        );
        assert!(s.is_enabled());
        let mut cfg = Config::default();
        s.apply_to(&mut cfg);
        assert_eq!(cfg.s3_bucket.as_deref(), Some("bucket"));
        assert_eq!(cfg.s3_region, None);
        assert_eq!(cfg.s3_endpoint.as_deref(), Some("https://s3.example.com"));
        let s3 = cfg.s3.as_ref().unwrap();
        assert_eq!(s3.bucket.as_deref(), Some("bucket"));
        assert!(s3.access_key.is_none() && s3.secret_key.is_none());
        // Nada de segredos: o perfil pode ser gravado em TOML.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.toml");
        rsb_sdk::config::write_config_secure(&path, &cfg).unwrap();
        let toml = std::fs::read_to_string(&path).unwrap();
        assert!(!toml.contains("access_key") && !toml.contains("secret_key"));
    }

    #[test]
    fn remember_rejects_invalid_keys_before_touching_keyring() {
        assert!(remember_credentials("", "").is_err());
        assert!(remember_credentials("short", "also-short").is_err());
    }
}
