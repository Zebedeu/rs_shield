//! Opções das operações de alto nível (backup, restore, verify).
//!
//! Substituem as listas longas de argumentos posicionais. Todos os campos são
//! públicos e têm valores por omissão sensatos, por isso o uso típico é:
//!
//! ```ignore
//! let opts = BackupOptions {
//!     dry_run: true,
//!     ..Default::default()
//! }
//! .with_encryption_key(Some("segredo"));
//! perform_backup(&config, opts).await?;
//! ```
//!
//! A chave de cifra é guardada num [`SecureString`] (zeroizada ao sair de
//! escopo) e nunca aparece em `Debug`.

use crate::core::cancellation::CancellationToken;
use crate::core::dedup_index::DedupIndexOptions;
use crate::core::types::ProgressCallback;
use crate::credentials::SecureString;
use crate::storage::Storage;
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;

fn secret(key: Option<&str>) -> Option<SecureString> {
    key.map(SecureString::from)
}

/// Representação segura de um campo opcional em `Debug`: nunca mostra o
/// conteúdo, só se está definido.
fn shown<T>(v: &Option<T>, set: &'static str) -> &'static str {
    if v.is_some() { set } else { "None" }
}

/// Opções de [`crate::backup::perform_backup`].
#[derive(Clone, Default)]
pub struct BackupOptions {
    /// Modo registado no relatório ("full"/"incremental"); `None` usa
    /// `config.backup_mode`.
    pub mode: Option<String>,
    /// Chave de cifra do backup.
    pub encryption_key: Option<SecureString>,
    /// Não escreve nada no repositório.
    pub dry_run: bool,
    /// Reservado (retomar backups interrompidos); atualmente sem efeito.
    pub resume: bool,
    /// Limite de threads; `None` usa `config.max_threads`/automático.
    pub max_threads: Option<usize>,
    /// Índice local de dedup (ativo por omissão): evita um HEAD por
    /// objeto já conhecido. Ver [`crate::core::dedup_index`].
    pub dedup_index: DedupIndexOptions,
    pub on_progress: Option<ProgressCallback>,
    pub cancellation_token: Option<CancellationToken>,
    /// Storage já construído (ex.: [`crate::storage::MemoryStorage`]);
    /// `None` constrói a partir do `Config` com
    /// [`crate::core::storage_backend::get_storage`].
    pub storage: Option<Arc<dyn Storage>>,
}

impl BackupOptions {
    /// Define (ou limpa, com `None`) a chave de cifra.
    pub fn with_encryption_key(mut self, key: Option<&str>) -> Self {
        self.encryption_key = secret(key);
        self
    }

    /// Chave de cifra como `&str` (uso interno das operações).
    pub fn key(&self) -> Option<&str> {
        self.encryption_key.as_ref().map(SecureString::as_str)
    }
}

impl fmt::Debug for BackupOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BackupOptions")
            .field("mode", &self.mode)
            .field(
                "encryption_key",
                &shown(&self.encryption_key, "***REDACTED***"),
            )
            .field("dry_run", &self.dry_run)
            .field("resume", &self.resume)
            .field("max_threads", &self.max_threads)
            .field("dedup_index", &self.dedup_index)
            .field("on_progress", &shown(&self.on_progress, "<callback>"))
            .field(
                "cancellation_token",
                &shown(&self.cancellation_token, "<token>"),
            )
            .field("storage", &shown(&self.storage, "<storage>"))
            .finish()
    }
}

/// Opções de [`crate::core::restore::perform_restore`] e de
/// [`crate::portable_restore::restore_from_config_or_backup`].
#[derive(Clone, Default)]
pub struct RestoreOptions {
    /// Snapshot a restaurar; `None` = o mais recente.
    pub snapshot_id: Option<String>,
    /// Diretório de destino do restore.
    pub target_path: PathBuf,
    /// Chave de cifra (necessária para backups cifrados).
    pub encryption_key: Option<SecureString>,
    /// Sobrescreve ficheiros existentes.
    pub force: bool,
    /// Restaura para `target_path/restore_<timestamp>`.
    pub versioned: bool,
    /// Ficheiros restaurados em paralelo; `None` (ou 0) usa
    /// [`crate::core::restore::default_restore_concurrency`]. A memória
    /// continua limitada por
    /// [`crate::core::restore::RESTORE_MEM_BUDGET_MIB`].
    pub concurrency: Option<usize>,
    pub on_progress: Option<ProgressCallback>,
    pub cancellation_token: Option<CancellationToken>,
    /// Storage já construído (ex.: [`crate::storage::MemoryStorage`]);
    /// `None` constrói a partir do `Config` com
    /// [`crate::core::storage_backend::get_storage`].
    pub storage: Option<Arc<dyn Storage>>,
}

impl RestoreOptions {
    /// Opções por omissão para restaurar em `target_path`.
    pub fn new(target_path: impl Into<PathBuf>) -> Self {
        Self {
            target_path: target_path.into(),
            ..Self::default()
        }
    }

    /// Define (ou limpa, com `None`) a chave de cifra.
    pub fn with_encryption_key(mut self, key: Option<&str>) -> Self {
        self.encryption_key = secret(key);
        self
    }

    /// Chave de cifra como `&str` (uso interno das operações).
    pub fn key(&self) -> Option<&str> {
        self.encryption_key.as_ref().map(SecureString::as_str)
    }
}

impl fmt::Debug for RestoreOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RestoreOptions")
            .field("snapshot_id", &self.snapshot_id)
            .field("target_path", &self.target_path)
            .field(
                "encryption_key",
                &shown(&self.encryption_key, "***REDACTED***"),
            )
            .field("force", &self.force)
            .field("versioned", &self.versioned)
            .field("concurrency", &self.concurrency)
            .field("on_progress", &shown(&self.on_progress, "<callback>"))
            .field(
                "cancellation_token",
                &shown(&self.cancellation_token, "<token>"),
            )
            .field("storage", &shown(&self.storage, "<storage>"))
            .finish()
    }
}

/// Opções de [`crate::integrity::perform_verify`].
#[derive(Clone, Default)]
pub struct VerifyOptions {
    /// Snapshot a verificar; `None` = o mais recente.
    pub snapshot_id: Option<String>,
    /// Sem resumo no log.
    pub quiet: bool,
    /// Só presença/tamanho/hash guardado (ignorado com `repair`).
    pub fast: bool,
    /// Apaga objetos comprovadamente corrompidos (implica verificação
    /// completa).
    pub repair: bool,
    /// Chave de cifra; `None` usa `config.encryption_key`.
    pub encryption_key: Option<SecureString>,
    pub on_progress: Option<ProgressCallback>,
    pub cancellation_token: Option<CancellationToken>,
    /// Storage já construído (ex.: [`crate::storage::MemoryStorage`]);
    /// `None` constrói a partir do `Config` com
    /// [`crate::core::storage_backend::get_storage`].
    pub storage: Option<Arc<dyn Storage>>,
}

impl VerifyOptions {
    /// Define (ou limpa, com `None`) a chave de cifra.
    pub fn with_encryption_key(mut self, key: Option<&str>) -> Self {
        self.encryption_key = secret(key);
        self
    }
}

impl fmt::Debug for VerifyOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifyOptions")
            .field("snapshot_id", &self.snapshot_id)
            .field("quiet", &self.quiet)
            .field("fast", &self.fast)
            .field("repair", &self.repair)
            .field(
                "encryption_key",
                &shown(&self.encryption_key, "***REDACTED***"),
            )
            .field("on_progress", &shown(&self.on_progress, "<callback>"))
            .field(
                "cancellation_token",
                &shown(&self.cancellation_token, "<token>"),
            )
            .field("storage", &shown(&self.storage, "<storage>"))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_prints_the_key() {
        let key = "super-secret-key-123";
        let b = BackupOptions::default().with_encryption_key(Some(key));
        let r = RestoreOptions::new("/tmp/x").with_encryption_key(Some(key));
        let v = VerifyOptions::default().with_encryption_key(Some(key));
        for s in [format!("{:?}", b), format!("{:?}", r), format!("{:?}", v)] {
            assert!(!s.contains(key), "key leaked in {s}");
            assert!(s.contains("REDACTED"));
        }
        assert_eq!(b.key(), Some(key));
        assert_eq!(r.key(), Some(key));
    }

    #[test]
    fn defaults_are_conservative() {
        let b = BackupOptions::default();
        assert!(!b.dry_run && b.mode.is_none() && b.encryption_key.is_none());
        let r = RestoreOptions::default();
        assert!(!r.force && !r.versioned && r.snapshot_id.is_none());
        let v = VerifyOptions::default();
        assert!(!v.fast && !v.repair && !v.quiet);
    }
}
