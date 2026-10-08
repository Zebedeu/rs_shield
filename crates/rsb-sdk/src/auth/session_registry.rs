//! Registo persistido de sessões (allowlist de JTI + revogação).
//!
//! As sessões do servidor eram apenas em memória e morriam quando o servidor
//! do login flow terminava, pelo que a CLI nunca conseguia validar o JTI.
//! Este registo é escrito pelo servidor ao emitir/revogar tokens num ficheiro
//! 0600 (`~/.rs-shield/sessions.json`) e lido localmente pela CLI.

use crate::auth::session::{InMemorySessionStore, Session, SessionStore};
use crate::auth::types::SessionClaims;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

const SESSIONS_FILE: &str = "sessions.json";
/// Limite de entradas para o ficheiro não crescer sem limite.
const MAX_ENTRIES: usize = 1000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SessionRecord {
    pub user_id: String,
    /// Unix timestamp (segundos)
    pub expires_at: i64,
    pub revoked: bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct RegistryFile {
    #[serde(default)]
    sessions: HashMap<String, SessionRecord>,
}

/// Estado de um JTI no registo persistido.
#[derive(Debug, Clone, PartialEq)]
pub enum SessionStatus {
    Active,
    Revoked,
    Expired,
    Unknown,
}

/// Registo de sessões persistido em disco.
#[derive(Clone, Debug)]
pub struct SessionRegistry {
    path: PathBuf,
    // Serializa leituras-modificações-escritas dentro do mesmo processo.
    lock: Arc<Mutex<()>>,
}

impl SessionRegistry {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            lock: Arc::new(Mutex::new(())),
        }
    }

    /// Registo no caminho por omissão `~/.rs-shield/sessions.json`.
    pub fn default_registry() -> Result<Self, String> {
        Ok(Self::new(Self::default_path()?))
    }

    pub fn default_path() -> Result<PathBuf, String> {
        Ok(crate::auth::secure_fs::rs_shield_dir()?.join(SESSIONS_FILE))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn read_file(&self) -> Result<RegistryFile, String> {
        if !self.path.exists() {
            return Ok(RegistryFile::default());
        }
        let data = std::fs::read(&self.path)
            .map_err(|e| format!("Failed to read session registry: {}", e))?;
        if data.is_empty() {
            return Ok(RegistryFile::default());
        }
        serde_json::from_slice(&data).map_err(|e| format!("Corrupted session registry: {}", e))
    }

    fn write_file(&self, file: &RegistryFile) -> Result<(), String> {
        let data = serde_json::to_vec(file)
            .map_err(|e| format!("Failed to serialize session registry: {}", e))?;
        crate::auth::secure_fs::write_private_atomic(&self.path, &data)
    }

    fn modify<F: FnOnce(&mut RegistryFile)>(&self, f: F) -> Result<(), String> {
        let _guard = self.lock.lock().unwrap_or_else(|p| p.into_inner());
        let mut file = self.read_file()?;
        f(&mut file);
        // Higiene: remover entradas expiradas e limitar o tamanho.
        let now = Utc::now().timestamp();
        file.sessions.retain(|_, r| r.expires_at > now);
        if file.sessions.len() > MAX_ENTRIES {
            let mut entries: Vec<(String, i64)> = file
                .sessions
                .iter()
                .map(|(k, r)| (k.clone(), r.expires_at))
                .collect();
            entries.sort_by_key(|(_, exp)| *exp);
            let excess = file.sessions.len() - MAX_ENTRIES;
            for (k, _) in entries.into_iter().take(excess) {
                file.sessions.remove(&k);
            }
        }
        self.write_file(&file)
    }

    /// Regista uma sessão emitida.
    pub fn record_issued(&self, jti: &str, user_id: &str, expires_at: i64) -> Result<(), String> {
        let rec = SessionRecord {
            user_id: user_id.to_string(),
            expires_at,
            revoked: false,
        };
        self.modify(|f| {
            f.sessions.insert(jti.to_string(), rec);
        })
    }

    /// Regista a sessão correspondente a claims já validadas.
    pub fn record_claims(&self, claims: &SessionClaims) -> Result<(), String> {
        self.record_issued(&claims.jti, &claims.sub, claims.exp)
    }

    /// Marca uma sessão como revogada (mantém a entrada até expirar).
    pub fn revoke(&self, jti: &str) -> Result<(), String> {
        self.modify(|f| {
            if let Some(r) = f.sessions.get_mut(jti) {
                r.revoked = true;
            }
        })
    }

    pub fn get(&self, jti: &str) -> Result<Option<SessionRecord>, String> {
        let _guard = self.lock.lock().unwrap_or_else(|p| p.into_inner());
        Ok(self.read_file()?.sessions.get(jti).cloned())
    }

    /// Estado de um JTI para um dado utilizador (fail-closed).
    pub fn status(&self, jti: &str, user_id: &str) -> Result<SessionStatus, String> {
        match self.get(jti)? {
            None => Ok(SessionStatus::Unknown),
            Some(r) if r.user_id != user_id => Ok(SessionStatus::Unknown),
            Some(r) if r.revoked => Ok(SessionStatus::Revoked),
            Some(r) if r.expires_at <= Utc::now().timestamp() => Ok(SessionStatus::Expired),
            Some(_) => Ok(SessionStatus::Active),
        }
    }
}

/// SessionStore em memória que também persiste emissão/revogação no
/// `SessionRegistry`, para que a CLI valide sessões sem o servidor ativo.
#[derive(Clone)]
pub struct PersistentSessionStore {
    inner: InMemorySessionStore,
    registry: SessionRegistry,
}

impl PersistentSessionStore {
    pub fn new(registry: SessionRegistry) -> Self {
        Self {
            inner: InMemorySessionStore::new(),
            registry,
        }
    }

    pub fn registry(&self) -> &SessionRegistry {
        &self.registry
    }
}

#[async_trait::async_trait]
impl SessionStore for PersistentSessionStore {
    async fn save(&self, session: Session) -> Result<(), String> {
        let registry = self.registry.clone();
        let (jti, user_id, exp) = (
            session.jti.clone(),
            session.user_id.clone(),
            session.expires_at.timestamp(),
        );
        // Persistir primeiro: se falhar, a sessão não é criada (fail-closed).
        tokio::task::spawn_blocking(move || registry.record_issued(&jti, &user_id, exp))
            .await
            .map_err(|e| format!("Session registry task failed: {}", e))??;
        self.inner.save(session).await
    }

    async fn get(&self, jti: &str) -> Result<Option<Session>, String> {
        let session = match self.inner.get(jti).await? {
            Some(s) => s,
            None => return Ok(None),
        };
        // Revogações feitas por outro processo (ex.: `rsb logout`) contam.
        let registry = self.registry.clone();
        let jti_owned = jti.to_string();
        let user_id = session.user_id.clone();
        let status = tokio::task::spawn_blocking(move || registry.status(&jti_owned, &user_id))
            .await
            .map_err(|e| format!("Session registry task failed: {}", e))??;
        if status == SessionStatus::Active {
            Ok(Some(session))
        } else {
            Ok(None)
        }
    }

    async fn revoke(&self, jti: &str) -> Result<(), String> {
        self.inner.revoke(jti).await?;
        let registry = self.registry.clone();
        let jti_owned = jti.to_string();
        tokio::task::spawn_blocking(move || registry.revoke(&jti_owned))
            .await
            .map_err(|e| format!("Session registry task failed: {}", e))?
    }

    async fn cleanup_expired(&self) -> Result<usize, String> {
        self.inner.cleanup_expired().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_issue_revoke_and_status() {
        let dir = tempfile::tempdir().unwrap();
        let reg = SessionRegistry::new(dir.path().join("sessions.json"));
        let exp = Utc::now().timestamp() + 600;

        assert_eq!(reg.status("j1", "alice").unwrap(), SessionStatus::Unknown);
        reg.record_issued("j1", "alice", exp).unwrap();
        assert_eq!(reg.status("j1", "alice").unwrap(), SessionStatus::Active);
        // JTI de outro utilizador não é aceite.
        assert_eq!(reg.status("j1", "bob").unwrap(), SessionStatus::Unknown);

        // Uma nova instância (outro processo) vê o mesmo estado.
        let reg2 = SessionRegistry::new(dir.path().join("sessions.json"));
        assert_eq!(reg2.status("j1", "alice").unwrap(), SessionStatus::Active);
        reg2.revoke("j1").unwrap();
        assert_eq!(reg.status("j1", "alice").unwrap(), SessionStatus::Revoked);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(reg.path()).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn test_registry_prunes_expired() {
        let dir = tempfile::tempdir().unwrap();
        let reg = SessionRegistry::new(dir.path().join("sessions.json"));
        let past = Utc::now().timestamp() - 10;
        reg.record_issued("old", "alice", past).unwrap();
        assert!(reg.get("old").unwrap().is_none());
    }
}
