use crate::auth::types::AuditLogEntry;
use chrono::Utc;
use serde_json::json;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::info;

pub struct AuditLogger {
    entries: Arc<Mutex<Vec<AuditLogEntry>>>,
    file_path: Option<String>,
}

impl AuditLogger {
    pub fn new(file_path: Option<String>) -> Self {
        Self {
            entries: Arc::new(Mutex::new(Vec::new())),
            file_path,
        }
    }

    pub async fn log_auth_success(&self, user_id: &str, ip_address: &str, user_agent: &str) {
        let entry = AuditLogEntry {
            timestamp: Utc::now(),
            user_id: user_id.to_string(),
            event_type: "auth_success".to_string(),
            status: "success".to_string(),
            ip_address: ip_address.to_string(),
            user_agent: user_agent.to_string(),
            details: json!({}),
        };

        self.log_entry(entry).await;
    }

    pub async fn log_auth_failure(
        &self,
        user_id: &str,
        ip_address: &str,
        user_agent: &str,
        reason: &str,
    ) {
        let entry = AuditLogEntry {
            timestamp: Utc::now(),
            user_id: user_id.to_string(),
            event_type: "auth_failure".to_string(),
            status: "failure".to_string(),
            ip_address: ip_address.to_string(),
            user_agent: user_agent.to_string(),
            details: json!({"reason": reason}),
        };

        self.log_entry(entry).await;
    }

    pub async fn log_backup_start(&self, user_id: &str, ip_address: &str, user_agent: &str) {
        let entry = AuditLogEntry {
            timestamp: Utc::now(),
            user_id: user_id.to_string(),
            event_type: "backup_start".to_string(),
            status: "success".to_string(),
            ip_address: ip_address.to_string(),
            user_agent: user_agent.to_string(),
            details: json!({}),
        };

        self.log_entry(entry).await;
    }

    pub async fn log_backup_complete(
        &self,
        user_id: &str,
        ip_address: &str,
        user_agent: &str,
        files_count: u64,
    ) {
        let entry = AuditLogEntry {
            timestamp: Utc::now(),
            user_id: user_id.to_string(),
            event_type: "backup_complete".to_string(),
            status: "success".to_string(),
            ip_address: ip_address.to_string(),
            user_agent: user_agent.to_string(),
            details: json!({"files_count": files_count}),
        };

        self.log_entry(entry).await;
    }

    pub async fn log_credentials_unlock(&self, user_id: &str, ip_address: &str, user_agent: &str) {
        let entry = AuditLogEntry {
            timestamp: Utc::now(),
            user_id: user_id.to_string(),
            event_type: "credentials_unlock".to_string(),
            status: "success".to_string(),
            ip_address: ip_address.to_string(),
            user_agent: user_agent.to_string(),
            details: json!({}),
        };

        self.log_entry(entry).await;
    }

    pub async fn log_logout(&self, user_id: &str, ip_address: &str, user_agent: &str) {
        let entry = AuditLogEntry {
            timestamp: Utc::now(),
            user_id: user_id.to_string(),
            event_type: "logout".to_string(),
            status: "success".to_string(),
            ip_address: ip_address.to_string(),
            user_agent: user_agent.to_string(),
            details: json!({}),
        };

        self.log_entry(entry).await;
    }

    async fn log_entry(&self, entry: AuditLogEntry) {
        let mut entries = self.entries.lock().await;

        // Log via tracing — sem user_agent cru (PII fingerprintável vai só para o ficheiro).
        info!(
            event = entry.event_type,
            user = entry.user_id,
            status = entry.status,
            ip = entry.ip_address,
            "Audit event"
        );

        entries.push(entry.clone());

        // Append (nunca truncate): antes cada evento apagava o anterior.
        if let Some(path) = &self.file_path
            && let Ok(json) = serde_json::to_string(&entry)
        {
            // Garante diretório (ex.: ~/.rs-shield) fora do repo.
            if let Some(parent) = std::path::Path::new(path).parent()
                && !parent.as_os_str().is_empty()
            {
                let _ = tokio::fs::create_dir_all(parent).await;
            }
            // Redige user_agent longo para limitar PII retida (LGPD/GDPR).
            let line = format!("{}\n", json);
            use tokio::io::AsyncWriteExt;
            if let Ok(mut f) = tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .await
            {
                let _ = f.write_all(line.as_bytes()).await;
                // chmod 0600 best-effort (log contém IP/UA = dado pessoal).
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ =
                        tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                            .await;
                }
            }
        }
        // Bound em memória para não virar DoS (antes crescia sem limite).
        const MAX_IN_MEMORY: usize = 10_000;
        if entries.len() > MAX_IN_MEMORY {
            let overflow = entries.len() - MAX_IN_MEMORY;
            entries.drain(0..overflow);
        }
    }

    pub async fn get_all_entries(&self) -> Vec<AuditLogEntry> {
        self.entries.lock().await.clone()
    }

    pub async fn get_entries_for_user(&self, user_id: &str) -> Vec<AuditLogEntry> {
        self.entries
            .lock()
            .await
            .iter()
            .filter(|e| e.user_id == user_id)
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_audit_logger_records_events() {
        let logger = AuditLogger::new(None);

        logger
            .log_auth_success("user1", "127.0.0.1", "Mozilla/5.0")
            .await;

        let entries = logger.get_all_entries().await;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].event_type, "auth_success");
    }

    #[tokio::test]
    async fn test_audit_logger_filters_by_user() {
        let logger = AuditLogger::new(None);

        logger
            .log_auth_success("user1", "127.0.0.1", "Mozilla/5.0")
            .await;
        logger
            .log_auth_success("user2", "127.0.0.1", "Mozilla/5.0")
            .await;

        let user1_entries = logger.get_entries_for_user("user1").await;
        assert_eq!(user1_entries.len(), 1);
        assert_eq!(user1_entries[0].user_id, "user1");
    }
}
