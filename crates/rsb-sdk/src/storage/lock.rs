//! Repository lock shared by backup and prune.
//!
//! Model (similar to restic): every holder writes its own object
//! `locks/<uuid>.lock` and then lists `locks/`:
//! - a **shared** holder (backup) fails if any other live **exclusive** lock exists;
//! - an **exclusive** holder (prune) fails if any other live lock exists.
//!
//! If two holders race, both see each other and both back off (safe). Locks
//! carry a heartbeat timestamp (`refreshed_unix`) refreshed periodically while
//! held; a lock whose heartbeat is older than [`STALE_AFTER`] is considered
//! abandoned (crashed process) and is ignored/removed.
//!
//! This only needs `write`/`list`/`read`/`delete`, so it works on local
//! storage and on S3 alike.

use super::Storage;
use serde::{Deserialize, Serialize};
use std::io::{self, ErrorKind};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{debug, warn};

/// Directory (prefix) holding lock objects.
pub const LOCK_DIR: &str = "locks";
/// A lock whose heartbeat is older than this is treated as stale.
pub const STALE_AFTER: Duration = Duration::from_secs(30 * 60);
/// How often a held lock refreshes its heartbeat.
pub const REFRESH_EVERY: Duration = Duration::from_secs(5 * 60);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LockKind {
    /// Held by backups: many may run concurrently, but not with a prune.
    Shared,
    /// Held by prune: excludes every other holder.
    Exclusive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockInfo {
    pub id: String,
    pub kind: LockKind,
    pub operation: String,
    pub hostname: String,
    pub pid: u32,
    pub created_unix: u64,
    pub refreshed_unix: u64,
}

impl LockInfo {
    pub fn is_stale(&self, now_unix: u64) -> bool {
        now_unix.saturating_sub(self.refreshed_unix) > STALE_AFTER.as_secs()
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}

/// A held repository lock. Call [`RepoLock::release`] when done; dropping
/// it without releasing stops the heartbeat and attempts a best-effort
/// delete (the lock otherwise expires after [`STALE_AFTER`]).
pub struct RepoLock {
    storage: Arc<dyn Storage>,
    path: String,
    info: LockInfo,
    heartbeat: Option<tokio::task::JoinHandle<()>>,
    released: bool,
}

impl RepoLock {
    /// Acquire a lock of `kind` for `operation` (e.g. "backup", "prune").
    pub async fn acquire(
        storage: Arc<dyn Storage>,
        kind: LockKind,
        operation: &str,
    ) -> io::Result<RepoLock> {
        let id = uuid::Uuid::new_v4().simple().to_string();
        let now = now_unix();
        let info = LockInfo {
            id: id.clone(),
            kind,
            operation: operation.to_string(),
            hostname: hostname(),
            pid: std::process::id(),
            created_unix: now,
            refreshed_unix: now,
        };
        let path = format!("{}/{}.lock", LOCK_DIR, id);
        let body = serde_json::to_vec(&info).map_err(io::Error::other)?;
        storage.write(&path, &body).await?;

        // Check for conflicting holders *after* publishing our own lock so
        // that concurrent acquirers always see at least one another.
        let conflict = match find_conflict(&*storage, &id, kind).await {
            Ok(c) => c,
            Err(e) => {
                let _ = storage.delete(&path).await;
                return Err(e);
            }
        };
        if let Some(other) = conflict {
            let _ = storage.delete(&path).await;
            return Err(io::Error::new(
                ErrorKind::WouldBlock,
                format!(
                    "Repository is locked by another {} operation ({:?} lock, host '{}', pid {}, \
                     heartbeat {}s ago). Retry later; a lock without heartbeat for {} min is \
                     considered stale and ignored.",
                    other.operation,
                    other.kind,
                    other.hostname,
                    other.pid,
                    now_unix().saturating_sub(other.refreshed_unix),
                    STALE_AFTER.as_secs() / 60
                ),
            ));
        }

        let heartbeat = spawn_heartbeat(storage.clone(), path.clone(), info.clone());
        debug!("🔒 Acquired {:?} repository lock {}", kind, path);
        Ok(RepoLock {
            storage,
            path,
            info,
            heartbeat,
            released: false,
        })
    }

    pub fn info(&self) -> &LockInfo {
        &self.info
    }

    /// Release the lock (stop heartbeat, delete the lock object).
    pub async fn release(mut self) -> io::Result<()> {
        if let Some(h) = self.heartbeat.take() {
            h.abort();
        }
        self.released = true;
        self.storage.delete(&self.path).await
    }
}

impl Drop for RepoLock {
    fn drop(&mut self) {
        if let Some(h) = self.heartbeat.take() {
            h.abort();
        }
        if !self.released {
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                let storage = self.storage.clone();
                let path = self.path.clone();
                handle.spawn(async move {
                    let _ = storage.delete(&path).await;
                });
            }
        }
    }
}

fn spawn_heartbeat(
    storage: Arc<dyn Storage>,
    path: String,
    mut info: LockInfo,
) -> Option<tokio::task::JoinHandle<()>> {
    let handle = tokio::runtime::Handle::try_current().ok()?;
    Some(handle.spawn(async move {
        loop {
            tokio::time::sleep(REFRESH_EVERY).await;
            info.refreshed_unix = now_unix();
            match serde_json::to_vec(&info) {
                Ok(body) => {
                    if let Err(e) = storage.write(&path, &body).await {
                        warn!("Failed to refresh repository lock {}: {}", path, e);
                    }
                }
                Err(e) => warn!("Failed to serialize repository lock: {}", e),
            }
        }
    }))
}

/// Returns the first live lock (other than `own_id`) that conflicts with `kind`.
async fn find_conflict(
    storage: &dyn Storage,
    own_id: &str,
    kind: LockKind,
) -> io::Result<Option<LockInfo>> {
    let entries = match storage.list(LOCK_DIR).await {
        Ok(e) => e,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let now = now_unix();
    for entry in entries {
        if !entry.ends_with(".lock") || entry.ends_with(&format!("{}.lock", own_id)) {
            continue;
        }
        let raw = match storage.read(&entry).await {
            Ok(r) => r,
            // Released between list and read.
            Err(e) if e.kind() == ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        let other: LockInfo = match serde_json::from_slice(&raw) {
            Ok(i) => i,
            Err(_) => {
                // Unparseable lock (e.g. torn write by an older client):
                // fail closed — treat as an exclusive live lock.
                return Ok(Some(LockInfo {
                    id: entry.clone(),
                    kind: LockKind::Exclusive,
                    operation: "unknown".into(),
                    hostname: "unknown".into(),
                    pid: 0,
                    created_unix: now,
                    refreshed_unix: now,
                }));
            }
        };
        if other.is_stale(now) {
            warn!(
                "Removing stale repository lock {} ({} on host '{}', pid {})",
                entry, other.operation, other.hostname, other.pid
            );
            let _ = storage.delete(&entry).await;
            continue;
        }
        let conflicts = kind == LockKind::Exclusive || other.kind == LockKind::Exclusive;
        if conflicts {
            return Ok(Some(other));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::LocalStorage;

    fn local(dir: &tempfile::TempDir) -> Arc<dyn Storage> {
        Arc::new(LocalStorage::new(dir.path().to_str().unwrap()))
    }

    #[tokio::test]
    async fn shared_locks_coexist_but_exclude_prune() {
        let dir = tempfile::tempdir().unwrap();
        let s = local(&dir);
        let b1 = RepoLock::acquire(s.clone(), LockKind::Shared, "backup").await.unwrap();
        let b2 = RepoLock::acquire(s.clone(), LockKind::Shared, "backup").await.unwrap();
        let err = RepoLock::acquire(s.clone(), LockKind::Exclusive, "prune")
            .await
            .err()
            .expect("prune must not run while a backup holds the lock");
        assert_eq!(err.kind(), ErrorKind::WouldBlock);
        b1.release().await.unwrap();
        b2.release().await.unwrap();
        let p = RepoLock::acquire(s.clone(), LockKind::Exclusive, "prune").await.unwrap();
        assert!(
            RepoLock::acquire(s.clone(), LockKind::Shared, "backup")
                .await
                .is_err()
        );
        p.release().await.unwrap();
        assert!(s.list(LOCK_DIR).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn stale_lock_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let s = local(&dir);
        let old = now_unix() - STALE_AFTER.as_secs() - 60;
        let stale = LockInfo {
            id: "dead".into(),
            kind: LockKind::Exclusive,
            operation: "prune".into(),
            hostname: "h".into(),
            pid: 1,
            created_unix: old,
            refreshed_unix: old,
        };
        s.write("locks/dead.lock", &serde_json::to_vec(&stale).unwrap())
            .await
            .unwrap();
        let l = RepoLock::acquire(s.clone(), LockKind::Shared, "backup").await.unwrap();
        l.release().await.unwrap();
        assert!(!s.exists("locks/dead.lock").await.unwrap());
    }
}
