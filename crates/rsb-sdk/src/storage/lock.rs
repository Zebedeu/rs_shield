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
//! Locks also record the holder's identity: hostname, optional machine id,
//! pid, process start time and a random holder id. When a lock was written on
//! *this* host and its process is gone (or the pid now belongs to a different
//! process, detected via the start time), the lock is reclaimed immediately
//! instead of waiting for [`STALE_AFTER`]. Locks from other hosts, and
//! old-format locks without identity fields, keep the timestamp rule.
//!
//! This only needs `write`/`list`/`read`/`delete` (no conditional writes), so
//! it works on local storage and on any S3-compatible provider alike.

use super::Storage;
use serde::{Deserialize, Serialize};
use std::io::{self, ErrorKind};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{debug, warn};

/// Directory (prefix) holding lock objects.
pub const LOCK_DIR: &str = "locks";
/// A lock whose heartbeat is older than this is treated as stale.
pub const STALE_AFTER: Duration = Duration::from_secs(30 * 60);
/// How often a held lock refreshes its heartbeat.
pub const REFRESH_EVERY: Duration = Duration::from_secs(5 * 60);
/// Tolerance when comparing process start times (seconds).
const START_TIME_TOLERANCE_SECS: u64 = 1;
/// Hostnames too generic to identify a machine: never trusted as "this host".
const AMBIGUOUS_HOSTNAMES: &[&str] = &["", "unknown", "localhost", "localhost.localdomain"];

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
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub pid: u32,
    pub created_unix: u64,
    pub refreshed_unix: u64,
    /// Start time (unix seconds) of the holder process, to defeat pid reuse.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_start_unix: Option<u64>,
    /// Random id of the holder process (stable for the process lifetime).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder_id: Option<String>,
    /// Best-effort machine id (`/etc/machine-id`); disambiguates machines or
    /// containers that share a hostname.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine_id: Option<String>,
}

/// Whether a lock must be honoured, and if not, why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockLiveness {
    /// The lock must be honoured.
    Live,
    /// Heartbeat older than [`STALE_AFTER`].
    StaleHeartbeat,
    /// Written on this host by a process that no longer exists.
    HolderDead,
    /// Written on this host, but the pid now belongs to another process.
    PidReused,
}

impl LockLiveness {
    pub fn is_stale(self) -> bool {
        self != LockLiveness::Live
    }
}

/// Identity of the machine evaluating a lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostIdentity {
    pub hostname: String,
    pub machine_id: Option<String>,
}

impl HostIdentity {
    /// The identity of the current machine (computed once).
    pub fn current() -> &'static HostIdentity {
        static HOST: OnceLock<HostIdentity> = OnceLock::new();
        HOST.get_or_init(|| HostIdentity {
            hostname: hostname(),
            machine_id: machine_id(),
        })
    }

    /// True when `info` was written on this machine and the hostname is
    /// specific enough to trust a local process lookup.
    pub fn is_same_host(&self, info: &LockInfo) -> bool {
        let generic = |h: &str| {
            AMBIGUOUS_HOSTNAMES
                .iter()
                .any(|a| a.eq_ignore_ascii_case(h.trim()))
        };
        !generic(&self.hostname)
            && self.hostname == info.hostname
            && self.machine_id == info.machine_id
    }
}

/// What a local process lookup found for a pid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    /// No such process (or a zombie).
    NotRunning,
    /// Running; start time in unix seconds when readable. It is `None` when
    /// the OS hides it (e.g. another user's process on macOS), in which case
    /// pid reuse cannot be ruled out and the lock is conservatively honoured.
    Running { start_unix: Option<u64> },
}

/// Looks up local processes. Abstracted for tests and fuzzing.
pub trait ProcessProbe: Send + Sync {
    fn state(&self, pid: u32) -> ProcessState;
}

/// [`ProcessProbe`] backed by `sysinfo`.
pub struct SysinfoProbe;

impl ProcessProbe for SysinfoProbe {
    fn state(&self, pid: u32) -> ProcessState {
        use sysinfo::{Pid, ProcessRefreshKind, ProcessStatus, ProcessesToUpdate, System};
        let pid = Pid::from_u32(pid);
        let mut sys = System::new();
        sys.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[pid]),
            true,
            ProcessRefreshKind::nothing(),
        );
        match sys.process(pid) {
            None => ProcessState::NotRunning,
            Some(p) if matches!(p.status(), ProcessStatus::Zombie | ProcessStatus::Dead) => {
                ProcessState::NotRunning
            }
            // sysinfo reports 0 when the start time is not readable.
            Some(p) => ProcessState::Running {
                start_unix: Some(p.start_time()).filter(|&t| t != 0),
            },
        }
    }
}

impl LockInfo {
    /// Timestamp-only staleness (the rule used for other hosts).
    pub fn is_stale(&self, now_unix: u64) -> bool {
        now_unix.saturating_sub(self.refreshed_unix) > STALE_AFTER.as_secs()
    }

    /// Full staleness decision: heartbeat age, plus holder liveness when the
    /// lock was written on this host by a client that recorded its identity.
    pub fn liveness(
        &self,
        now_unix: u64,
        host: &HostIdentity,
        probe: &dyn ProcessProbe,
    ) -> LockLiveness {
        if self.is_stale(now_unix) {
            return LockLiveness::StaleHeartbeat;
        }
        // Old-format locks (no start time) and other hosts: timestamp only.
        let Some(start) = self.process_start_unix else {
            return LockLiveness::Live;
        };
        if self.pid == 0 || !host.is_same_host(self) {
            return LockLiveness::Live;
        }
        match probe.state(self.pid) {
            ProcessState::NotRunning => LockLiveness::HolderDead,
            ProcessState::Running {
                start_unix: Some(actual),
            } if actual.abs_diff(start) > START_TIME_TOLERANCE_SECS => LockLiveness::PidReused,
            ProcessState::Running { .. } => LockLiveness::Live,
        }
    }

    /// Human-readable description of the holder, for error messages.
    pub fn holder_description(&self, now_unix: u64) -> String {
        let mut s = format!(
            "{} operation ({:?} lock, host '{}', pid {}",
            self.operation, self.kind, self.hostname, self.pid
        );
        if let Some(h) = &self.holder_id {
            s.push_str(&format!(", holder {}", h));
        }
        if let Some(start) = self.process_start_unix {
            s.push_str(&format!(", process started at unix {}", start));
        }
        s.push_str(&format!(
            ", created {}s ago, heartbeat {}s ago, lock {})",
            now_unix.saturating_sub(self.created_unix),
            now_unix.saturating_sub(self.refreshed_unix),
            self.id
        ));
        s
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn hostname() -> String {
    sysinfo::System::host_name()
        .filter(|h| !h.trim().is_empty())
        .or_else(|| std::env::var("HOSTNAME").ok())
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        .unwrap_or_else(|| "unknown".to_string())
}

fn machine_id() -> Option<String> {
    ["/etc/machine-id", "/var/lib/dbus/machine-id"]
        .iter()
        .find_map(|p| std::fs::read_to_string(p).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && s.len() <= 128)
}

/// Random id identifying this process as a lock holder.
fn holder_id() -> &'static str {
    static ID: OnceLock<String> = OnceLock::new();
    ID.get_or_init(|| uuid::Uuid::new_v4().simple().to_string())
}

/// Start time of the current process, as seen by `sysinfo`.
fn own_start_time() -> Option<u64> {
    static START: OnceLock<Option<u64>> = OnceLock::new();
    *START.get_or_init(|| match SysinfoProbe.state(std::process::id()) {
        ProcessState::Running { start_unix } => start_unix,
        ProcessState::NotRunning => None,
    })
}

/// A held repository lock. Call [`RepoLock::release`] when done; dropping
/// it without releasing stops the heartbeat and attempts a best-effort
/// delete (the lock otherwise expires after [`STALE_AFTER`], or as soon as
/// another process on the same host notices this process is gone).
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
        let host = HostIdentity::current();
        let info = LockInfo {
            id: id.clone(),
            kind,
            operation: operation.to_string(),
            hostname: host.hostname.clone(),
            pid: std::process::id(),
            created_unix: now,
            refreshed_unix: now,
            process_start_unix: own_start_time(),
            holder_id: Some(holder_id().to_string()),
            machine_id: host.machine_id.clone(),
        };
        let path = format!("{}/{}.lock", LOCK_DIR, id);
        let body = serde_json::to_vec(&info).map_err(io::Error::other)?;
        storage.write(&path, &body).await?;

        // Check for conflicting holders *after* publishing our own lock so
        // that concurrent acquirers always see at least one another.
        let conflict = match find_conflict(&*storage, &id, kind, host, &SysinfoProbe).await {
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
                    "Repository is locked by another {}. Retry later; a lock whose process is \
                     gone (same host) or without heartbeat for {} min is considered stale and \
                     ignored.",
                    other.holder_description(now_unix()),
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
        if !self.released
            && let Ok(handle) = tokio::runtime::Handle::try_current()
        {
            let storage = self.storage.clone();
            let path = self.path.clone();
            handle.spawn(async move {
                let _ = storage.delete(&path).await;
            });
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

/// Parses a lock object. Unparseable locks (e.g. a torn write by an older
/// client) fail closed: they are reported as a live exclusive lock.
pub fn parse_lock(entry: &str, raw: &[u8], now_unix: u64) -> LockInfo {
    serde_json::from_slice(raw).unwrap_or_else(|_| LockInfo {
        id: entry.to_string(),
        kind: LockKind::Exclusive,
        operation: "unknown".into(),
        hostname: "unknown".into(),
        pid: 0,
        created_unix: now_unix,
        refreshed_unix: now_unix,
        process_start_unix: None,
        holder_id: None,
        machine_id: None,
    })
}

/// Returns the first live lock (other than `own_id`) that conflicts with `kind`.
async fn find_conflict(
    storage: &dyn Storage,
    own_id: &str,
    kind: LockKind,
    host: &HostIdentity,
    probe: &dyn ProcessProbe,
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
        let other = parse_lock(&entry, &raw, now);
        let liveness = other.liveness(now, host, probe);
        if liveness.is_stale() {
            warn!(
                "Removing stale repository lock {} ({:?}: {} on host '{}', pid {})",
                entry, liveness, other.operation, other.hostname, other.pid
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

    fn lock(hostname: &str, pid: u32, start: Option<u64>, refreshed: u64) -> LockInfo {
        LockInfo {
            id: "other".into(),
            kind: LockKind::Exclusive,
            operation: "prune".into(),
            hostname: hostname.into(),
            pid,
            created_unix: refreshed,
            refreshed_unix: refreshed,
            process_start_unix: start,
            holder_id: Some("h0".into()),
            machine_id: HostIdentity::current().machine_id.clone(),
        }
    }

    async fn put(s: &Arc<dyn Storage>, name: &str, info: &LockInfo) {
        s.write(
            &format!("{}/{}.lock", LOCK_DIR, name),
            &serde_json::to_vec(info).unwrap(),
        )
        .await
        .unwrap();
    }

    /// Pid of a child process that has exited and been reaped.
    fn dead_pid() -> u32 {
        let mut child = std::process::Command::new(if cfg!(windows) { "cmd" } else { "true" })
            .args(if cfg!(windows) {
                &["/C", "exit"][..]
            } else {
                &[][..]
            })
            .spawn()
            .unwrap();
        let pid = child.id();
        child.wait().unwrap();
        pid
    }

    /// `None` = not running, `Some(None)` = running with hidden start time.
    struct FakeProbe(Option<Option<u64>>);
    impl ProcessProbe for FakeProbe {
        fn state(&self, _pid: u32) -> ProcessState {
            match self.0 {
                None => ProcessState::NotRunning,
                Some(start_unix) => ProcessState::Running { start_unix },
            }
        }
    }

    fn host(name: &str) -> HostIdentity {
        HostIdentity {
            hostname: name.into(),
            machine_id: None,
        }
    }

    #[tokio::test]
    async fn shared_locks_coexist_but_exclude_prune() {
        let dir = tempfile::tempdir().unwrap();
        let s = local(&dir);
        let b1 = RepoLock::acquire(s.clone(), LockKind::Shared, "backup")
            .await
            .unwrap();
        let b2 = RepoLock::acquire(s.clone(), LockKind::Shared, "backup")
            .await
            .unwrap();
        let err = RepoLock::acquire(s.clone(), LockKind::Exclusive, "prune")
            .await
            .err()
            .expect("prune must not run while a backup holds the lock");
        assert_eq!(err.kind(), ErrorKind::WouldBlock);
        b1.release().await.unwrap();
        b2.release().await.unwrap();
        let p = RepoLock::acquire(s.clone(), LockKind::Exclusive, "prune")
            .await
            .unwrap();
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
        put(&s, "dead", &lock("h", 1, None, old)).await;
        let l = RepoLock::acquire(s.clone(), LockKind::Shared, "backup")
            .await
            .unwrap();
        l.release().await.unwrap();
        assert!(!s.exists("locks/dead.lock").await.unwrap());
    }

    #[tokio::test]
    async fn dead_pid_same_host_lock_is_reclaimed_immediately() {
        let dir = tempfile::tempdir().unwrap();
        let s = local(&dir);
        let me = HostIdentity::current();
        if me.is_same_host(&lock(&me.hostname, 1, None, 0)) {
            let fresh = lock(&me.hostname, dead_pid(), Some(now_unix() - 10), now_unix());
            put(&s, "crashed", &fresh).await;
            let l = RepoLock::acquire(s.clone(), LockKind::Exclusive, "prune")
                .await
                .expect("lock of a dead local process must be reclaimed");
            l.release().await.unwrap();
            assert!(!s.exists("locks/crashed.lock").await.unwrap());
        }
    }

    #[tokio::test]
    async fn live_same_host_lock_is_honoured() {
        let dir = tempfile::tempdir().unwrap();
        let s = local(&dir);
        let me = HostIdentity::current();
        let Some(start) = own_start_time() else {
            return;
        };
        put(
            &s,
            "live",
            &lock(&me.hostname, std::process::id(), Some(start), now_unix()),
        )
        .await;
        let err = RepoLock::acquire(s.clone(), LockKind::Shared, "backup")
            .await
            .err()
            .expect("live local holder must be honoured");
        assert_eq!(err.kind(), ErrorKind::WouldBlock);
        let msg = err.to_string();
        assert!(msg.contains("holder h0"), "{msg}");
        assert!(
            msg.contains(&format!("pid {}", std::process::id())),
            "{msg}"
        );
        assert!(s.exists("locks/live.lock").await.unwrap());
    }

    #[tokio::test]
    async fn pid_reuse_same_host_is_stale() {
        let dir = tempfile::tempdir().unwrap();
        let s = local(&dir);
        let me = HostIdentity::current();
        let Some(start) = own_start_time() else {
            return;
        };
        if !me.is_same_host(&lock(&me.hostname, 1, None, 0)) {
            return;
        }
        // Our pid, but recorded with a start time of a different process.
        put(
            &s,
            "reused",
            &lock(
                &me.hostname,
                std::process::id(),
                Some(start - 3600),
                now_unix(),
            ),
        )
        .await;
        let l = RepoLock::acquire(s.clone(), LockKind::Exclusive, "prune")
            .await
            .expect("lock whose pid was reused must be reclaimed");
        l.release().await.unwrap();
        assert!(!s.exists("locks/reused.lock").await.unwrap());
    }

    #[tokio::test]
    async fn other_host_lock_uses_timestamp_rule() {
        let dir = tempfile::tempdir().unwrap();
        let s = local(&dir);
        let now = now_unix();
        put(
            &s,
            "remote",
            &lock("some-other-host.example", dead_pid(), Some(now - 10), now),
        )
        .await;
        assert!(
            RepoLock::acquire(s.clone(), LockKind::Exclusive, "prune")
                .await
                .is_err(),
            "a fresh lock from another host must be honoured even if the pid is unknown here"
        );
        let old = now - STALE_AFTER.as_secs() - 1;
        put(
            &s,
            "remote",
            &lock("some-other-host.example", 1, Some(old), old),
        )
        .await;
        RepoLock::acquire(s.clone(), LockKind::Exclusive, "prune")
            .await
            .unwrap()
            .release()
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn old_format_lock_parses_and_uses_timestamp_rule() {
        let dir = tempfile::tempdir().unwrap();
        let s = local(&dir);
        let me = HostIdentity::current();
        let now = now_unix();
        // Lock written by a previous version: no identity fields. Even with
        // our hostname and a dead pid it must be honoured until it expires.
        let old_json = format!(
            r#"{{"id":"x","kind":"exclusive","operation":"prune","hostname":"{}","pid":{},"created_unix":{now},"refreshed_unix":{now}}}"#,
            me.hostname,
            dead_pid()
        );
        let parsed = parse_lock("locks/old.lock", old_json.as_bytes(), now);
        assert_eq!(parsed.operation, "prune");
        assert_eq!(parsed.process_start_unix, None);
        assert_eq!(parsed.holder_id, None);
        s.write("locks/old.lock", old_json.as_bytes())
            .await
            .unwrap();
        assert!(
            RepoLock::acquire(s.clone(), LockKind::Shared, "backup")
                .await
                .is_err()
        );
        // Even older: no hostname/pid at all.
        let minimal = br#"{"id":"y","kind":"shared","operation":"backup","created_unix":1,"refreshed_unix":1}"#;
        let p = parse_lock("locks/min.lock", minimal, now);
        assert_eq!(p.kind, LockKind::Shared);
        assert_eq!(p.pid, 0);
        assert!(p.liveness(now, me, &SysinfoProbe).is_stale());
    }

    #[test]
    fn liveness_decision_table() {
        let now = 10_000;
        let h = host("box1");
        let mut l = lock("box1", 42, Some(500), now);
        l.machine_id = None;
        assert_eq!(
            l.liveness(now, &h, &FakeProbe(None)),
            LockLiveness::HolderDead
        );
        let running = |t| FakeProbe(Some(Some(t)));
        assert_eq!(l.liveness(now, &h, &running(500)), LockLiveness::Live);
        assert_eq!(l.liveness(now, &h, &running(501)), LockLiveness::Live);
        assert_eq!(l.liveness(now, &h, &running(900)), LockLiveness::PidReused);
        // Running but start time hidden (other user's process): honour it.
        assert_eq!(
            l.liveness(now, &h, &FakeProbe(Some(None))),
            LockLiveness::Live
        );
        // Other host / ambiguous hostname / other machine id: probe ignored.
        assert_eq!(
            l.liveness(now, &host("box2"), &FakeProbe(None)),
            LockLiveness::Live
        );
        let mut u = l.clone();
        u.hostname = "localhost".into();
        assert_eq!(
            u.liveness(now, &host("localhost"), &FakeProbe(None)),
            LockLiveness::Live
        );
        let mut m = l.clone();
        m.machine_id = Some("container".into());
        assert_eq!(m.liveness(now, &h, &FakeProbe(None)), LockLiveness::Live);
        // Old format: timestamp only.
        let mut o = l.clone();
        o.process_start_unix = None;
        assert_eq!(o.liveness(now, &h, &FakeProbe(None)), LockLiveness::Live);
        assert_eq!(
            o.liveness(now + STALE_AFTER.as_secs() + 1, &h, &FakeProbe(None)),
            LockLiveness::StaleHeartbeat
        );
    }

    #[test]
    fn unparseable_lock_fails_closed() {
        let l = parse_lock("locks/x.lock", b"{not json", 5);
        assert_eq!(l.kind, LockKind::Exclusive);
        assert!(
            !l.liveness(5, HostIdentity::current(), &SysinfoProbe)
                .is_stale()
        );
    }
}
