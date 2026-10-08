pub mod lock;

use async_trait::async_trait;
use aws_config::BehaviorVersion;
use aws_credential_types::Credentials;
use aws_sdk_s3::Client;
use aws_sdk_s3::config::Region;
use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::io::AsyncWriteExt;

pub use lock::{LockKind, RepoLock};

#[async_trait]
pub trait Storage: Send + Sync {
    async fn write(&self, path: &str, data: &[u8]) -> io::Result<()>;
    async fn read(&self, path: &str) -> io::Result<Vec<u8>>;
    async fn exists(&self, path: &str) -> io::Result<bool>;
    async fn list(&self, prefix: &str) -> io::Result<Vec<String>>;
    async fn delete(&self, path: &str) -> io::Result<()>;

    /// Size in bytes of a stored object, or `None` if it does not exist.
    ///
    /// Used by dedup to reject obviously truncated objects without
    /// downloading them. The default implementation reads the object; real
    /// backends override it with a metadata call.
    async fn size(&self, path: &str) -> io::Result<Option<u64>> {
        if !self.exists(path).await? {
            return Ok(None);
        }
        Ok(Some(self.read(path).await?.len() as u64))
    }
}

#[derive(Clone, Debug)]
pub struct LocalStorage {
    base_path: PathBuf,
}

impl LocalStorage {
    pub fn new(path: &str) -> Self {
        Self {
            base_path: PathBuf::from(path),
        }
    }

    /// Fail-closed join: rejeita paths absolutos, `..` e separadores que
    /// escapem de `base_path`. Retorna o path contido ou erro.
    fn safe_join(&self, rel: &str) -> io::Result<PathBuf> {
        validate_storage_path(rel)?;
        Ok(self.base_path.join(rel))
    }
}

/// Valida um path relativo de storage/restore.
///
/// Rejeita: vazio, absoluto, `..`, backslash (Windows escape), NUL,
/// e qualquer componente `ParentDir`/`RootDir`/`Prefix`.
pub fn validate_storage_path(rel: &str) -> io::Result<()> {
    use std::path::Component;
    if rel.is_empty() {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "Empty storage path",
        ));
    }
    if rel.contains('\0') || rel.contains('\\') {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "Invalid characters in storage path",
        ));
    }
    let p = PathBuf::from(rel);
    if p.is_absolute() {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "Absolute paths are not allowed in storage/restore",
        ));
    }
    for comp in p.components() {
        match comp {
            Component::Normal(_) => {}
            _ => {
                return Err(io::Error::new(
                    ErrorKind::InvalidInput,
                    "Path traversal detected (.. or root/prefix not allowed)",
                ));
            }
        }
    }
    Ok(())
}

/// Valida hash de conteúdo (hex minúsculo, 64 chars BLAKE3) para impedir
/// `../` via `metadata.hash` em `data/<enc|clear>/<hash>`.
pub fn validate_content_hash(hash: &str) -> io::Result<()> {
    if hash.len() != 64
        || !hash
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        // Aceita também maiúsculas? Não — normaliza para minúsculas na escrita,
        // rejeita o resto para não virar vetor de traversal.
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "Invalid content hash (expected 64 lowercase hex chars)",
        ));
    }
    Ok(())
}

/// Returns true when `endpoint` parses as a URL whose host is exactly a
/// loopback address (`localhost`, `127.0.0.0/8`, `::1`).
///
/// Uses a real URL parser so that `http://localhost.evil.com`,
/// `http://evil.com/?x=127.0.0.1` or `http://localhost@evil.com` are NOT
/// treated as loopback.
pub fn is_loopback_endpoint(endpoint: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(endpoint.trim()) else {
        return false;
    };
    let Some(host) = url.host_str() else {
        return false;
    };
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    bare.parse::<std::net::IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

/// Returns true when `endpoint` uses plain http to a non-loopback host.
pub fn is_insecure_remote_endpoint(endpoint: &str) -> bool {
    endpoint.trim().to_lowercase().starts_with("http://") && !is_loopback_endpoint(endpoint)
}

/// Atomically and durably writes `data` to `path`:
/// temp file in the same directory → `sync_all` → `rename` → fsync(dir).
///
/// A crash at any point leaves either the old object or the complete new
/// one, never a truncated file (which dedup would otherwise trust forever).
/// Parent directories are created with plain `create_dir_all` (no `~`/`$VAR`
/// expansion).
pub async fn atomic_write_file(path: &Path, data: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).await?;

    let file_name = path
        .file_name()
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidInput, "Path has no file name"))?
        .to_string_lossy()
        .to_string();
    let tmp_path = parent.join(format!(
        ".{}{}{}",
        file_name,
        TMP_MARKER,
        uuid::Uuid::new_v4().simple()
    ));

    let result = async {
        // create_new => O_CREAT|O_EXCL: never follows a pre-planted symlink.
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)
            .await?;
        file.write_all(data).await?;
        file.flush().await?;
        file.sync_all().await?;
        drop(file);
        fs::rename(&tmp_path, path).await?;
        sync_dir(parent).await
    }
    .await;

    if result.is_err() {
        let _ = fs::remove_file(&tmp_path).await;
    }
    result
}

/// Marker used in temp file names produced by [`atomic_write_file`].
pub const TMP_MARKER: &str = ".rsb-tmp-";

/// fsync a directory so a preceding rename/create is durable (no-op off unix).
pub async fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        let d = fs::File::open(dir).await?;
        d.sync_all().await?;
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
    Ok(())
}

#[async_trait]
impl Storage for LocalStorage {
    async fn write(&self, path: &str, data: &[u8]) -> io::Result<()> {
        let full_path = self.safe_join(path)?;
        // Atomic (tmp + fsync + rename + fsync dir): a crash never leaves a
        // truncated `data/<kind>/<hash>` that dedup would trust forever.
        atomic_write_file(&full_path, data).await
    }

    async fn read(&self, path: &str) -> io::Result<Vec<u8>> {
        let full_path = self.safe_join(path)?;
        fs::read(full_path).await
    }

    async fn exists(&self, path: &str) -> io::Result<bool> {
        let full_path = self.safe_join(path)?;
        Ok(full_path.exists())
    }

    async fn list(&self, prefix: &str) -> io::Result<Vec<String>> {
        let prefix = prefix.trim_end_matches('/');
        validate_storage_path(prefix)?;
        let dir = self.base_path.join(prefix);
        let mut results = Vec::new();

        if !dir.exists() {
            // 🐛 Fix: Return informative error instead of silent empty list
            // This helps users diagnose backup corruption or incomplete copies
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "Backup structure incomplete: '{}' directory not found. \
                    This may indicate a corrupted backup or incomplete copy. \
                    Check that the entire backup folder was copied.",
                    prefix
                ),
            ));
        }

        let mut entries = fs::read_dir(dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            if let Ok(file_name) = entry.file_name().into_string() {
                // Leftovers of an interrupted atomic write are not objects.
                if file_name.starts_with('.') && file_name.contains(TMP_MARKER) {
                    continue;
                }
                // Returns the full relative path, e.g., "snapshots/snapshot1.toml"
                let relative = format!("{}/{}", prefix, file_name);
                results.push(relative);
            }
        }
        Ok(results)
    }

    async fn delete(&self, path: &str) -> io::Result<()> {
        let full_path = self.safe_join(path)?;
        fs::remove_file(full_path).await
    }

    async fn size(&self, path: &str) -> io::Result<Option<u64>> {
        let full_path = self.safe_join(path)?;
        match fs::metadata(full_path).await {
            Ok(m) if m.is_file() => Ok(Some(m.len())),
            Ok(_) => Ok(None),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }
}

pub struct S3Storage {
    client: Client,
    bucket: String,
}

impl S3Storage {
    /// Create S3 storage with explicitly provided credentials
    /// This avoids any side effects from environment variables
    pub async fn new(
        bucket: &str,
        region: Option<String>,
        endpoint: Option<String>,
        credentials: Credentials,
    ) -> Self {
        let mut config_loader = aws_config::defaults(BehaviorVersion::latest());

        if let Some(r) = region {
            config_loader = config_loader.region(Region::new(r));
        }

        let force_path_style = endpoint.is_some();
        if let Some(e) = endpoint {
            // Mesma política do s3_check: http só em loopback, senão warn alto.
            if is_insecure_remote_endpoint(&e) {
                tracing::warn!(
                    "Insecure S3 endpoint '{}': credentials would go in cleartext. Use https://.",
                    e
                );
            }
            config_loader = config_loader.endpoint_url(e);
        }

        let sdk_config = config_loader.credentials_provider(credentials).load().await;

        // S3-specific configuration
        let s3_config = aws_sdk_s3::config::Builder::from(&sdk_config)
            // Force Path Style (e.g., domain.com/bucket) if a custom endpoint is used.
            // Essential for MinIO, Localstack, and some S3-compatible providers.
            .force_path_style(force_path_style)
            .build();

        let client = Client::from_conf(s3_config);

        Self {
            client,
            bucket: bucket.to_string(),
        }
    }
}

#[async_trait]
impl Storage for S3Storage {
    async fn write(&self, path: &str, data: &[u8]) -> io::Result<()> {
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(path)
            .body(data.to_vec().into())
            .send()
            .await
            .map_err(|e| io::Error::other(format!("S3 Upload Error: {}", e)))?;
        Ok(())
    }

    async fn read(&self, path: &str) -> io::Result<Vec<u8>> {
        let resp = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(path)
            .send()
            .await
            .map_err(|e| io::Error::new(ErrorKind::NotFound, format!("S3 Read Error: {}", e)))?;

        let data = resp
            .body
            .collect()
            .await
            .map_err(|e| io::Error::other(format!("S3 Body Error: {}", e)))?;

        Ok(data.into_bytes().to_vec())
    }

    async fn exists(&self, path: &str) -> io::Result<bool> {
        match self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(path)
            .send()
            .await
        {
            Ok(_) => Ok(true),
            Err(e) => {
                let service_error = e.into_service_error();
                if service_error.is_not_found() {
                    Ok(false)
                } else {
                    Err(io::Error::other(format!(
                        "S3 Head Error: {}",
                        service_error
                    )))
                }
            }
        }
    }

    async fn list(&self, prefix: &str) -> io::Result<Vec<String>> {
        // ListObjectsV2 returns at most 1000 keys per call: follow the
        // continuation token until the listing is complete. A partial
        // listing made prune delete live data and made
        // find_latest_snapshot pick a stale snapshot.
        let mut files = Vec::new();
        let mut continuation: Option<String> = None;
        loop {
            let resp = self
                .client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(prefix)
                .set_continuation_token(continuation.take())
                .send()
                .await
                .map_err(|e| io::Error::other(format!("S3 List Error: {}", e)))?;

            files.extend(
                resp.contents
                    .unwrap_or_default()
                    .into_iter()
                    .filter_map(|obj| obj.key),
            );

            if !resp.is_truncated.unwrap_or(false) {
                break;
            }
            match resp.next_continuation_token {
                Some(token) if !token.is_empty() => continuation = Some(token),
                _ => {
                    // Fail closed: a silently partial listing is dangerous.
                    return Err(io::Error::other(
                        "S3 List Error: truncated listing without continuation token",
                    ));
                }
            }
        }
        Ok(files)
    }

    async fn delete(&self, path: &str) -> io::Result<()> {
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(path)
            .send()
            .await
            .map_err(|e| io::Error::other(format!("S3 Delete Error: {}", e)))?;
        Ok(())
    }

    async fn size(&self, path: &str) -> io::Result<Option<u64>> {
        match self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(path)
            .send()
            .await
        {
            Ok(out) => Ok(Some(out.content_length.unwrap_or(0).max(0) as u64)),
            Err(e) => {
                let service_error = e.into_service_error();
                if service_error.is_not_found() {
                    Ok(None)
                } else {
                    Err(io::Error::other(format!(
                        "S3 Head Error: {}",
                        service_error
                    )))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_detection_is_exact() {
        assert!(is_loopback_endpoint("http://localhost:9000"));
        assert!(is_loopback_endpoint("http://127.0.0.1:9000"));
        assert!(is_loopback_endpoint("http://[::1]:9000"));
        assert!(!is_loopback_endpoint("http://localhost.evil.com"));
        assert!(!is_loopback_endpoint("http://evil.com/?h=127.0.0.1"));
        assert!(!is_loopback_endpoint("http://localhost@evil.com"));
        assert!(!is_loopback_endpoint("http://127.0.0.1.nip.io"));
        assert!(is_insecure_remote_endpoint("http://minio.example.com"));
        assert!(is_insecure_remote_endpoint("http://localhost.evil.com"));
        assert!(!is_insecure_remote_endpoint("https://minio.example.com"));
        assert!(!is_insecure_remote_endpoint("http://localhost:9000"));
    }

    #[tokio::test]
    async fn local_write_is_atomic_and_leaves_no_temp_files() {
        let dir = tempfile::tempdir().unwrap();
        let storage = LocalStorage::new(dir.path().to_str().unwrap());
        storage.write("data/clear/abc", b"hello").await.unwrap();
        storage.write("data/clear/abc", b"world!").await.unwrap();
        assert_eq!(storage.read("data/clear/abc").await.unwrap(), b"world!");
        assert_eq!(storage.size("data/clear/abc").await.unwrap(), Some(6));
        assert_eq!(storage.size("data/clear/missing").await.unwrap(), None);
        let names: Vec<_> = std::fs::read_dir(dir.path().join("data/clear"))
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names.len(), 1, "temp files left behind: {:?}", names);
    }

    #[tokio::test]
    async fn local_list_ignores_temp_files_and_trailing_slash() {
        let dir = tempfile::tempdir().unwrap();
        let storage = LocalStorage::new(dir.path().to_str().unwrap());
        storage.write("snapshots/a.toml", b"x").await.unwrap();
        std::fs::write(
            dir.path().join(format!("snapshots/.a.toml{}123", TMP_MARKER)),
            b"",
        )
        .unwrap();
        let listed = storage.list("snapshots/").await.unwrap();
        assert_eq!(listed, vec!["snapshots/a.toml".to_string()]);
    }
}
