pub mod instrumented;
pub mod lock;
pub mod memory;

use async_trait::async_trait;
use aws_config::BehaviorVersion;
use aws_credential_types::Credentials;
use aws_sdk_s3::Client;
use aws_sdk_s3::config::Region;
use aws_sdk_s3::error::{DisplayErrorContext, SdkError};
use std::io::{self, ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use tokio::fs;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

pub use instrumented::{InstrumentedStorage, StorageCallCounts};
pub use lock::{LockKind, RepoLock};
pub use memory::MemoryStorage;

/// Streaming reader over a stored object (see [`Storage::read_stream`]).
pub type BlobReader = Pin<Box<dyn AsyncRead + Send>>;

#[async_trait]
pub trait Storage: Send + Sync {
    async fn write(&self, path: &str, data: &[u8]) -> io::Result<()>;
    /// Reads a whole object into memory. Meant for small objects
    /// (manifests, snapshots); use [`Storage::read_stream`] for data blobs.
    async fn read(&self, path: &str) -> io::Result<Vec<u8>>;

    /// Opens an object as a byte stream so callers can process it with
    /// bounded memory (no full-object buffering in real backends).
    ///
    /// The default implementation falls back to [`Storage::read`]; real
    /// backends override it (local: file handle, S3: GetObject body).
    async fn read_stream(&self, path: &str) -> io::Result<BlobReader> {
        let data = self.read(path).await?;
        Ok(Box::pin(io::Cursor::new(data)))
    }

    /// Writes everything `reader` yields to `path`; returns the number of
    /// bytes written. Same atomicity as [`Storage::write`].
    ///
    /// The default implementation buffers the whole stream in memory; real
    /// backends override it (local: streamed into a temp file + rename,
    /// S3: spooled to a local temp file, then [`Storage::write_file`]).
    async fn write_from_reader(&self, path: &str, mut reader: BlobReader) -> io::Result<u64> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).await?;
        self.write(path, &buf).await?;
        Ok(buf.len() as u64)
    }

    /// Writes the contents of the local file `src` to `path` (used to
    /// upload blobs spooled to disk without loading them in memory). Same
    /// atomicity as [`Storage::write`].
    ///
    /// The default implementation reads the file into memory; real backends
    /// stream it (local: copy into a temp file + rename, S3: PutObject with
    /// a file-backed body of known length).
    async fn write_file(&self, path: &str, src: &Path) -> io::Result<()> {
        let data = fs::read(src).await?;
        self.write(path, &data).await
    }

    /// Like [`Storage::write`], but making the new object durable may be
    /// deferred until the next [`Storage::sync`]. The object is never
    /// visible partially written; a crash before the `sync` can only lose
    /// it. Used for data objects, whose manifest is written after a
    /// `sync`. The default implementation is [`Storage::write`].
    async fn write_deferred(&self, path: &str, data: &[u8]) -> io::Result<()> {
        self.write(path, data).await
    }

    /// [`Storage::write_file`] with the durability of
    /// [`Storage::write_deferred`].
    async fn write_file_deferred(&self, path: &str, src: &Path) -> io::Result<()> {
        self.write_file(path, src).await
    }

    /// Makes every earlier deferred write durable. The default does
    /// nothing (writes are durable when they return).
    async fn sync(&self) -> io::Result<()> {
        Ok(())
    }

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
    /// Directories that received a deferred write since the last `sync`.
    pending_dirs: std::sync::Arc<std::sync::Mutex<std::collections::HashSet<PathBuf>>>,
}

impl LocalStorage {
    pub fn new(path: &str) -> Self {
        Self {
            base_path: PathBuf::from(path),
            pending_dirs: Default::default(),
        }
    }

    fn note_pending(&self, full_path: &Path) {
        if let Some(parent) = full_path.parent() {
            self.pending_dirs
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(parent.to_path_buf());
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

/// Atomically and durably writes `data` to `path`: temp file in the same
/// directory → [`sync_before_rename`] → `rename` → fsync(dir).
///
/// A crash at any point leaves either the old object or the complete new
/// one, never a truncated file (which dedup would otherwise trust forever).
/// Parent directories are created with plain `create_dir_all` (no `~`/`$VAR`
/// expansion).
pub async fn atomic_write_file(path: &Path, data: &[u8]) -> io::Result<()> {
    // One blocking task for the whole sequence (one copy of `data`), instead
    // of a blocking round trip per 8 KiB through `tokio::fs`.
    let path = path.to_path_buf();
    let data = data.to_vec();
    blocking(move || atomic_write_blocking(&path, true, |f| f.write_all(&data)).map(|_| ())).await
}

/// Like [`atomic_write_file`], copying the content of the local file `src`
/// (in one blocking task, through a 1 MiB buffer).
pub async fn atomic_copy_file(path: &Path, src: &Path) -> io::Result<()> {
    copy_file_atomically(path, src, true).await
}

/// [`atomic_copy_file`]; with `sync_parent == false` the directory is not
/// fsync'ed (see [`Storage::write_file_deferred`]).
async fn copy_file_atomically(path: &Path, src: &Path, sync_parent: bool) -> io::Result<()> {
    let (path, src) = (path.to_path_buf(), src.to_path_buf());
    blocking(move || {
        let src = std::fs::File::open(&src)?;
        let mut reader = std::io::BufReader::with_capacity(COPY_BUF, src);
        atomic_write_blocking(&path, sync_parent, |f| {
            std::io::copy(&mut reader, f).map(|_| ())
        })
        .map(|_| ())
    })
    .await
}

/// Copy buffer of the atomic writes.
const COPY_BUF: usize = 1024 * 1024;

async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> io::Result<T> + Send + 'static,
) -> io::Result<T> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(io::Error::other)?
}

/// Temp file name next to `path` and the directory holding both.
fn atomic_tmp_path(path: &Path) -> io::Result<(PathBuf, PathBuf)> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
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
    Ok((parent, tmp_path))
}

/// Blocking core of [`atomic_write_file`] / [`atomic_copy_file`]: `fill`
/// writes the content into the temp file. The parent directory is
/// fsync'ed after the rename when `sync_parent` is set.
fn atomic_write_blocking(
    path: &Path,
    sync_parent: bool,
    fill: impl FnOnce(&mut std::fs::File) -> io::Result<()>,
) -> io::Result<u64> {
    let (parent, tmp_path) = atomic_tmp_path(path)?;
    std::fs::create_dir_all(&parent)?;
    let result = (|| {
        // create_new => O_CREAT|O_EXCL: never follows a pre-planted symlink.
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)?;
        fill(&mut file)?;
        file.flush()?;
        sync_before_rename(&file)?;
        let n = file.metadata()?.len();
        drop(file);
        std::fs::rename(&tmp_path, path)?;
        if sync_parent {
            sync_dir_blocking(&parent)?;
        }
        Ok(n)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
    }
    result
}

/// Like [`atomic_write_file`], streaming the content from `reader` (memory
/// stays bounded by the copy buffer). Returns the number of bytes written.
pub async fn atomic_write_from_reader<R>(path: &Path, reader: &mut R) -> io::Result<u64>
where
    R: AsyncRead + Unpin + ?Sized,
{
    let (parent, tmp_path) = atomic_tmp_path(path)?;
    let parent = parent.as_path();
    fs::create_dir_all(parent).await?;

    let result = async {
        // create_new => O_CREAT|O_EXCL: never follows a pre-planted symlink.
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)
            .await?;
        // 1 MiB reads/writes: each `tokio::fs` operation is a blocking-pool
        // round trip, so the default 8 KiB copy buffer is slow.
        let mut reader = tokio::io::BufReader::with_capacity(COPY_BUF, reader);
        let n = tokio::io::copy_buf(&mut reader, &mut file).await?;
        file.flush().await?;
        file.sync_all().await?;
        drop(file);
        fs::rename(&tmp_path, path).await?;
        sync_dir(parent).await?;
        Ok(n)
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

/// Makes the data written to `file` reach stable storage before any later
/// write, in particular the rename that publishes it, so a crash or power
/// loss can never leave a renamed but incomplete file.
///
/// On Apple platforms this is `F_BARRIERFSYNC`: an I/O barrier, much
/// cheaper than the full drive-cache flush of `F_FULLFSYNC` (what
/// `sync_all` does there), with the ordering guarantee needed here. It
/// does not make the file durable by itself: callers report success only
/// after [`sync_dir`] (`F_FULLFSYNC`, which flushes everything written
/// before it). If the barrier is not supported, falls back to `sync_all`.
/// Elsewhere it is `sync_all`.
pub fn sync_before_rename(file: &std::fs::File) -> io::Result<()> {
    #[cfg(target_vendor = "apple")]
    {
        use std::os::fd::AsRawFd;
        // SAFETY: fcntl on a valid, open descriptor owned by `file`.
        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_BARRIERFSYNC) } != -1 {
            return Ok(());
        }
    }
    file.sync_all()
}

/// Blocking [`sync_dir`].
fn sync_dir_blocking(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    std::fs::File::open(dir)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = dir;
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

    async fn write_from_reader(&self, path: &str, mut reader: BlobReader) -> io::Result<u64> {
        let full_path = self.safe_join(path)?;
        atomic_write_from_reader(&full_path, &mut reader).await
    }

    async fn write_file(&self, path: &str, src: &Path) -> io::Result<()> {
        let full_path = self.safe_join(path)?;
        atomic_copy_file(&full_path, src).await
    }

    async fn write_deferred(&self, path: &str, data: &[u8]) -> io::Result<()> {
        let full_path = self.safe_join(path)?;
        let data = data.to_vec();
        let target = full_path.clone();
        blocking(move || atomic_write_blocking(&target, false, |f| f.write_all(&data))).await?;
        self.note_pending(&full_path);
        Ok(())
    }

    async fn write_file_deferred(&self, path: &str, src: &Path) -> io::Result<()> {
        let full_path = self.safe_join(path)?;
        copy_file_atomically(&full_path, src, false).await?;
        self.note_pending(&full_path);
        Ok(())
    }

    async fn sync(&self) -> io::Result<()> {
        let dirs: Vec<PathBuf> = {
            let mut pending = self.pending_dirs.lock().unwrap_or_else(|e| e.into_inner());
            pending.drain().collect()
        };
        for (i, dir) in dirs.iter().enumerate() {
            if let Err(e) = sync_dir(dir).await {
                // Not synced: keep them pending for the next attempt.
                let mut pending = self.pending_dirs.lock().unwrap_or_else(|e| e.into_inner());
                pending.extend(dirs[i..].iter().cloned());
                return Err(e);
            }
        }
        Ok(())
    }

    async fn read(&self, path: &str) -> io::Result<Vec<u8>> {
        let full_path = self.safe_join(path)?;
        fs::read(full_path).await
    }

    async fn read_stream(&self, path: &str) -> io::Result<BlobReader> {
        let full_path = self.safe_join(path)?;
        let file = fs::File::open(full_path).await?;
        Ok(Box::pin(file))
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

/// Região usada com um endpoint S3-compatível quando nenhuma é indicada
/// (MinIO, Ceph, Garage... aceitam-na; R2 aceita também "auto").
pub const DEFAULT_S3_COMPAT_REGION: &str = "us-east-1";

/// Região efetiva: qualquer string não vazia é aceite tal como está (R2 usa
/// "auto"); com endpoint personalizado e sem região usa
/// [`DEFAULT_S3_COMPAT_REGION`] em vez de falhar. Sem endpoint (AWS) e sem
/// região devolve `None` e a cadeia de defaults do SDK decide (env/perfil).
pub fn effective_s3_region(region: Option<&str>, endpoint: Option<&str>) -> Option<String> {
    let region = region.map(str::trim).filter(|r| !r.is_empty());
    let has_endpoint = endpoint.is_some_and(|e| !e.trim().is_empty());
    match region {
        Some(r) => Some(r.to_string()),
        None if has_endpoint => Some(DEFAULT_S3_COMPAT_REGION.to_string()),
        None => None,
    }
}

/// Ajustes de compatibilidade com fornecedores S3 que não são a AWS
/// (MinIO, R2, B2, Wasabi, Spaces, Ceph RGW, Garage, Scaleway, Hetzner,
/// IDrive e2...):
/// - endpoint personalizado ⇒ path-style (`host/bucket/key`), nunca
///   virtual-hosted;
/// - checksums CRC32/CRC64 só quando a operação os exige: as versões
///   recentes do SDK enviam-nos por omissão e vários fornecedores rejeitam
///   esses headers (a integridade é garantida pelos nossos hashes BLAKE3).
pub fn apply_s3_compat(
    builder: aws_sdk_s3::config::Builder,
    custom_endpoint: bool,
) -> aws_sdk_s3::config::Builder {
    use aws_sdk_s3::config::{RequestChecksumCalculation, ResponseChecksumValidation};
    builder
        .force_path_style(custom_endpoint)
        .request_checksum_calculation(RequestChecksumCalculation::WhenRequired)
        .response_checksum_validation(ResponseChecksumValidation::WhenRequired)
}

/// Constrói o cliente S3 (SigV4, session token opcional nas credenciais)
/// com os ajustes de [`apply_s3_compat`] e [`effective_s3_region`].
pub async fn build_s3_client(
    region: Option<String>,
    endpoint: Option<String>,
    credentials: Credentials,
) -> Client {
    let endpoint = endpoint
        .map(|e| e.trim().to_string())
        .filter(|e| !e.is_empty());
    let region = effective_s3_region(region.as_deref(), endpoint.as_deref());

    let mut config_loader = aws_config::defaults(BehaviorVersion::latest());
    if let Some(r) = region {
        config_loader = config_loader.region(Region::new(r));
    }

    let custom_endpoint = endpoint.is_some();
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
    let s3_config = apply_s3_compat(
        aws_sdk_s3::config::Builder::from(&sdk_config),
        custom_endpoint,
    )
    .build();
    Client::from_conf(s3_config)
}

/// Classifica um erro do SDK S3 num `io::ErrorKind`, sem depender do corpo
/// da resposta: HEAD não tem corpo e vários fornecedores devolvem 404 sem
/// código (ou com códigos próprios), por isso o status HTTP também conta.
fn s3_error_kind<E>(err: &SdkError<E>, typed_not_found: impl Fn(&E) -> bool) -> ErrorKind {
    if err.as_service_error().is_some_and(typed_not_found) {
        return ErrorKind::NotFound;
    }
    match err.raw_response().map(|r| r.status().as_u16()) {
        Some(404) => ErrorKind::NotFound,
        Some(401) | Some(403) => ErrorKind::PermissionDenied,
        _ => ErrorKind::Other,
    }
}

fn s3_io_error<E>(
    op: &str,
    path: &str,
    err: SdkError<E>,
    typed_not_found: impl Fn(&E) -> bool,
) -> io::Error
where
    E: std::error::Error + Send + Sync + 'static,
{
    let kind = s3_error_kind(&err, typed_not_found);
    io::Error::new(
        kind,
        format!("S3 {} Error ({}): {}", op, path, DisplayErrorContext(&err)),
    )
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
        Self {
            client: build_s3_client(region, endpoint, credentials).await,
            bucket: bucket.to_string(),
        }
    }

    /// Prefixo de listagem com a mesma semântica de diretório do
    /// `LocalStorage`: `"data/clear"` não pode apanhar `"data/clearX/..."`.
    fn dir_prefix(prefix: &str) -> String {
        let p = prefix.trim_end_matches('/');
        if p.is_empty() {
            String::new()
        } else {
            format!("{}/", p)
        }
    }

    /// Há pelo menos um objeto sob `prefix/`? (S3 não tem diretórios.)
    async fn prefix_exists(&self, prefix: &str) -> io::Result<bool> {
        let resp = self
            .client
            .list_objects_v2()
            .bucket(&self.bucket)
            .prefix(Self::dir_prefix(prefix))
            .max_keys(1)
            .send()
            .await
            .map_err(|e| s3_io_error("List", prefix, e, |_| false))?;
        Ok(!resp.contents().is_empty())
    }
}

#[async_trait]
impl Storage for S3Storage {
    async fn write(&self, path: &str, data: &[u8]) -> io::Result<()> {
        // PutObject simples (sem ACL, tagging, storage class, SSE-KMS nem
        // escrita condicional): suportado por todos os fornecedores.
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(path)
            .body(data.to_vec().into())
            .send()
            .await
            .map_err(|e| s3_io_error("Upload", path, e, |_| false))?;
        Ok(())
    }

    async fn write_file(&self, path: &str, src: &Path) -> io::Result<()> {
        // Plain PutObject with a file-backed body of known length (no
        // multipart, no conditional write): streamed from disk, never held
        // in memory, and accepted by every S3-compatible provider.
        let body = aws_sdk_s3::primitives::ByteStream::from_path(src)
            .await
            .map_err(|e| io::Error::other(format!("S3 Upload Error ({}): {}", path, e)))?;
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(path)
            .body(body)
            .send()
            .await
            .map_err(|e| s3_io_error("Upload", path, e, |_| false))?;
        Ok(())
    }

    async fn write_from_reader(&self, path: &str, mut reader: BlobReader) -> io::Result<u64> {
        // PutObject needs the length up front: spool to a local temp file
        // (deleted on drop) instead of buffering the stream in memory.
        let tmp = tempfile::NamedTempFile::new()?;
        let mut file = fs::File::create(tmp.path()).await?;
        let n = tokio::io::copy(&mut reader, &mut file).await?;
        file.flush().await?;
        drop(file);
        self.write_file(path, tmp.path()).await?;
        Ok(n)
    }

    async fn read(&self, path: &str) -> io::Result<Vec<u8>> {
        let resp = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(path)
            .send()
            .await
            .map_err(|e| s3_io_error("Read", path, e, |se| se.is_no_such_key()))?;

        let data = resp
            .body
            .collect()
            .await
            .map_err(|e| io::Error::other(format!("S3 Body Error: {}", e)))?;

        Ok(data.into_bytes().to_vec())
    }

    async fn read_stream(&self, path: &str) -> io::Result<BlobReader> {
        let resp = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(path)
            .send()
            .await
            .map_err(|e| s3_io_error("Read", path, e, |se| se.is_no_such_key()))?;
        // Streams the HTTP body chunk by chunk; nothing is collected.
        Ok(Box::pin(resp.body.into_async_read()))
    }

    async fn exists(&self, path: &str) -> io::Result<bool> {
        // "dir/" refere-se a um diretório (ex.: validação de estrutura no
        // restore usa `exists("data/")`): em S3 é "há objetos com o prefixo".
        if path.ends_with('/') {
            return self.prefix_exists(path).await;
        }
        Ok(self.size(path).await?.is_some())
    }

    async fn list(&self, prefix: &str) -> io::Result<Vec<String>> {
        // ListObjectsV2 returns at most 1000 keys per call: follow the
        // continuation token until the listing is complete. A partial
        // listing made prune delete live data and made
        // find_latest_snapshot pick a stale snapshot.
        let dir_prefix = Self::dir_prefix(prefix);
        let mut files = Vec::new();
        let mut continuation: Option<String> = None;
        loop {
            let resp = self
                .client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(&dir_prefix)
                .set_continuation_token(continuation.take())
                .send()
                .await
                .map_err(|e| s3_io_error("List", prefix, e, |_| false))?;

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
        // DeleteObject individual (DeleteObjects em lote exige Content-MD5
        // e não é suportado/limitado em vários fornecedores).
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(path)
            .send()
            .await
            .map_err(|e| s3_io_error("Delete", path, e, |_| false))?;
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
                // 404 sem corpo (HEAD) ou com código próprio do fornecedor.
                let err = s3_io_error("Head", path, e, |se| se.is_not_found());
                if err.kind() == ErrorKind::NotFound {
                    Ok(None)
                } else {
                    Err(err)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s3_region_defaults_only_for_custom_endpoints() {
        // Qualquer string é aceite (R2 usa "auto").
        assert_eq!(
            effective_s3_region(Some("auto"), Some("https://x.r2.cloudflarestorage.com")),
            Some("auto".to_string())
        );
        assert_eq!(
            effective_s3_region(Some(" eu-central-003 "), None),
            Some("eu-central-003".to_string())
        );
        // Endpoint personalizado sem região: us-east-1 em vez de falhar.
        assert_eq!(
            effective_s3_region(None, Some("http://localhost:9000")),
            Some(DEFAULT_S3_COMPAT_REGION.to_string())
        );
        assert_eq!(
            effective_s3_region(Some("  "), Some("https://s3.wasabisys.com")),
            Some(DEFAULT_S3_COMPAT_REGION.to_string())
        );
        // AWS sem região: deixa a cadeia de defaults do SDK decidir.
        assert_eq!(effective_s3_region(None, None), None);
        assert_eq!(effective_s3_region(None, Some("  ")), None);
    }

    #[test]
    fn s3_client_config_is_provider_compatible() {
        use aws_sdk_s3::config::{
            BehaviorVersion, RequestChecksumCalculation, ResponseChecksumValidation,
        };
        let base = || {
            aws_sdk_s3::config::Builder::new()
                .behavior_version(BehaviorVersion::latest())
                .region(Region::new("auto"))
        };
        for custom in [true, false] {
            let cfg = apply_s3_compat(base(), custom).build();
            assert_eq!(
                cfg.request_checksum_calculation(),
                Some(&RequestChecksumCalculation::WhenRequired)
            );
            assert_eq!(
                cfg.response_checksum_validation(),
                Some(&ResponseChecksumValidation::WhenRequired)
            );
            assert_eq!(cfg.region().map(|r| r.as_ref()), Some("auto"));
        }
    }

    #[test]
    fn s3_list_prefix_has_directory_semantics() {
        assert_eq!(S3Storage::dir_prefix("snapshots"), "snapshots/");
        assert_eq!(S3Storage::dir_prefix("data/clear/"), "data/clear/");
        assert_eq!(S3Storage::dir_prefix(""), "");
    }

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
    async fn local_read_stream_matches_read_and_rejects_traversal() {
        use tokio::io::AsyncReadExt;
        let dir = tempfile::tempdir().unwrap();
        let storage = LocalStorage::new(dir.path().to_str().unwrap());
        let payload: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
        storage.write("data/clear/blob", &payload).await.unwrap();
        let mut r = storage.read_stream("data/clear/blob").await.unwrap();
        let mut got = Vec::new();
        r.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, payload);
        assert!(storage.read_stream("../etc/passwd").await.is_err());
        assert!(storage.read_stream("data/clear/missing").await.is_err());
    }

    #[tokio::test]
    async fn local_streaming_writes_are_atomic() {
        let dir = tempfile::tempdir().unwrap();
        let storage = LocalStorage::new(dir.path().to_str().unwrap());
        let payload: Vec<u8> = (0..500_000u32).map(|i| (i % 249) as u8).collect();
        let n = storage
            .write_from_reader("data/enc/x", Box::pin(io::Cursor::new(payload.clone())))
            .await
            .unwrap();
        assert_eq!(n, payload.len() as u64);
        assert_eq!(storage.read("data/enc/x").await.unwrap(), payload);

        let src = dir.path().join("spool");
        std::fs::write(&src, b"from file").unwrap();
        storage.write_file("data/enc/y", &src).await.unwrap();
        assert_eq!(storage.read("data/enc/y").await.unwrap(), b"from file");
        assert!(storage.write_file("../escape", &src).await.is_err());
        let names: Vec<_> = std::fs::read_dir(dir.path().join("data/enc"))
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names.len(), 2, "temp files left behind: {:?}", names);

        // Default trait implementations (MemoryStorage) behave the same.
        let mem = MemoryStorage::new();
        mem.write_from_reader("a/b", Box::pin(io::Cursor::new(b"xyz".to_vec())))
            .await
            .unwrap();
        mem.write_file("a/c", &src).await.unwrap();
        assert_eq!(mem.read("a/b").await.unwrap(), b"xyz");
        assert_eq!(mem.read("a/c").await.unwrap(), b"from file");
    }

    #[tokio::test]
    async fn local_deferred_writes_are_atomic_and_synced_on_demand() {
        let dir = tempfile::tempdir().unwrap();
        let storage = LocalStorage::new(dir.path().to_str().unwrap());
        storage
            .write_deferred("data/clear/a", b"one")
            .await
            .unwrap();
        let src = dir.path().join("spool");
        std::fs::write(&src, b"two").unwrap();
        storage
            .write_file_deferred("data/enc/b", &src)
            .await
            .unwrap();
        assert!(storage.write_deferred("../escape", b"x").await.is_err());
        // Visible (and complete) at once; durability waits for `sync`.
        assert_eq!(storage.read("data/clear/a").await.unwrap(), b"one");
        assert_eq!(storage.read("data/enc/b").await.unwrap(), b"two");
        assert_eq!(storage.pending_dirs.lock().unwrap().len(), 2);
        storage.sync().await.unwrap();
        assert!(storage.pending_dirs.lock().unwrap().is_empty());
        for d in ["data/clear", "data/enc"] {
            assert_eq!(std::fs::read_dir(dir.path().join(d)).unwrap().count(), 1);
        }
        // Defaults (MemoryStorage) behave like plain writes.
        let mem = MemoryStorage::new();
        mem.write_deferred("a/b", b"x").await.unwrap();
        mem.sync().await.unwrap();
        assert_eq!(mem.read("a/b").await.unwrap(), b"x");
    }

    #[test]
    fn sync_before_rename_works_on_regular_files() {
        let dir = tempfile::tempdir().unwrap();
        let f = std::fs::File::create(dir.path().join("f")).unwrap();
        sync_before_rename(&f).unwrap();
    }

    #[tokio::test]
    async fn local_list_ignores_temp_files_and_trailing_slash() {
        let dir = tempfile::tempdir().unwrap();
        let storage = LocalStorage::new(dir.path().to_str().unwrap());
        storage.write("snapshots/a.toml", b"x").await.unwrap();
        std::fs::write(
            dir.path()
                .join(format!("snapshots/.a.toml{}123", TMP_MARKER)),
            b"",
        )
        .unwrap();
        let listed = storage.list("snapshots/").await.unwrap();
        assert_eq!(listed, vec!["snapshots/a.toml".to_string()]);
    }
}
