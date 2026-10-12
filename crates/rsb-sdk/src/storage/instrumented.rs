//! [`Storage`] wrapper that counts calls and can inject a fixed latency per
//! call, to model a remote backend (S3) on top of local or in-memory
//! storage in benchmarks and tests.
//!
//! Calls are counted by the S3 request they correspond to:
//! `write`/`write_file`/`write_from_reader` → PUT, `read`/`read_stream` →
//! GET, `size`/`exists` → HEAD (`exists("dir/")` is a LIST on S3),
//! `list` → LIST, `delete` → DELETE. `list_pages` additionally counts
//! the ListObjectsV2 pages an S3 listing of that size would need (1000
//! keys per page).

use super::{BlobReader, Storage};
use async_trait::async_trait;
use std::io;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Snapshot of the calls made through an [`InstrumentedStorage`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StorageCallCounts {
    pub put: u64,
    pub get: u64,
    pub head: u64,
    pub list: u64,
    /// ListObjectsV2 pages an S3 backend would need for the `list` calls.
    pub list_pages: u64,
    pub delete: u64,
}

impl StorageCallCounts {
    /// Total number of requests (S3 pages for listings).
    pub fn total(&self) -> u64 {
        self.put + self.get + self.head + self.list_pages + self.delete
    }
}

impl std::fmt::Display for StorageCallCounts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PUT {} / GET {} / HEAD {} / LIST {} ({} pages) / DELETE {}",
            self.put, self.get, self.head, self.list, self.list_pages, self.delete
        )
    }
}

#[derive(Default)]
struct Counters {
    put: AtomicU64,
    get: AtomicU64,
    head: AtomicU64,
    list: AtomicU64,
    list_pages: AtomicU64,
    delete: AtomicU64,
}

/// Counting / latency-injecting [`Storage`] wrapper (see the module docs).
pub struct InstrumentedStorage {
    inner: Arc<dyn Storage>,
    latency: Duration,
    counters: Counters,
}

impl InstrumentedStorage {
    /// Counts calls to `inner` without adding latency.
    pub fn new(inner: Arc<dyn Storage>) -> Self {
        Self::with_latency(inner, Duration::ZERO)
    }

    /// Counts calls to `inner` and sleeps `latency` before each one.
    pub fn with_latency(inner: Arc<dyn Storage>, latency: Duration) -> Self {
        Self {
            inner,
            latency,
            counters: Counters::default(),
        }
    }

    /// Calls made so far.
    pub fn counts(&self) -> StorageCallCounts {
        let c = &self.counters;
        StorageCallCounts {
            put: c.put.load(Ordering::Relaxed),
            get: c.get.load(Ordering::Relaxed),
            head: c.head.load(Ordering::Relaxed),
            list: c.list.load(Ordering::Relaxed),
            list_pages: c.list_pages.load(Ordering::Relaxed),
            delete: c.delete.load(Ordering::Relaxed),
        }
    }

    /// Resets every counter to zero.
    pub fn reset(&self) {
        let c = &self.counters;
        for a in [&c.put, &c.get, &c.head, &c.list, &c.list_pages, &c.delete] {
            a.store(0, Ordering::Relaxed);
        }
    }

    async fn call(&self, counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
        if !self.latency.is_zero() {
            tokio::time::sleep(self.latency).await;
        }
    }
}

#[async_trait]
impl Storage for InstrumentedStorage {
    async fn write(&self, path: &str, data: &[u8]) -> io::Result<()> {
        self.call(&self.counters.put).await;
        self.inner.write(path, data).await
    }

    async fn read(&self, path: &str) -> io::Result<Vec<u8>> {
        self.call(&self.counters.get).await;
        self.inner.read(path).await
    }

    async fn read_stream(&self, path: &str) -> io::Result<BlobReader> {
        self.call(&self.counters.get).await;
        self.inner.read_stream(path).await
    }

    async fn write_from_reader(&self, path: &str, reader: BlobReader) -> io::Result<u64> {
        self.call(&self.counters.put).await;
        self.inner.write_from_reader(path, reader).await
    }

    async fn write_file(&self, path: &str, src: &Path) -> io::Result<()> {
        self.call(&self.counters.put).await;
        self.inner.write_file(path, src).await
    }

    async fn write_deferred(&self, path: &str, data: &[u8]) -> io::Result<()> {
        self.call(&self.counters.put).await;
        self.inner.write_deferred(path, data).await
    }

    async fn write_file_deferred(&self, path: &str, src: &Path) -> io::Result<()> {
        self.call(&self.counters.put).await;
        self.inner.write_file_deferred(path, src).await
    }

    fn cache_identity(&self) -> Option<String> {
        self.inner.cache_identity()
    }

    async fn sync(&self) -> io::Result<()> {
        // Not a storage request (a local fsync); no latency either.
        self.inner.sync().await
    }

    async fn exists(&self, path: &str) -> io::Result<bool> {
        if path.ends_with('/') {
            self.counters.list_pages.fetch_add(1, Ordering::Relaxed);
            self.call(&self.counters.list).await;
        } else {
            self.call(&self.counters.head).await;
        }
        self.inner.exists(path).await
    }

    async fn list(&self, prefix: &str) -> io::Result<Vec<String>> {
        self.call(&self.counters.list).await;
        let out = self.inner.list(prefix).await?;
        // Extra pages of a long S3 listing cost one round trip each.
        let pages = (out.len() as u64).div_ceil(1000).max(1);
        self.counters.list_pages.fetch_add(pages, Ordering::Relaxed);
        if pages > 1 && !self.latency.is_zero() {
            tokio::time::sleep(self.latency * (pages - 1) as u32).await;
        }
        Ok(out)
    }

    async fn delete(&self, path: &str) -> io::Result<()> {
        self.call(&self.counters.delete).await;
        self.inner.delete(path).await
    }

    async fn size(&self, path: &str) -> io::Result<Option<u64>> {
        self.call(&self.counters.head).await;
        self.inner.size(path).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MemoryStorage;

    #[tokio::test]
    async fn counts_calls_by_s3_request_kind() {
        let s = InstrumentedStorage::new(Arc::new(MemoryStorage::new()));
        s.write("data/clear/a", b"x").await.unwrap();
        assert_eq!(s.read("data/clear/a").await.unwrap(), b"x");
        assert_eq!(s.size("data/clear/a").await.unwrap(), Some(1));
        assert!(s.exists("data/clear/a").await.unwrap());
        assert!(s.exists("data/").await.unwrap());
        assert_eq!(s.list("data/clear").await.unwrap().len(), 1);
        s.delete("data/clear/a").await.unwrap();
        let c = s.counts();
        assert_eq!(
            c,
            StorageCallCounts {
                put: 1,
                get: 1,
                head: 2,
                list: 2,
                list_pages: 2,
                delete: 1,
            }
        );
        assert_eq!(c.total(), 7);
        s.reset();
        assert_eq!(s.counts(), StorageCallCounts::default());
    }
}
