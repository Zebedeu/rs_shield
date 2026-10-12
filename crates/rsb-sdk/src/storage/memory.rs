//! Storage em memória, para testes e para injetar nas operações sem tocar
//! no disco nem na rede.
//!
//! A semântica imita [`super::LocalStorage`]:
//! - paths validados com [`super::validate_storage_path`] (sem `..`,
//!   absolutos, `\`, NUL);
//! - `list(prefix)` devolve só os filhos **diretos** de `prefix` (ficheiros e
//!   "diretórios"), no formato `"<prefix>/<nome>"`, e falha com `NotFound`
//!   se o "diretório" nunca existiu;
//! - os "diretórios" persistem depois de apagados os ficheiros (como no
//!   disco), pelo que `list` de um diretório esvaziado devolve `[]`;
//! - `read`/`read_stream`/`delete` de um objeto inexistente falham com
//!   `NotFound`; `size` devolve `None`.

use super::{BlobReader, Storage, validate_storage_path};
use async_trait::async_trait;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, ErrorKind};
use std::sync::RwLock;

#[derive(Default)]
struct Inner {
    objects: BTreeMap<String, Vec<u8>>,
    dirs: BTreeSet<String>,
}

/// Backend [`Storage`] totalmente em memória (thread-safe).
#[derive(Default)]
pub struct MemoryStorage {
    inner: RwLock<Inner>,
}

impl std::fmt::Debug for MemoryStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryStorage")
            .field("objects", &self.len())
            .finish()
    }
}

fn poisoned() -> io::Error {
    io::Error::other("MemoryStorage lock poisoned")
}

fn not_found(path: &str) -> io::Error {
    io::Error::new(ErrorKind::NotFound, format!("Object not found: {}", path))
}

impl MemoryStorage {
    pub fn new() -> Self {
        Self::default()
    }

    /// Número de objetos guardados.
    pub fn len(&self) -> usize {
        self.inner.read().map(|i| i.objects.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Todos os paths de objetos (ordenados), útil em asserts.
    pub fn keys(&self) -> Vec<String> {
        self.inner
            .read()
            .map(|i| i.objects.keys().cloned().collect())
            .unwrap_or_default()
    }
}

#[async_trait]
impl Storage for MemoryStorage {
    async fn write(&self, path: &str, data: &[u8]) -> io::Result<()> {
        validate_storage_path(path)?;
        let mut inner = self.inner.write().map_err(|_| poisoned())?;
        if inner.dirs.contains(path) {
            return Err(io::Error::new(
                ErrorKind::IsADirectory,
                format!("'{}' is a directory", path),
            ));
        }
        // Regista os diretórios-pai (como `create_dir_all`).
        let mut parent = path;
        while let Some((p, _)) = parent.rsplit_once('/') {
            if inner.objects.contains_key(p) {
                return Err(io::Error::new(
                    ErrorKind::NotADirectory,
                    format!("'{}' is a file", p),
                ));
            }
            inner.dirs.insert(p.to_string());
            parent = p;
        }
        inner.objects.insert(path.to_string(), data.to_vec());
        Ok(())
    }

    async fn read(&self, path: &str) -> io::Result<Vec<u8>> {
        validate_storage_path(path)?;
        let inner = self.inner.read().map_err(|_| poisoned())?;
        inner
            .objects
            .get(path)
            .cloned()
            .ok_or_else(|| not_found(path))
    }

    async fn read_stream(&self, path: &str) -> io::Result<BlobReader> {
        let data = self.read(path).await?;
        Ok(Box::pin(io::Cursor::new(data)))
    }

    async fn exists(&self, path: &str) -> io::Result<bool> {
        validate_storage_path(path)?;
        let inner = self.inner.read().map_err(|_| poisoned())?;
        // Como no disco, "dir/" (com barra final) refere-se ao diretório.
        Ok(inner.objects.contains_key(path) || inner.dirs.contains(path.trim_end_matches('/')))
    }

    async fn list(&self, prefix: &str) -> io::Result<Vec<String>> {
        let prefix = prefix.trim_end_matches('/');
        validate_storage_path(prefix)?;
        let inner = self.inner.read().map_err(|_| poisoned())?;
        if !inner.dirs.contains(prefix) {
            return Err(io::Error::new(
                ErrorKind::NotFound,
                format!(
                    "Backup structure incomplete: '{}' directory not found. \
                    This may indicate a corrupted backup or incomplete copy. \
                    Check that the entire backup folder was copied.",
                    prefix
                ),
            ));
        }
        let start = format!("{}/", prefix);
        let mut children = BTreeSet::new();
        let keys = inner
            .objects
            .keys()
            .chain(inner.dirs.iter())
            .filter_map(|k| k.strip_prefix(&start));
        for rest in keys {
            let child = rest.split('/').next().unwrap_or(rest);
            if !child.is_empty() {
                children.insert(format!("{}{}", start, child));
            }
        }
        Ok(children.into_iter().collect())
    }

    async fn delete(&self, path: &str) -> io::Result<()> {
        validate_storage_path(path)?;
        let mut inner = self.inner.write().map_err(|_| poisoned())?;
        inner
            .objects
            .remove(path)
            .map(|_| ())
            .ok_or_else(|| not_found(path))
    }

    async fn size(&self, path: &str) -> io::Result<Option<u64>> {
        validate_storage_path(path)?;
        let inner = self.inner.read().map_err(|_| poisoned())?;
        Ok(inner.objects.get(path).map(|d| d.len() as u64))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::LocalStorage;
    use tokio::io::AsyncReadExt;

    /// Aplica a mesma sequência de operações às duas implementações e
    /// compara os resultados observáveis.
    #[tokio::test]
    async fn behaves_like_local_storage() {
        let dir = tempfile::tempdir().unwrap();
        let local = LocalStorage::new(dir.path().to_str().unwrap());
        let mem = MemoryStorage::new();
        let backends: [&dyn Storage; 2] = [&local, &mem];

        let mut results: Vec<Vec<String>> = Vec::new();
        for s in backends {
            let mut out = Vec::new();
            s.write("snapshots/a.toml", b"aa").await.unwrap();
            s.write("snapshots/b.toml", b"bbb").await.unwrap();
            s.write("data/clear/h1", b"1").await.unwrap();
            s.write("data/enc/h2", b"22").await.unwrap();
            s.write("data/clear/h1", b"one").await.unwrap(); // overwrite

            let mut l = s.list("snapshots").await.unwrap();
            l.sort();
            out.push(format!("{:?}", l));
            let mut l = s.list("snapshots/").await.unwrap();
            l.sort();
            out.push(format!("{:?}", l));
            let mut l = s.list("data").await.unwrap();
            l.sort();
            out.push(format!("{:?}", l));
            out.push(format!(
                "{:?}",
                s.list("missing").await.map_err(|e| e.kind())
            ));
            out.push(format!("{:?}", s.list("../x").await.map_err(|e| e.kind())));

            out.push(format!("{:?}", s.read("data/clear/h1").await.unwrap()));
            out.push(format!("{:?}", s.read("nope").await.map_err(|e| e.kind())));
            let mut r = s.read_stream("data/enc/h2").await.unwrap();
            let mut buf = Vec::new();
            r.read_to_end(&mut buf).await.unwrap();
            out.push(format!("{:?}", buf));
            out.push(format!("{:?}", s.read_stream("nope").await.is_err()));

            out.push(format!("{:?}", s.size("snapshots/b.toml").await.unwrap()));
            out.push(format!("{:?}", s.size("snapshots/zz").await.unwrap()));
            out.push(format!("{:?}", s.exists("snapshots/a.toml").await.unwrap()));
            out.push(format!("{:?}", s.exists("snapshots/zz").await.unwrap()));
            out.push(format!("{:?}", s.exists("data/").await.unwrap()));
            out.push(format!("{:?}", s.exists("data").await.unwrap()));
            out.push(format!("{:?}", s.exists("nodir/").await.unwrap()));

            s.delete("snapshots/a.toml").await.unwrap();
            out.push(format!(
                "{:?}",
                s.delete("snapshots/a.toml").await.map_err(|e| e.kind())
            ));
            s.delete("snapshots/b.toml").await.unwrap();
            // Diretório esvaziado continua a existir (lista vazia).
            out.push(format!("{:?}", s.list("snapshots").await.unwrap()));

            out.push(format!("{:?}", s.write("/abs", b"x").await.is_err()));
            out.push(format!("{:?}", s.write("a/../b", b"x").await.is_err()));
            results.push(out);
        }
        assert_eq!(results[0], results[1]);
    }

    #[tokio::test]
    async fn repository_lock_works_on_memory_storage() {
        use crate::storage::lock::LOCK_DIR;
        use crate::storage::{LockKind, RepoLock};
        use std::sync::Arc;
        let s: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let b = RepoLock::acquire(s.clone(), LockKind::Shared, "backup")
            .await
            .unwrap();
        assert!(
            RepoLock::acquire(s.clone(), LockKind::Exclusive, "prune")
                .await
                .is_err()
        );
        b.release().await.unwrap();
        let p = RepoLock::acquire(s.clone(), LockKind::Exclusive, "prune")
            .await
            .unwrap();
        p.release().await.unwrap();
        assert!(s.list(LOCK_DIR).await.unwrap().is_empty());
    }
}
