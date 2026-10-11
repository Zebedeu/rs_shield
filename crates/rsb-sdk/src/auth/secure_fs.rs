//! Helpers de I/O para ficheiros sensíveis (segredos, sessões, credenciais).
//!
//! Escrita atómica (ficheiro temporário + rename) com permissões 0600 desde a
//! criação, para que nunca exista uma janela em que o conteúdo fica legível
//! por outros utilizadores ou meio escrito.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Diretório base `~/.rs-shield` (criado com 0700 se não existir).
pub fn rs_shield_dir() -> Result<PathBuf, String> {
    let home = dirs::home_dir().ok_or_else(|| "Home directory not found".to_string())?;
    let dir = home.join(".rs-shield");
    ensure_private_dir(&dir)?;
    Ok(dir)
}

/// Cria o diretório (recursivamente) e restringe-o a 0700 em Unix.
pub fn ensure_private_dir(dir: &Path) -> Result<(), String> {
    if !dir.exists() {
        fs::create_dir_all(dir)
            .map_err(|e| format!("Failed to create directory {:?}: {}", dir, e))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
        }
    }
    Ok(())
}

/// Escreve `data` em `path` de forma atómica com modo 0600.
pub fn write_private_atomic(path: &Path, data: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    ensure_private_dir(parent)?;

    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "data".to_string());
    let tmp_path = parent.join(format!(".{}.tmp-{}", file_name, uuid::Uuid::new_v4()));

    let result = (|| -> Result<(), String> {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts
            .open(&tmp_path)
            .map_err(|e| format!("Failed to create temp file {:?}: {}", tmp_path, e))?;
        file.write_all(data)
            .map_err(|e| format!("Failed to write temp file: {}", e))?;
        file.sync_all()
            .map_err(|e| format!("Failed to sync temp file: {}", e))?;
        fs::rename(&tmp_path, path)
            .map_err(|e| format!("Failed to move file into place {:?}: {}", path, e))?;
        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }
    result
}

/// Cria o ficheiro apenas se ainda não existir (O_EXCL), com modo 0600.
/// Retorna `Ok(false)` se outro processo já o criou entretanto.
pub fn create_private_exclusive(path: &Path, data: &[u8]) -> Result<bool, String> {
    if let Some(parent) = path.parent() {
        ensure_private_dir(parent)?;
    }
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    match opts.open(path) {
        Ok(mut file) => {
            file.write_all(data)
                .map_err(|e| format!("Failed to write {:?}: {}", path, e))?;
            file.sync_all()
                .map_err(|e| format!("Failed to sync {:?}: {}", path, e))?;
            Ok(true)
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(e) => Err(format!("Failed to create {:?}: {}", path, e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_private_atomic_mode_and_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("secret.json");
        write_private_atomic(&path, b"hello").unwrap();
        write_private_atomic(&path, b"world").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"world");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        // Nenhum ficheiro temporário deixado para trás.
        let leftovers: Vec<_> = fs::read_dir(path.parent().unwrap())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp-"))
            .collect();
        assert!(leftovers.is_empty());
    }
}
