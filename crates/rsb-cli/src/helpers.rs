use anyhow::{Result, anyhow};
use rsb_sdk::config::{self, Config};
use std::fs;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};

/// Nomes de ficheiros .toml que nunca são perfis de backup.
const NON_PROFILE_TOML: &[&str] = &[
    "Cargo.toml",
    "rustfmt.toml",
    ".rustfmt.toml",
    "clippy.toml",
    ".clippy.toml",
    "rust-toolchain.toml",
    "deny.toml",
    "Dioxus.toml",
    "pyproject.toml",
];

/// Um .toml é candidato a perfil se não estiver na lista de exclusão e
/// tiver `source_path` + `destination_path` no topo.
fn is_profile_candidate(path: &Path) -> bool {
    if !path.is_file() || path.extension().and_then(|s| s.to_str()) != Some("toml") {
        return false;
    }
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if NON_PROFILE_TOML
        .iter()
        .any(|n| n.eq_ignore_ascii_case(name))
    {
        return false;
    }
    fs::read_to_string(path)
        .ok()
        .and_then(|c| c.parse::<toml::Table>().ok())
        .map(|t| t.contains_key("source_path") && t.contains_key("destination_path"))
        .unwrap_or(false)
}

/// Procura perfis .toml no diretório indicado (ordenados por nome).
pub fn find_profile_candidates(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut found: Vec<PathBuf> = fs::read_dir(dir)?
        .flatten()
        .map(|e| e.path())
        .filter(|p| is_profile_candidate(p))
        .collect();
    found.sort();
    Ok(found)
}

/// Resolve o ficheiro de perfil: argumento explícito (config ou backup) ou,
/// em último caso, auto-descoberta no diretório atual — só se existir
/// exatamente UM perfil válido (nunca Cargo.toml nem outros .toml de tooling).
pub fn resolve_profile_path(config: Option<PathBuf>, backup: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(c) = config.or(backup) {
        return Ok(c);
    }
    let current = std::env::current_dir()?;
    let mut candidates = find_profile_candidates(&current)?;
    match candidates.len() {
        0 => Err(anyhow!(
            "No config found. Use --config <path> or --backup <path> (no backup profile .toml in {})",
            current.display()
        )),
        1 => {
            let path = candidates.remove(0);
            eprintln!("ℹ️  Using profile auto-discovered: {}", path.display());
            Ok(path)
        }
        _ => Err(anyhow!(
            "Multiple backup profiles found in {}; specify one explicitly:\n{}",
            current.display(),
            candidates
                .iter()
                .map(|p| format!("  • {}", p.display()))
                .collect::<Vec<_>>()
                .join("\n")
        )),
    }
}

/// Resolve config path from either --config, --backup, or auto-discover
/// Returns: (config_path, is_portable_mode)
pub fn resolve_config_or_backup(
    config: &Option<PathBuf>,
    backup: &Option<PathBuf>,
) -> Result<(PathBuf, bool)> {
    // If --backup provided, use it directly (portable mode)
    if let Some(backup_path) = backup {
        if backup_path.exists() {
            return Ok((backup_path.clone(), true));
        } else {
            return Err(anyhow!(
                "❌ Error: Backup path not found: {}",
                backup_path.display()
            ));
        }
    }

    // If --config provided, use it
    if let Some(config_path) = config {
        if config_path.exists() {
            return Ok((config_path.clone(), false));
        } else {
            return Err(anyhow!(
                "❌ Error: Configuration file not found: {}",
                config_path.display()
            ));
        }
    }

    resolve_profile_path(None, None).map(|p| (p, false))
}

/// Extract destination path from config.toml
pub fn extract_destination_from_config(config_path: &PathBuf) -> Result<PathBuf> {
    let config_content = fs::read_to_string(config_path)
        .map_err(|e| anyhow!("Failed to read config: {:?} - {}", config_path, e))?;

    let config_table: toml::Table = toml::from_str(&config_content)
        .map_err(|e| anyhow!("Failed to parse config.toml: {}", e))?;

    let dest_val = config_table
        .get("destination_path")
        .or_else(|| config_table.get("destination"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("'destination_path' not found in config.toml"))?;

    Ok(PathBuf::from(dest_val))
}

/// Avisa que um segredo passado como argumento fica visível em `ps`/histórico.
pub fn warn_secret_arg(flag: &str) {
    eprintln!(
        "⚠️  WARNING: secrets passed via {} are visible to other users (ps) and stored in shell history. \
         Prefer env {} / OS keyring / interactive prompt.",
        flag,
        config::ENCRYPTION_KEY_ENV
    );
}

/// Nome do perfil (usado como conta no keyring) a partir do caminho do .toml.
pub fn profile_name(path: &Path) -> Option<String> {
    path.file_stem()
        .and_then(|s| s.to_str())
        .map(|s| s.to_string())
}

/// Obtém a chave de cifra: `--key` (com aviso) → env RSB_ENCRYPTION_KEY →
/// keyring do perfil → chave legada no TOML → prompt (só em TTY).
/// Se `required` e nenhuma chave estiver disponível, devolve erro em vez de
/// prosseguir em claro.
pub fn obtain_encryption_key(
    cli_key: Option<String>,
    profile: Option<&str>,
    cfg: Option<&Config>,
    required: bool,
) -> Result<Option<String>> {
    if cli_key.is_some() {
        warn_secret_arg("--key");
    }
    if let Some(k) = config::resolve_encryption_key(cli_key, profile, cfg) {
        return Ok(Some(k));
    }
    if !required {
        return Ok(None);
    }
    if std::io::stdin().is_terminal() {
        let prompt = match profile {
            Some(p) => format!("Enter encryption key for profile '{}': ", p),
            None => "Enter encryption key: ".to_string(),
        };
        let key = rpassword::prompt_password(prompt)?;
        if key.is_empty() {
            return Err(anyhow!("Encryption key cannot be empty"));
        }
        return Ok(Some(key));
    }
    Err(anyhow!(
        "This profile has encryption enabled but no key is available. \
         Set {} (e.g. via a 0600 EnvironmentFile), store the key in the OS keyring \
         (rsb create-profile --encrypt), or run interactively. Refusing to back up unencrypted.",
        config::ENCRYPTION_KEY_ENV
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cargo_toml_is_never_a_profile() {
        let dir = tempfile::tempdir().unwrap();
        let cargo = dir.path().join("Cargo.toml");
        fs::write(&cargo, "source_path = \"a\"\ndestination_path = \"b\"\n").unwrap();
        assert!(!is_profile_candidate(&cargo));
        assert!(find_profile_candidates(dir.path()).unwrap().is_empty());
    }

    #[test]
    fn only_profile_tomls_are_candidates() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("other.toml"), "name = \"x\"\n").unwrap();
        fs::write(
            dir.path().join("b.toml"),
            "source_path = \"a\"\ndestination_path = \"b\"\n",
        )
        .unwrap();
        fs::write(
            dir.path().join("a.toml"),
            "source_path = \"a\"\ndestination_path = \"b\"\n",
        )
        .unwrap();
        let found = find_profile_candidates(dir.path()).unwrap();
        assert_eq!(found.len(), 2);
        assert!(found[0].ends_with("a.toml"));
    }

    #[test]
    fn explicit_path_wins() {
        let p = PathBuf::from("/tmp/explicit.toml");
        assert_eq!(resolve_profile_path(Some(p.clone()), None).unwrap(), p);
    }
}
