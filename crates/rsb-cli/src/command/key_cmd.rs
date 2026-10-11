//! `rsb key ...`: repository key file (`keys/repo.key`, format v3).
//!
//! Secrets are only ever read from an interactive prompt: there are no
//! password arguments (they would end up in `ps` and shell history).

use crate::helpers::resolve_profile_path;
use anyhow::{Result, anyhow};
use clap::{Args, Subcommand};
use rsb_sdk::crypto::keyfile::{self, KdfParams, REPO_KEY_PATH};
use rsb_sdk::storage::{LocalStorage, Storage};
use std::io::IsTerminal;
use std::path::PathBuf;
use std::sync::Arc;
use zeroize::Zeroizing;

/// Which repository to operate on.
#[derive(Args, Debug, Clone)]
pub struct RepoTarget {
    /// Path to the profile .toml (its destination, local or S3, is used)
    pub config: Option<PathBuf>,

    /// Local repository directory (alternative to a profile)
    #[arg(short = 'r', long)]
    pub repo: Option<PathBuf>,
}

/// Argon2id cost overrides (defaults: 65536 KiB, t=3, p=1).
#[derive(Args, Debug, Clone, Default)]
pub struct KdfArgs {
    /// Argon2 memory cost in KiB (minimum 19456)
    #[arg(long)]
    pub m_cost_kib: Option<u32>,
    /// Argon2 passes (minimum 2)
    #[arg(long)]
    pub t_cost: Option<u32>,
    /// Argon2 lanes
    #[arg(long)]
    pub p_cost: Option<u32>,
}

impl KdfArgs {
    fn params(&self, base: KdfParams) -> Option<KdfParams> {
        if self.m_cost_kib.is_none() && self.t_cost.is_none() && self.p_cost.is_none() {
            return None;
        }
        Some(KdfParams {
            m_cost_kib: self.m_cost_kib.unwrap_or(base.m_cost_kib),
            t_cost: self.t_cost.unwrap_or(base.t_cost),
            p_cost: self.p_cost.unwrap_or(base.p_cost),
        })
    }
}

#[derive(Subcommand)]
pub enum KeyCommand {
    /// Create keys/repo.key and upgrade the repository to format v3
    /// (otherwise done automatically by the first encrypted backup)
    Init {
        #[command(flatten)]
        target: RepoTarget,
        #[command(flatten)]
        kdf: KdfArgs,
    },

    /// Change the repository password (rewraps the key; no data is rewritten)
    ChangePassword {
        #[command(flatten)]
        target: RepoTarget,
        #[command(flatten)]
        kdf: KdfArgs,
    },
}

fn prompt(msg: &str) -> Result<Zeroizing<String>> {
    if !std::io::stdin().is_terminal() {
        return Err(anyhow!(
            "Passwords are only read from an interactive prompt (no TTY available)"
        ));
    }
    Ok(Zeroizing::new(rpassword::prompt_password(msg)?))
}

fn prompt_new() -> Result<Zeroizing<String>> {
    let pw = prompt("New password: ")?;
    if pw.is_empty() {
        return Err(anyhow!("The password must not be empty"));
    }
    let confirm = prompt("Confirm new password: ")?;
    if *pw != *confirm {
        return Err(anyhow!("Passwords do not match"));
    }
    Ok(pw)
}

async fn open_storage(target: &RepoTarget) -> Result<Arc<dyn Storage>> {
    if let Some(repo) = &target.repo {
        if target.config.is_some() {
            return Err(anyhow!("Use either a profile or --repo, not both"));
        }
        if !repo.is_dir() {
            return Err(anyhow!("Repository not found: {}", repo.display()));
        }
        return Ok(Arc::new(LocalStorage::new(&repo.to_string_lossy())));
    }
    let path = resolve_profile_path(target.config.clone(), None)?;
    let cfg = rsb_sdk::config::load_config(&path).map_err(|e| anyhow!("{}", e))?;
    rsb_sdk::core::storage_backend::get_storage(&cfg)
        .await
        .map_err(|e| anyhow!("{}", e))
}

impl KeyCommand {
    pub async fn execute(&self) -> Result<()> {
        // Mutating commands: same authentication gate as backup/restore/prune.
        rsb_sdk::server::routes::check_fido2_auth()
            .await
            .map_err(|e| anyhow!("{}", e))?;
        match self {
            KeyCommand::Init { target, kdf } => {
                let storage = open_storage(target).await?;
                if keyfile::repo_key_exists(&*storage).await? {
                    return Err(anyhow!(
                        "{} already exists; use `rsb key change-password`",
                        REPO_KEY_PATH
                    ));
                }
                println!("If this repository already has encrypted backups, enter their password.");
                let pw = prompt_new()?;
                let params = kdf.params(KdfParams::DEFAULT).unwrap_or_default();
                keyfile::init_repo_key(storage, pw.as_bytes(), params).await?;
                println!("✅ Created {} (format v3).", REPO_KEY_PATH);
                println!(
                    "⚠️  Losing {} makes every v3 backup unreadable: keep a copy of it.",
                    REPO_KEY_PATH
                );
            }
            KeyCommand::ChangePassword { target, kdf } => {
                let storage = open_storage(target).await?;
                let current = keyfile::read_key_file(&*storage).await?.ok_or_else(|| {
                    anyhow!(
                        "{} not found: run `rsb key init` or an encrypted backup first",
                        REPO_KEY_PATH
                    )
                })?;
                let old = prompt("Current password: ")?;
                // Fail fast (typed AuthenticationFailed) before asking for the new one.
                current.unwrap_key(old.as_bytes())?;
                let new = prompt_new()?;
                keyfile::change_password(
                    storage,
                    old.as_bytes(),
                    new.as_bytes(),
                    kdf.params(current.params()),
                )
                .await?;
                println!("✅ Repository password changed. Existing backups are unchanged.");
                println!(
                    "ℹ️  Update RSB_ENCRYPTION_KEY / the OS keyring entry used by scheduled backups."
                );
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kdf_overrides() {
        assert_eq!(KdfArgs::default().params(KdfParams::DEFAULT), None);
        let k = KdfArgs {
            t_cost: Some(4),
            ..Default::default()
        };
        assert_eq!(
            k.params(KdfParams::DEFAULT),
            Some(KdfParams {
                t_cost: 4,
                ..KdfParams::DEFAULT
            })
        );
    }
}
