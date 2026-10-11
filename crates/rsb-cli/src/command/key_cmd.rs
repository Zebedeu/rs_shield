//! `rsb key ...`: repository key file (`keys/repo.key`, format v3).
//!
//! Secrets are only ever read from an interactive prompt: there are no
//! password arguments (they would end up in `ps` and shell history).

use crate::helpers::resolve_profile_path;
use anyhow::{Result, anyhow};
use clap::{Args, Subcommand};
use rsb_sdk::CancellationToken;
use rsb_sdk::crypto::keyfile::{self, KdfParams, REPO_KEY_PATH};
use rsb_sdk::crypto::lifecycle;
use rsb_sdk::storage::{LocalStorage, Storage};
use std::io::{IsTerminal, Write};
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
        /// Re-encrypt existing v1/v2 data as v3 without asking (for scripts)
        #[arg(long)]
        yes: bool,
    },

    /// Re-encrypt every v1/v2 (pre-v3) object and manifest as v3, verify
    /// the repository, then drop the legacy password from the key file.
    /// Resumable: run it again after an interruption.
    Migrate {
        #[command(flatten)]
        target: RepoTarget,
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

/// Asks a yes/no question on the terminal (default: no).
fn confirm(question: &str) -> Result<bool> {
    print!("{} [y/N] ", question);
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(matches!(line.trim(), "y" | "Y" | "yes" | "YES" | "Yes"))
}

fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{} B", n)
    } else {
        format!("{:.1} {}", v, UNITS[u])
    }
}

/// Progress on stderr (one line, rewritten) and Ctrl-C → cancellation.
fn progress_and_cancel() -> (rsb_sdk::core::types::ProgressCallback, CancellationToken) {
    let token = CancellationToken::new();
    let t = token.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            eprintln!(
                "\n⏹️  Stopping after the current object (run the command again to resume)..."
            );
            t.cancel();
        }
    });
    let cb: rsb_sdk::core::types::ProgressCallback = Arc::new(|i, total, msg: String| {
        let short: String = msg.chars().take(60).collect();
        eprint!("\r\x1b[2K  [{}/{}] {}", i + 1, total, short);
    });
    (cb, token)
}

async fn run_migration(storage: Arc<dyn Storage>, pw: &[u8]) -> Result<()> {
    let (cb, token) = progress_and_cancel();
    let rep = lifecycle::migrate_legacy_objects(storage, pw, Some(cb), Some(token)).await;
    eprintln!();
    let rep = rep?;
    println!(
        "✅ Migration complete: {} object(s) re-encrypted as v3 ({} already v3), {} manifest(s) \
         rewritten, {} object(s) verified.",
        rep.objects_migrated, rep.objects_already_v3, rep.manifests_rewritten, rep.objects_verified
    );
    if rep.legacy_secret_removed {
        println!(
            "🔑 The legacy (v1/v2) password was removed from {}.",
            REPO_KEY_PATH
        );
    }
    if !rep.unreferenced_legacy.is_empty() {
        println!(
            "ℹ️  {} v1/v2 object(s) are not referenced by any snapshot (prune garbage-collects them).",
            rep.unreferenced_legacy.len()
        );
    }
    if !rep.unreadable_legacy.is_empty() {
        println!(
            "⚠️  {} unreferenced object(s) could not be decrypted and were left as they are:",
            rep.unreadable_legacy.len()
        );
        for p in rep.unreadable_legacy.iter().take(10) {
            println!("     {}", p);
        }
    }
    Ok(())
}

fn print_legacy_summary(s: &lifecycle::LegacySummary) {
    println!(
        "This repository holds {} v1/v2 (pre-v3) object(s) ({}) and {} v1/v2 manifest(s).",
        s.objects,
        human_bytes(s.bytes),
        s.manifests
    );
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
            KeyCommand::Init { target, kdf, yes } => {
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
                keyfile::init_repo_key(storage.clone(), pw.as_bytes(), params).await?;
                println!("✅ Created {} (format v3).", REPO_KEY_PATH);
                println!(
                    "⚠️  Losing {} makes every v3 backup unreadable: keep a copy of it \
                     (`rsb key export`).",
                    REPO_KEY_PATH
                );
                let summary = lifecycle::legacy_summary(&*storage).await?;
                if !summary.is_empty() {
                    print_legacy_summary(&summary);
                    let go = if *yes {
                        true
                    } else if std::io::stdin().is_terminal() {
                        confirm("Re-encrypt them as v3 now (recommended)?")?
                    } else {
                        false
                    };
                    if go {
                        run_migration(storage, pw.as_bytes()).await?;
                    } else {
                        println!(
                            "ℹ️  Run `rsb key migrate` to re-encrypt them; until then the password \
                             cannot be changed."
                        );
                    }
                }
            }
            KeyCommand::Migrate { target } => {
                let storage = open_storage(target).await?;
                let pw = prompt("Repository password: ")?;
                let summary = lifecycle::legacy_summary(&*storage).await?;
                print_legacy_summary(&summary);
                run_migration(storage, pw.as_bytes()).await?;
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
