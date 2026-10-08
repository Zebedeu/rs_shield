use anyhow::Result;
use chrono::Local;
use clap::Parser;
use rsb_cli::command::list_profiles_cmd::{ListProfilesCmd, OutputFormat};
use rsb_cli::command::main_cmd::{Commands, ListProfilesFormat, StorageChoice};
use rsb_cli::helpers::{obtain_encryption_key, profile_name, resolve_profile_path, warn_secret_arg};
use rsb_sdk::backup::diagnostic::{print_diagnostics, run_backup_diagnostics, sync_changed_files};
use rsb_sdk::backup::perform_backup;
use rsb_sdk::integrity::perform_verify;
use rsb_sdk::server;
use rsb_sdk::server::LoginFlow;
use rsb_sdk::server::routes::check_fido2_auth;
use rsb_sdk::utils::{calculate_retention_backups, ensure_directory_exists, send_healthcheck};
use rsb_sdk::{config, core, credentials::Fido2Manager};
use std::fs;
use std::io::IsTerminal;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{Level, info, warn};

#[derive(Parser)]
#[command(
    name = "rsb-cli",
    version = "0.1.0-alpha.4",
    about = "Rust Shield Backup"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt().with_max_level(Level::WARN).init();

    let cli = Cli::parse();

    match cli.command {
        Commands::CreateProfile {
            name,
            source,
            dest,
            mode,
            compression,
            encrypt,
            password,
            exclude,
            s3_bucket,
            s3_region,
            s3_endpoint,
            portable,
        } => {
            if !source.exists() {
                return Err(format!("Source path does not exist: {}", source.display()).into());
            }
            if !std::path::Path::new(&dest).exists() {
                warn!(
                    "Destination path does not exist, creating: {}",
                    dest.display()
                );
                ensure_directory_exists(
                    dest.to_str()
                        .ok_or("Invalid path characters in destination")?,
                )?;
            }

            // Handle encryption password: é guardada no keyring do SO (nunca no
            // TOML). Sem TTY e sem -k, o perfil fica só com encrypt_patterns e a
            // chave terá de vir de RSB_ENCRYPTION_KEY no momento do backup.
            if password.is_some() {
                warn_secret_arg("-k/--password");
            }
            let encryption_pwd = if encrypt {
                if let Some(pwd) = password {
                    Some(pwd)
                } else if std::io::stdin().is_terminal() {
                    // Prompt for password if encryption enabled but not provided
                    use rpassword::prompt_password;
                    let pwd = prompt_password(
                        "Enter encryption password (stored in OS keyring; empty = use RSB_ENCRYPTION_KEY at backup time): ",
                    )?;
                    if pwd.is_empty() {
                        None
                    } else {
                        let confirm = prompt_password("Confirm password: ")?;
                        if pwd != confirm {
                            return Err("Passwords do not match".into());
                        }
                        Some(pwd)
                    }
                } else {
                    None
                }
            } else {
                None
            };

            // Convert paths to relative if portable mode is enabled
            let (source_for_profile, dest_for_profile) = if portable {
                let source_rel = source
                    .canonicalize()
                    .ok()
                    .and_then(|p| pathdiff::diff_paths(&p, std::env::current_dir().ok()?))
                    .unwrap_or(source.clone());
                let dest_rel = dest
                    .canonicalize()
                    .ok()
                    .and_then(|p| pathdiff::diff_paths(&p, std::env::current_dir().ok()?))
                    .unwrap_or(dest.clone());
                (source_rel, dest_rel)
            } else {
                (source.clone(), dest.clone())
            };

            config::create_profile_with_options(
                &name,
                &source_for_profile,
                &dest_for_profile,
                Some(mode.as_str()),
                Some(compression),
                encrypt,
                encryption_pwd.as_deref(),
                exclude.as_deref(),
                s3_bucket.as_deref(),
                s3_region.as_deref(),
                s3_endpoint.as_deref(),
            )?;
            let config_file = format!("{}.toml", name);
            println!("✅ Profile '{}' created: {}", name, config_file);
            if portable {
                println!("📱 Portable mode enabled: using relative paths");
                println!("   This profile can be moved between computers!");
            }
            println!("📋 Next step, execute backup:");
            println!("   rsb backup {}", config_file);
        }
        Commands::Backup {
            config,
            backup,
            mode,
            key,
            storage,
            dry_run,
            no_resume,
            verify,
            no_compress,
            threads,
            report,
            healthcheck_url,
        } => {
            let _auth_token = check_fido2_auth().await?;

            // Resolve config or backup path (nunca Cargo.toml; erro se ambíguo)
            let config_path = resolve_profile_path(config, backup)?;

            if !config_path.exists() {
                eprintln!(
                    "❌ Error: Configuration file not found: {}",
                    config_path.display()
                );
                eprintln!();
                eprintln!("📋 Create a new profile first:");
                eprintln!("   rsb create-profile mybackup /path/to/source /path/to/destination");
                eprintln!();
                eprintln!("   This will generate 'mybackup.toml'");
                eprintln!();
                eprintln!("   Then execute backup:");
                eprintln!("   rsb backup mybackup.toml");
                return Err(
                    format!("Configuration file not found: {}", config_path.display()).into(),
                );
            }

            let mut cfg = config::load_config(&config_path)?;

            if let Some(level) = cfg.compression_level {
                config::validate_compression_level(level)?;
            }

            // Storage: --storage > configuração do perfil. Só se pergunta em
            // modo interativo (TTY) quando o perfil não tem S3 configurado;
            // em cron/systemd nunca se lê stdin.
            let s3_configured = cfg
                .s3
                .as_ref()
                .and_then(|s| s.bucket.as_ref())
                .is_some()
                || cfg.s3_bucket.is_some();
            let interactive = std::io::stdin().is_terminal();
            let choice = match storage {
                Some(c) => c,
                None if s3_configured => StorageChoice::S3,
                None if interactive => {
                    println!("\n💾 Backup Storage Type (profile has no S3 configured)");
                    println!("   1. S3 or S3-compatible (AWS, MinIO, Wasabi, etc.)");
                    println!("   2. Local storage (local filesystem) [default]");
                    print!("\nChoose storage type (1 or 2): ");
                    use std::io::Write;
                    std::io::stdout().flush()?;

                    let mut response = String::new();
                    std::io::stdin().read_line(&mut response)?;
                    if response.trim() == "1" {
                        StorageChoice::S3
                    } else {
                        StorageChoice::Local
                    }
                }
                None => StorageChoice::Local,
            };

            match choice {
                StorageChoice::S3 => {
                    if !s3_configured {
                        if !interactive {
                            return Err(
                                "--storage s3 requested but the profile has no S3 configuration (run interactively to configure it)"
                                    .into(),
                            );
                        }
                        println!("\n📦 Configuring S3 Storage");
                        println!("   Please provide bucket name, region, and endpoint URL...\n");
                        config::prompt_for_s3_config(&config_path)?;
                        cfg = config::load_config(&config_path)?;
                        println!("✅ S3 configuration updated.");
                    }
                    println!("✅ Using S3 storage. Starting backup...\n");
                }
                StorageChoice::Local => {
                    cfg.s3 = None;
                    cfg.s3_bucket = None;
                    cfg.s3_region = None;
                    cfg.s3_endpoint = None;
                    println!("✅ Using local storage. Starting backup...\n");
                }
            }

            // Chave: falha (em vez de backup em claro) se o perfil exige cifra.
            let profile = profile_name(&config_path);
            let key = obtain_encryption_key(
                key,
                profile.as_deref(),
                Some(&cfg),
                cfg.encryption_required(),
            );
            let key = match key {
                Ok(k) => k,
                Err(e) => {
                    // Sinalizar falha no healthcheck (ex.: cron sem chave).
                    send_healthcheck(&healthcheck_url, "/fail").await;
                    return Err(e.into());
                }
            };

            send_healthcheck(&healthcheck_url, "/start").await;

            let resume = !no_resume;
            let backup_mode = mode.as_deref().unwrap_or("incremental");

            // Apply no-compress option if set
            if no_compress {
                cfg.compression_level = Some(0);
            }

            // ⚡ CLI option priority: CLI args > Config file > Default
            // Merge CLI options with config, allowing CLI to override config
            let effective_threads = threads.or(cfg.max_threads);

            if let Some(t) = effective_threads {
                if t > 4 {
                    println!("📊 Using {} parallel threads for backup", t);
                }
            }

            // Debug info
            println!("📂 Source: {}", cfg.source_path);
            println!("💾 Destination: {}", cfg.destination_path);
            if !cfg.exclude_patterns.is_empty() {
                println!("🚫 Exclude patterns: {}", cfg.exclude_patterns.join(", "));
            }
            println!();

            let mut report_data = match perform_backup(
                &cfg,
                backup_mode,
                key.as_deref(),
                dry_run,
                resume,
                effective_threads, // ⚡ Use merged option
                None,
            )
            .await
            {
                Ok(data) => data,
                Err(e) => {
                    send_healthcheck(&healthcheck_url, "/fail").await;
                    return Err(e);
                }
            };

            // Verify backup if requested
            if verify && !dry_run {
                println!("🔍 Verifying backup integrity...");
                match perform_verify(&cfg, None, false, false, None, None).await {
                    Ok(verify_report) => {
                        println!(
                            "✅ Verification passed: {} files verified",
                            verify_report.total_files
                        );
                        report_data.files_processed = verify_report.total_files;
                    }
                    Err(e) => {
                        send_healthcheck(&healthcheck_url, "/fail").await;
                        return Err(format!("❌ Backup verification failed: {}", e).into());
                    }
                }
            }

            send_healthcheck(&healthcheck_url, "").await;
            println!("✅ Backup completed.");

            if report {
                report_data.profile_path = config_path.to_string_lossy().to_string();
                let html = rsb_sdk::report::generate_html(&report_data);
                let filename = PathBuf::from(format!(
                    "rsb-report-backup-{}.html",
                    Local::now().format("%Y%m%d-%H%M%S")
                ));
                fs::write(&filename, html)?;
                println!("📄 Report generated at: {}", filename.display());
            }
        }

        Commands::Restore {
            config,
            backup,
            snapshot,
            target,
            key,
            force,
            versioned,
            report,
            files,
            date,
            verify,
        } => {
            let _auth_token = check_fido2_auth().await?;

            // Funcionalidades ainda não implementadas: falhar em vez de ignorar
            // silenciosamente (restauraria tudo / o snapshot errado).
            if files.is_some() {
                return Err(
                    "❌ --files (selective restore) is not yet supported; omit it to restore the whole snapshot"
                        .into(),
                );
            }
            if date.is_some() {
                return Err(
                    "❌ --date is not yet supported; use --snapshot <ID> (see `rsb snapshots list`)"
                        .into(),
                );
            }

            if key.is_some() {
                warn_secret_arg("--key");
            }
            let key = config::resolve_encryption_key(
                key,
                config.as_deref().and_then(profile_name).as_deref(),
                None,
            );

            // Either config or backup must be provided
            let (cfg, _profile_name) = if let Some(ref config_path) = config {
                // Traditional mode: use config file
                let cfg = config::load_config(&config_path)?;
                let name = config_path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("default")
                    .to_string();
                (cfg, name)
            } else if let Some(ref backup_path) = backup {
                // Direct backup mode: use portable restore function
                if !backup_path.exists() {
                    eprintln!("❌ Error: Backup path not found: {}", backup_path.display());
                    return Err(format!("Backup not found: {}", backup_path.display()).into());
                }

                println!("📁 Restoring from backup: {}", backup_path.display());

                // Validate backup structure before attempting restore
                let validation = rsb_sdk::validate_backup_structure(backup_path);
                if !validation.is_valid {
                    eprintln!("⚠️  Backup validation issues detected:");
                    for issue in &validation.issues {
                        eprintln!("  ❌ {}", issue);
                    }
                    for warning in &validation.warnings {
                        eprintln!("  ⚠️  {}", warning);
                    }
                    println!("💡 Suggestions:");
                    for suggestion in &validation.suggestions {
                        println!("  • {}", suggestion);
                    }
                    return Err("Backup validation failed".into());
                }

                println!(
                    "✅ Backup validation passed. Found {} snapshots, {} data files",
                    validation.snapshots_count, validation.data_files_count
                );

                // Create config using portable restore function
                let cfg = rsb_sdk::config_from_backup_path(backup_path, key.clone())
                    .map_err(|e| format!("Failed to create config from backup: {}", e))?;

                let name = backup_path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("backup")
                    .to_string();
                (cfg, name)
            } else {
                return Err(
                    "❌ Error: Either --config or --backup is required for restore operation"
                        .into(),
                );
            };

            // Clone target for potential later use in verification
            let target_for_verify = target.clone();

            let key = key.or_else(|| cfg.encryption_key.clone());
            let mut report_data = core::perform_restore(
                &cfg,
                snapshot.as_deref(),
                target,
                key.as_deref(),
                force,
                versioned,
                None,
            )
            .await?;

            // Verify restored files if requested
            if verify {
                println!("🔍 Verifying restored files integrity...");

                // Run verification on the backup data to ensure integrity
                match perform_verify(&cfg, snapshot.as_deref(), false, false, None, None).await {
                    Ok(verify_report) => {
                        println!("✅ Verification passed!");
                        println!("   📊 Snapshots verified: {}", verify_report.total_files);
                        println!("   ✔️  Files processed: {}", verify_report.files_processed);

                        // Merge verification data into restore report
                        report_data.total_files = verify_report.total_files;
                        report_data.files_processed = verify_report.files_processed;
                    }
                    Err(e) => {
                        eprintln!("   Files may have integrity issues. Please review manually.");
                        return Err(format!("❌ Restore verification failed: {}", e).into());
                    }
                }
            }

            println!("✅ Restore completed.");

            if report {
                report_data.profile_path = if let Some(ref cfg_path) = config {
                    cfg_path.to_string_lossy().to_string()
                } else if let Some(ref backup_path) = backup {
                    format!("Backup: {}", backup_path.display())
                } else {
                    "Unknown".to_string()
                };

                let html = rsb_sdk::report::generate_html(&report_data);

                let filename = PathBuf::from(format!(
                    "rsb-report-restore-{}.html",
                    Local::now().format("%Y%m%d-%H%M%S")
                ));

                fs::write(&filename, html)?;

                println!("📄 Report generated at: {}", filename.display());
            }
        }
        Commands::Verify {
            config,
            backup,
            snapshot,
            quiet,
            quick,
            fast,
            report,
            key,
        } => {
            let _auth_token = check_fido2_auth().await?;

            if key.is_some() {
                warn_secret_arg("--key");
            }
            let key = config::resolve_encryption_key(
                key,
                config.as_deref().and_then(profile_name).as_deref(),
                None,
            );

            // Determine verification mode: config or backup path
            let (cfg, profile_path) = if let Some(config_path) = config {
                // Verify via profile
                let mut cfg = config::load_config(&config_path)?;
                if let Some(k) = key {
                    cfg.encryption_key = Some(k);
                }
                (cfg, config_path.to_string_lossy().to_string())
            } else if let Some(backup_path) = backup {
                // Verify via direct backup path using portable restore function
                if !backup_path.exists() {
                    eprintln!("❌ Error: Backup path not found: {}", backup_path.display());
                    return Err(format!("Backup not found: {}", backup_path.display()).into());
                }
                // Create config using portable restore function
                let cfg = rsb_sdk::config_from_backup_path(&backup_path, key.clone())
                    .map_err(|e| format!("Failed to create config from backup: {}", e))?;
                (cfg, format!("Backup: {}", backup_path.display()))
            } else {
                return Err(
                    "❌ Error: Either --config <FILE> or --backup <PATH> is required".into(),
                );
            };

            // Use quick mode if requested (quick takes precedence over fast)
            let use_fast = quick || fast;
            if quick && fast {
                println!("Using quick verification (--quick takes precedence)");
            } else if quick {
                println!("Using quick verification mode");
            } else if fast {
                println!("Using fast verification mode (hash only, no decryption)");
            }

            let mut report_data =
                perform_verify(&cfg, snapshot.as_deref(), quiet, use_fast, None, None).await?;
            println!("✅ Verification completed.");

            if report {
                report_data.profile_path = profile_path;
                let html = rsb_sdk::report::generate_html(&report_data);
                let filename = PathBuf::from(format!(
                    "rsb-report-verify-{}.html",
                    Local::now().format("%Y%m%d-%H%M%S")
                ));
                fs::write(&filename, html)?;
                println!("📄 Report generated at: {}", filename.display());
            }
        }
        Commands::Prune {
            config,
            backup,
            keep_last,
            retention,
            dry_run,
            confirm,
            quiet,
            healthcheck_url,
        } => {
            if !dry_run && !confirm {
                return Err(
                    "Refusing destructive prune without --confirm (or preview with --dry-run). Re-run with --confirm to proceed."
                        .into(),
                );
            }
            let _auth_token = check_fido2_auth().await?;
            send_healthcheck(&healthcheck_url, "/start").await;

            // Resolve config or backup path (nunca Cargo.toml; erro se ambíguo)
            let config_path = resolve_profile_path(config, backup)?;

            let cfg = config::load_config(&config_path)?;

            // Determine the number of backups to keep
            let keep_count = if let Some(count) = keep_last {
                count
            } else if let Some(ref policy) = retention {
                // Parse retention policy (e.g., "30d", "6m", "1y") or number
                // Attempt to parse as a number first (e.g., "10" -> 10 backups)
                if let Ok(num) = policy.parse::<usize>() {
                    num
                } else {
                    // Parse time-based retention policies
                    // Examples: "30d" = 30 days, "6m" = 6 months, "1y" = 1 year
                    calculate_retention_backups(policy)
                }
            } else {
                // Default to keeping last 10 backups if neither specified
                10
            };

            if dry_run {
                println!("DRY RUN MODE: Would keep last {} backups", keep_count);
            } else {
                println!("🧹 Keeping last {} backups...", keep_count);
            }

            if !dry_run {
                if let Err(e) = core::perform_prune(&cfg, keep_count).await {
                    send_healthcheck(&healthcheck_url, "/fail").await;
                    return Err(e);
                }
            }
            send_healthcheck(&healthcheck_url, "").await;
            info!("Prune completed.");
        }
        Commands::Schedule {
            config,
            backup,
            format,
        } => {
            // Resolve config or backup path (nunca Cargo.toml; erro se ambíguo)
            let config_path = resolve_profile_path(config, backup)?;

            let abs_config = std::fs::canonicalize(&config_path).unwrap_or(config_path.clone());
            let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("rsb"));

            let exe_str = format!("\"{}\"", exe.display());
            let config_str = format!("\"{}\"", abs_config.display());

            // Nunca gerar `--key` na linha de comando (visível em `ps`, crontab,
            // journal). A chave vem de RSB_ENCRYPTION_KEY num ficheiro 0600.
            let env_file = dirs::home_dir()
                .map(|h| h.join(".rs-shield").join("rsb-backup.env"))
                .unwrap_or_else(|| PathBuf::from("rsb-backup.env"));
            let env_file_str = env_file.display().to_string();
            let key_env = config::ENCRYPTION_KEY_ENV;

            if format == "cron" {
                println!("# 1) Store the encryption key in a file readable only by you:");
                println!(
                    "#    (umask 077 && printf '{}=%s\\n' 'YOUR_KEY' > \"{}\")",
                    key_env, env_file_str
                );
                println!("# 2) Add this line to your crontab (crontab -e):");
                println!(
                    "0 3 * * * set -a && . \"{}\" && set +a && {} backup {} --storage local",
                    env_file_str, exe_str, config_str
                );
                println!("# (use --storage s3 if the profile backs up to S3)");
            } else if format == "systemd" {
                println!("# 1) Create {} with mode 0600 containing:", env_file_str);
                println!("#    {}=YOUR_KEY", key_env);
                println!("# 2) Example rsb-backup.service:");
                println!(
                    "[Service]\nType=oneshot\nEnvironmentFile={}\nExecStart={} backup {} --storage local",
                    env_file_str, exe_str, config_str
                );
            } else {
                return Err("Unknown format. Use 'cron' or 'systemd'.".into());
            }
        }
        Commands::Watch {
            config,
            backup,
            sync_to,
            key,
            interval,
            healthcheck_url,
        } => {
            let _auth_token = check_fido2_auth().await?;

            // Resolve config or backup path (nunca Cargo.toml; erro se ambíguo)
            let config_path = resolve_profile_path(config, backup)?;

            let mut cfg = config::load_config(&config_path)?;
            // Watch sempre cifra: sem chave disponível → erro (nunca em claro).
            let profile = profile_name(&config_path);
            let key = obtain_encryption_key(key, profile.as_deref(), Some(&cfg), true)?
                .ok_or("Encryption key required")?;
            cfg.encryption_key = Some(key);

            if let Some(url) = healthcheck_url {
                let url_clone = url.clone();
                tokio::spawn(async move {
                    send_healthcheck(&Some(url_clone.clone()), "/start").await;
                    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(300));
                    loop {
                        interval.tick().await;
                        send_healthcheck(&Some(url_clone.clone()), "").await;
                    }
                });
            }

            let source = PathBuf::from(&cfg.source_path);
            let sync_dst = sync_to;
            let backup_dst = PathBuf::from(&cfg.destination_path);

            println!("🟢 Real-Time Sync started");
            println!("📂 Source: {}", source.display());
            println!("📁 Syncing to: {}", sync_dst.display());
            println!("💾 Backup to: {}", backup_dst.display());
            println!("⏱️ Interval: {}s", interval);
            println!("🔐 Encryption: ENABLED");
            println!("\nPress Ctrl+C to stop\n");
            let mut total_changes = 0;
            let mut backups_count = 0;

            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(interval)).await;

                match sync_changed_files(&source, &sync_dst).await {
                    Ok(copied_count) => {
                        if copied_count > 0 {
                            total_changes += copied_count;
                            println!("✅ Sync: {} new/modified files synchronized.", copied_count);

                            // ⚡ Use config max_threads for watch mode
                            let watch_threads = cfg.max_threads;

                            match perform_backup(
                                &cfg,
                                "incremental",
                                Some(cfg.encryption_key.as_ref().unwrap()),
                                false,
                                false,
                                watch_threads, // ⚡ Use config value instead of None
                                None,
                            )
                            .await
                            {
                                Ok(report) => {
                                    backups_count += 1;
                                    println!(
                                        "💾 Backup #{}: {} files total, {} processed",
                                        backups_count, report.total_files, report.files_processed
                                    );
                                }
                                Err(e) => {
                                    eprintln!("❌ Backup error: {}", e);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("❌ Sync error: {}", e);
                    }
                }

                println!(
                    "📊 Total: {} changes detected, {} backups created",
                    total_changes, backups_count
                );
                println!("---");
            }
        }

        Commands::Server { port } => {
            // Dummy sender since we're running server standalone

            let (tx, _rx) = tokio::sync::oneshot::channel();
            server::routes::start_auth_server(port, tx).await?;
        }

        Commands::Login { user_id, recovery } => {
            if recovery {
                // Recovery code flow
                println!("\n🔐 Recovery Code Authentication");
                println!("================================\n");

                use rpassword::prompt_password;

                print!("Enter recovery code: ");
                use std::io::Write;
                std::io::stdout().flush()?;

                let recovery_code = prompt_password("")?;

                if recovery_code.is_empty() {
                    return Err("❌ Recovery code cannot be empty".into());
                }

                // Load Fido2Manager and verify recovery code
                let mut fido2_manager =
                    Fido2Manager::new("http://localhost:3000", "localhost", "RSB CLI")?;

                // Sem credenciais carregadas não há códigos para verificar;
                // falhar aqui evita mascarar erros de keyring/ficheiro.
                let cred_path = Fido2Manager::default_storage_path()
                    .map_err(|e| format!("❌ Cannot locate credential storage: {}", e))?;
                if !cred_path.exists() {
                    return Err("❌ No FIDO2 credentials found; recovery is not possible".into());
                }
                fido2_manager
                    .load_from_file(&cred_path)
                    .map_err(|e| format!("❌ Could not load credentials: {}", e))?;

                // Verify recovery code
                if fido2_manager.verify_backup_code(&user_id, &recovery_code) {
                    // Save the updated manager (recovery code was consumed).
                    // Se não for possível persistir o consumo, o código continuaria
                    // reutilizável → não emitir token.
                    fido2_manager.save_to_file(&cred_path).map_err(|e| {
                        format!(
                            "❌ Failed to persist consumed recovery code ({}); no token issued",
                            e
                        )
                    })?;

                    // Create and save token
                    let jwt_mgr = rsb_sdk::auth::JwtManager::from_env()?;
                    let scopes = vec!["backup".to_string(), "restore".to_string()];
                    let token = jwt_mgr.create_token(&user_id, scopes.clone(), 1800)?;
                    // check_fido2_auth só aceita tokens cujo jti esteja no registo
                    // de sessões persistido.
                    let claims = jwt_mgr.verify_token(&token)?;
                    rsb_sdk::auth::SessionRegistry::default_registry()?
                        .record_claims(&claims)?;

                    println!("\n✅ Recovery code verified successfully!");
                    println!("🔑 User: {}", user_id);
                    println!("📋 Scopes: {:?}\n", scopes);

                    let auth_file = save_auth_token(&token)?;

                    info!("✅ Authentication successful with recovery code!");
                    info!("📍 Token saved to: {}", auth_file.display());
                    println!("✅ You are now authenticated!");
                    println!("📍 Token saved to: {}\n", auth_file.display());
                    println!("You can now use: rsb backup, rsb restore, rsb verify\n");
                    println!("⚠️ IMPORTANT: Generate new recovery codes soon!");
                    println!("   Use: rsb auth generate-codes\n");
                } else {
                    return Err("❌ Invalid or already used recovery code".into());
                }
            } else {
                // FIDO2 flow (original)
                let mut login_flow = LoginFlow::new();

                match login_flow.start(user_id.clone()).await {
                    Ok(token) => {
                        // Verify and save token
                        let jwt_mgr = rsb_sdk::auth::JwtManager::from_env()?;
                        match jwt_mgr.verify_token(&token) {
                            Ok(claims) => {
                                println!("🔑 User: {}", claims.sub);
                                println!("📋 Scopes: {:?}\n", claims.scopes);

                                let auth_file = save_auth_token(&token)?;

                                info!("✅ Authentication successful!");
                                info!("📍 Token saved to: {}", auth_file.display());
                                println!("✅ You are now authenticated!");
                                println!("📍 Token saved to: {}\n", auth_file.display());
                                println!("You can now use: rsb backup, rsb restore, rsb verify\n");
                            }
                            Err(e) => {
                                eprintln!("❌ Invalid token received: {:?}", e);
                                return Err("❌ Failed to validate token".into());
                            }
                        }

                        // Shutdown server gracefully
                        login_flow.shutdown().await;
                    }
                    Err(e) => {
                        login_flow.shutdown().await;
                        return Err(format!("❌ Authentication failed: {}", e).into());
                    }
                }
            }
        }

        Commands::Fido2(cmd) => {
            let origin = "http://localhost:3000";
            let rp_id = "localhost";

            let manager = Fido2Manager::new(origin, rp_id, "RSB CLI")?;

            cmd.execute(Arc::new(Mutex::new(manager))).await?;
        }
        Commands::Snapshots(cmd) => {
            cmd.execute().await?;
        }

        Commands::ListProfiles { directory, format } => {
            let output_format = match format {
                ListProfilesFormat::Table => OutputFormat::Table,
                ListProfilesFormat::Json => OutputFormat::Json,
                ListProfilesFormat::Csv => OutputFormat::Csv,
            };
            ListProfilesCmd::execute(directory, output_format).await?;
        }
        Commands::Diagnose {
            backup,
            key,
            verbose,
            json: output_json,
            repair,
        } => {
            // --repair altera o backup: exige autenticação como os outros comandos mutáveis.
            if repair {
                let _auth_token = check_fido2_auth().await?;
            }
            if !backup.exists() {
                eprintln!("❌ Error: Backup path not found: {}", backup.display());
                return Err(format!("Backup not found: {}", backup.display()).into());
            }
            if key.is_some() {
                warn_secret_arg("--key");
            }
            let key = config::resolve_encryption_key(key, None, None);

            println!("🔍 Diagnosing backup: {}\n", backup.display());

            // Run diagnostics
            let diagnostics =
                run_backup_diagnostics(&backup, key.as_deref(), verbose, repair).await?;

            if output_json {
                // Output JSON format
                println!("{}", serde_json::to_string_pretty(&diagnostics)?);
            } else {
                // Output human-readable format
                print_diagnostics(&diagnostics);
            }
        }

        Commands::Config(cmd) => {
            cmd.execute().await?;
        }
    }

    Ok(())
}

/// Grava o token de sessão em ~/.rs-shield/auth_token (dir 0700, ficheiro 0600
/// criado já com essas permissões).
fn save_auth_token(token: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let home = dirs::home_dir().ok_or("❌ Home directory not found")?;
    let rsb_dir = home.join(".rs-shield");
    config::create_dir_secure(&rsb_dir)?;
    let auth_file = rsb_dir.join("auth_token");
    config::write_file_secure(&auth_file, token.as_bytes())?;
    Ok(auth_file)
}
