use clap::{Parser, Subcommand};
use std::fs;
use std::path::PathBuf;
use chrono::Local;
use tracing::{info, warn, Level};
use tracing_subscriber;
use rsb_core::{config, core};
use rsb_core::utils::ensure_directory_exists;
use keyring::Entry;
use rpassword;
use atty;

#[derive(Parser)]
#[command(name = "rsb", version = "0.1.0", about = "Rust Shield Backup")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a new backup profile
    CreateProfile {
        /// Profile name (generates config.toml)
        name: String,
        /// Source path
        source: PathBuf,
        /// Destination path
        dest: PathBuf,
    },
    /// Run backup with an existing profile
    Backup {
        /// Path to config.toml
        config: PathBuf,
        /// Mode: full or incremental
        #[arg(default_value = "incremental")]
        mode: String,
        /// Encryption key (optional)
        #[arg(short, long)]
        key: Option<String>,
        /// Simulate backup without writing files (dry-run)
        #[arg(long)]
        dry_run: bool,
        /// Do not attempt to resume an interrupted backup.
        #[arg(long)]
        no_resume: bool,
        /// Generate an HTML report of the operation.
        #[arg(long)]
        report: bool,
        /// Healthchecks.io URL for monitoring (sends start/success/fail pings)
        #[arg(long)]
        healthcheck_url: Option<String>,
    },
    /// Restore a backup with an existing profile
    Restore {
        /// Path to the profile's config.toml
        config: PathBuf,
        /// Snapshot ID to restore (default: most recent)
        #[arg(long)]
        snapshot: Option<String>,
        /// Path to restore to (default: source_path + "_restored")
        #[arg(short, long)]
        target: Option<PathBuf>,
        /// Decryption key (required if backup is encrypted)
        #[arg(short, long)]
        key: Option<String>,
        /// Force overwrite of existing files
        #[arg(short, long)]
        force: bool,
        /// Generate an HTML report of the operation.
        #[arg(long)]
        report: bool,
    },
    /// Verify a backup with an existing profile
    Verify {
        /// Path to config.toml
        config: PathBuf,
        /// Snapshot ID to verify (default: most recent)
        #[arg(long)]
        snapshot: Option<String>,
        /// Show only files with issues (quiet mode)
        #[arg(short, long)]
        quiet: bool,
        /// Fast verification (only stored file hash, no decryption)
        #[arg(long)]
        fast: bool,
        /// Generate an HTML report of the operation.
        #[arg(long)]
        report: bool,
        /// Decryption key (required if backup is encrypted)
        #[arg(short, long)]
        key: Option<String>,
    },
    /// Delete old snapshots according to retention policy
    Prune {
        /// Path to config.toml
        config: PathBuf,
        /// Keep the last N backups.
        #[arg(long, required = true)]
        keep_last: usize,
        /// Healthchecks.io URL for monitoring
        #[arg(long)]
        healthcheck_url: Option<String>,
    },
    /// Generate scheduling commands (Cron/Systemd)
    Schedule {
        /// Path to config.toml
        config: PathBuf,
        /// Output format: 'cron' or 'systemd'
        #[arg(long, default_value = "cron")]
        format: String,
    },
    /// Monitor folder in real-time and perform automatic backups
    Watch {
        /// Path to config.toml
        config: PathBuf,
        /// Path to sync files to (destination)
        #[arg(short, long)]
        sync_to: PathBuf,
        /// Encryption key (required)
        #[arg(short, long)]
        key: String,
        /// Check interval in seconds (default: 2)
        #[arg(long, default_value = "2")]
        interval: u64,
        /// Healthchecks.io URL for monitoring (sends heartbeats every 5 min)
        #[arg(long)]
        healthcheck_url: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt().with_max_level(Level::INFO).init();
    info!("Starting RSB");

    let cli = Cli::parse();

    match cli.command {
        Commands::CreateProfile { name, source, dest } => {
            // Validar que source existe
            if !source.exists() {
                return Err(format!("Source path does not exist: {}", source.display()).into());
            }
            if !std::path::Path::new(&dest).exists() {
                warn!("Destination path does not exist, creating: {}", dest.display());
                ensure_directory_exists(dest.to_str().ok_or("Invalid path characters in destination")?)?;
            }
            
            config::create_profile(&name, &source, &dest)?;
            let config_file = format!("{}.toml", name);
            info!("✅ Profile '{}' created: {}", name, config_file);
            info!("📋 Next step, execute backup:");
            info!("   rsb backup {}", config_file);
        }
        Commands::Backup { config, mode, key, dry_run, no_resume, report, healthcheck_url } => {
            // Validar que config file existe
            if !config.exists() {
                eprintln!("❌ Error: Configuration file not found: {}", config.display());
                eprintln!();
                eprintln!("📋 Create a new profile first:");
                eprintln!("   rsb create-profile mybackup /path/to/source /path/to/destination");
                eprintln!();
                eprintln!("   This will generate 'mybackup.toml'");
                eprintln!();
                eprintln!("   Then execute backup:");
                eprintln!("   rsb backup mybackup.toml");
                return Err(format!("Configuration file not found: {}", config.display()).into());
            }

            send_healthcheck(&healthcheck_url, "/start").await;

            let mut cfg = config::load_config(&config)?;
            let profile_name = config.file_stem().and_then(|s| s.to_str()).unwrap_or("default");
            
            // Ask user: S3 or Local Storage?
            println!("\n💾 Backup Storage Type");
            println!("   1. S3 or S3-compatible (AWS, MinIO, Wasabi, etc.)");
            println!("   2. Local storage (local filesystem)");
            print!("\nChoose storage type (1 or 2): ");
            use std::io::Write;
            std::io::stdout().flush()?;
            
            let mut response = String::new();
            std::io::stdin().read_line(&mut response)?;
            let use_s3 = response.trim() == "1";
            
            if use_s3 {
                // Always prompt for S3 configuration when user chooses S3
                // This allows updating existing configs or setting up new ones
                println!("\n📦 Configuring S3 Storage");
                println!("   Please provide bucket name, region, and endpoint URL...\n");
                config::prompt_for_s3_config(&config)?;
                // Reload config with S3 settings
                cfg = config::load_config(&config)?;
                println!("✅ S3 configuration updated. Starting backup...\n");
            } else {
                // Use local storage - clear any S3 config
                cfg.s3 = None;
                cfg.s3_bucket = None;
                cfg.s3_region = None;
                cfg.s3_endpoint = None;
                println!("✅ Using local storage. Starting backup...\n");
            }
            
            let resume = !no_resume;

            let mut report_data = match core::perform_backup(&cfg, &mode, key.as_deref(), dry_run, resume, None).await {
                Ok(data) => data,
                Err(e) => {
                    send_healthcheck(&healthcheck_url, "/fail").await;
                    return Err(e);
                }
            };
            send_healthcheck(&healthcheck_url, "").await;
            info!("Backup completed.");

            if report {
                report_data.profile_path = config.to_string_lossy().to_string();
                let html = rsb_core::report::generate_html(&report_data);
                let filename = PathBuf::from(format!("rsb-report-backup-{}.html", Local::now().format("%Y%m%d-%H%M%S")));
                fs::write(&filename, html)?;
                info!("Report generated at: {}", filename.display());
            }
        }
        Commands::Restore { config, snapshot, target, key, force, report } => {
            let mut cfg = config::load_config(&config)?;
            let profile_name = config.file_stem().and_then(|s| s.to_str()).unwrap_or("default");

            let mut report_data = core::perform_restore(&cfg, snapshot.as_deref(), target, key.as_deref(), force, None).await?;
            info!("Restore completed.");

            if report {
                report_data.profile_path = config.to_string_lossy().to_string();
                let html = rsb_core::report::generate_html(&report_data);
                let filename = PathBuf::from(format!("rsb-report-restore-{}.html", Local::now().format("%Y%m%d-%H%M%S")));
                fs::write(&filename, html)?;
                info!("Report generated at: {}", filename.display());
            }
        }
        Commands::Verify { config, snapshot, quiet, fast, report, key } => {
            let mut cfg = config::load_config(&config)?;

            if let Some(k) = key {
                cfg.encryption_key = Some(k);
            }

            let mut report_data = core::perform_verify(&cfg, snapshot.as_deref(), quiet, fast, None).await?;
            info!("Verification completed.");

            if report {
                report_data.profile_path = config.to_string_lossy().to_string();
                let html = rsb_core::report::generate_html(&report_data);
                let filename = PathBuf::from(format!("rsb-report-verify-{}.html", Local::now().format("%Y%m%d-%H%M%S")));
                fs::write(&filename, html)?;
                info!("Report generated at: {}", filename.display());
            }
        }
        Commands::Prune { config, keep_last, healthcheck_url } => {
            send_healthcheck(&healthcheck_url, "/start").await;
            let mut cfg = config::load_config(&config)?;

            if let Err(e) = core::perform_prune(&cfg, keep_last).await {
                send_healthcheck(&healthcheck_url, "/fail").await;
                return Err(e);
            }
            send_healthcheck(&healthcheck_url, "").await;
            info!("Prune completed.");
        }
        Commands::Schedule { config, format } => {
            let abs_config = std::fs::canonicalize(&config).unwrap_or(config.clone());
            let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("rsb"));

            // Quote paths to handle spaces (common on Windows/macOS)
            let exe_str = format!("\"{}\"", exe.display());
            let config_str = format!("\"{}\"", abs_config.display());

            if format == "cron" {
                println!("# Add this line to your crontab (crontab -e):");
                println!("0 3 * * * {} backup {} --key \"YOUR_PASSWORD\"", exe_str, config_str);
            } else if format == "systemd" {
                println!("# Example rsb-backup.service:");
                println!("[Service]\nType=oneshot\nExecStart={} backup {} --key \"YOUR_PASSWORD\"", exe_str, config_str);
            } else {
                println!("Unknown format. Use 'cron' or 'systemd'.");
            }
        }
        Commands::Watch { config, sync_to, key, interval, healthcheck_url } => {
            let mut cfg = config::load_config(&config)?;
            cfg.encryption_key = Some(key);

            // Start heartbeat task if URL is provided
            if let Some(url) = healthcheck_url {
                let url_clone = url.clone();
                tokio::spawn(async move {
                    send_healthcheck(&Some(url_clone.clone()), "/start").await;
                    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(300)); // 5 minutes
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

            let mut last_count = 0;
            let mut total_changes = 0;
            let mut backups_count = 0;

            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(interval)).await;

                // Sync files
                match sync_changed_files(&source, &sync_dst).await {
                    Ok(copied_count) => {
                        if copied_count > 0 {
                            total_changes += copied_count;
                            println!("✅ Sync: {} new/modified files synchronized.", copied_count);

                            // Perform automatic backup
                            match core::perform_backup(&cfg, "incremental", Some(&cfg.encryption_key.as_ref().unwrap()), false, false, None).await {
                                Ok(report) => {
                                    backups_count += 1;
                                    println!("💾 Backup #{}: {} files total, {} processed",
                                        backups_count, report.total_files, report.files_processed);
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

                println!("📊 Total: {} changes detected, {} backups created", total_changes, backups_count);
                println!("---");
            }
        }
    }

    Ok(())
}

// Helper function to sync files
async fn sync_changed_files(src: &PathBuf, dst: &PathBuf) -> Result<usize, String> {
    use std::time::SystemTime;
    use walkdir::WalkDir;

    if !src.exists() {
        return Err("Source folder does not exist".to_string());
    }

    let mut copied_count = 0;
    for entry in WalkDir::new(src)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let src_path = entry.path();
        if src_path.is_file() {
            let relative_path = src_path.strip_prefix(src).map_err(|e| e.to_string())?;
            let dst_path = dst.join(relative_path);

            if let Some(parent) = dst_path.parent() {
                ensure_directory_exists(parent.to_str().ok_or("Invalid path characters in destination")?)?;
            }

            let should_copy = if !dst_path.exists() {
                true
            } else {
                let src_meta = fs::metadata(src_path).map_err(|e| e.to_string())?;
                let dst_meta = fs::metadata(&dst_path).map_err(|e| e.to_string())?;
                src_meta.modified().unwrap_or(SystemTime::UNIX_EPOCH) > dst_meta.modified().unwrap_or(SystemTime::UNIX_EPOCH)
            };

            if should_copy {
                fs::copy(src_path, &dst_path)
                    .map_err(|e| format!("Error copying file: {}", e))?;
                copied_count += 1;
            }
        }
    }

    Ok(copied_count)
}

async fn send_healthcheck(url: &Option<String>, suffix: &str) {
    if let Some(base_url) = url {
        let target = format!("{}{}", base_url, suffix);
        let client = reqwest::Client::new();
        if let Err(e) = client.get(&target).timeout(std::time::Duration::from_secs(10)).send().await {
            warn!("Failed to send healthcheck to {}: {}", target, e);
        }
    }
}
