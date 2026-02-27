pub mod config;
pub mod core;
pub mod crypto;
pub mod report;
pub mod utils;
pub mod storage;
pub mod realtime;
pub mod s3_check;
pub mod credentials;

pub use core::{perform_backup, perform_restore, perform_verify, perform_prune};
pub use crate::core::cancellation::CancellationToken;
pub use config::{Config, create_profile, load_config};
pub use realtime::{RealtimeSync, RealtimeWatcher, ChangeQueue, FileChange, ChangeType, SyncStrategy, SyncStats};
pub use s3_check::verify_s3_connection;
pub use credentials::{SecureString, CredentialsManager, encryption};
