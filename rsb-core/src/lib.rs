pub mod config;
pub mod core;
pub mod credentials;
pub mod crypto;
pub mod realtime;
pub mod report;
pub mod s3_check;
pub mod storage;
pub mod utils;

pub use crate::core::cancellation::CancellationToken;
pub use config::{create_profile, load_config, Config};
pub use core::{perform_backup, perform_prune, perform_restore, perform_verify};
pub use credentials::{encryption, CredentialsManager, SecureString};
pub use realtime::{
    ChangeQueue, ChangeType, FileChange, RealtimeSync, RealtimeWatcher, SyncStats, SyncStrategy,
};
pub use s3_check::verify_s3_connection;
