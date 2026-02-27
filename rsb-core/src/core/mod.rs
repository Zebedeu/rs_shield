// Re-exporta tudo para facilitar uso externo (ex: rsb_core::core::perform_backup)

pub mod types;
pub mod resource_monitor;
pub mod file_processor;
pub mod manifest;
pub mod backup;
pub mod restore;
pub mod verify;
pub mod prune;
pub mod storage_backend;
pub mod email_notifications;
pub mod notification_logger;
pub mod notification_history;
pub mod chat_integrations;
pub mod cancellation;

pub use backup::{perform_backup, perform_backup_with_cancellation};
pub use restore::{perform_restore, perform_restore_with_cancellation};
pub use verify::{perform_verify, perform_verify_with_cancellation};
pub use prune::perform_prune;
pub use email_notifications::{EmailConfig, EmailNotification, send_email_notification, send_email_notification_blocking};
pub use notification_logger::{NotificationLogger, NotificationLogEntry};
pub use notification_history::{NotificationHistory, NotificationHistoryEntry, HistorySummary};
pub use chat_integrations::{ChatIntegration, send_chat_notification, send_chat_notification_blocking};
pub use storage_backend::get_storage;
pub use cancellation::CancellationToken;
