use crate::operation::operations::{NewOperation, OperationsManager, create_operation};

pub fn record_backup_operation(
    status: String,
    files_processed: usize,
    duration_secs: u64,
    backup_size: String,
    source: String,
    destination: String,
) -> Result<(), String> {
    let mut manager = OperationsManager::new();

    let operation = create_operation(NewOperation {
        operation_type: "Backup".to_string(),
        status,
        files_processed,
        files_skipped: 0,
        files_with_errors: 0,
        duration_secs,
        backup_size,
        source_path: Some(source),
        destination_path: Some(destination),
    });

    manager.add_operation(operation)
}

pub fn record_restore_operation(
    status: String,
    files_processed: usize,
    duration_secs: u64,
    source: String,
    destination: String,
) -> Result<(), String> {
    let mut manager = OperationsManager::new();

    let operation = create_operation(NewOperation {
        operation_type: "Restore".to_string(),
        status,
        files_processed,
        files_skipped: 0,
        files_with_errors: 0,
        duration_secs,
        backup_size: "N/A".to_string(),
        source_path: Some(source),
        destination_path: Some(destination),
    });

    manager.add_operation(operation)
}

pub fn record_verify_operation(
    status: String,
    files_processed: usize,
    files_with_errors: usize,
    duration_secs: u64,
    backup_path: String,
) -> Result<(), String> {
    let mut manager = OperationsManager::new();

    let operation = create_operation(NewOperation {
        operation_type: "Verify".to_string(),
        status,
        files_processed,
        files_skipped: 0,
        files_with_errors,
        duration_secs,
        backup_size: "N/A".to_string(),
        source_path: Some(backup_path),
        destination_path: None,
    });

    manager.add_operation(operation)
}

pub fn record_prune_operation(
    status: String,
    files_removed: usize,
    duration_secs: u64,
    space_freed: String,
    backup_path: String,
) -> Result<(), String> {
    let mut manager = OperationsManager::new();

    let operation = create_operation(NewOperation {
        operation_type: "Prune".to_string(),
        status,
        files_processed: files_removed,
        files_skipped: 0,
        files_with_errors: 0,
        duration_secs,
        backup_size: format!("Liberado: {}", space_freed),
        source_path: Some(backup_path),
        destination_path: None,
    });

    manager.add_operation(operation)
}
pub async fn record_schedule_operation(
    success: bool,
    error: Option<String>,
    duration_secs: Option<u64>,
) -> Result<(), String> {
    let mut manager = OperationsManager::new();

    let status = if success {
        "success".to_string()
    } else {
        format!("failed: {:?}", error)
    };
    let duration = duration_secs.unwrap_or(0);

    let operation = create_operation(NewOperation {
        operation_type: "Schedule".to_string(),
        status,
        files_processed: 0,
        files_skipped: 0,
        files_with_errors: if error.is_some() { 1 } else { 0 },
        duration_secs: duration,
        backup_size: "N/A".to_string(),
        source_path: None,
        destination_path: None,
    });

    manager.add_operation(operation)
}
