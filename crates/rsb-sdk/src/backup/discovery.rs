use crate::core::file_processor;
use crate::utils::{matches_exclude_pattern, walk_filtered};
use rayon::prelude::*;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

/// Discovers files to back up. Walker errors (unreadable directories,
/// permission denied, ...) are dropped here; prefer
/// [`discover_files_with_errors`] so they can be reported.
pub fn discover_files(
    source: &Path,
    exclude_patterns: &[String],
) -> Result<Vec<(PathBuf, PathBuf)>, Box<dyn std::error::Error>> {
    discover_files_with_errors(source, exclude_patterns).map(|(files, _)| files)
}

/// Like [`discover_files`], but also returns every walker error as a
/// message so the backup does not report a clean success when parts of the
/// source tree could not be read.
pub fn discover_files_with_errors(
    source: &Path,
    exclude_patterns: &[String],
) -> Result<(Vec<(PathBuf, PathBuf)>, Vec<String>), Box<dyn std::error::Error>> {
    if !source.exists() {
        return Err(format!("Source path does not exist: {}", source.display()).into());
    }

    if !source.is_dir() {
        return Err(format!("Source path is not a directory: {}", source.display()).into());
    }

    // Check read permissions
    match std::fs::read_dir(source) {
        Ok(_) => info!("✅ Source directory is readable: {}", source.display()),
        Err(e) => {
            return Err(format!(
                "Cannot read source directory: {} (error: {})",
                source.display(),
                e
            )
            .into());
        }
    }

    let walker = walk_filtered(source, exclude_patterns, true);
    let mut walk_errors: Vec<String> = Vec::new();

    let mut files: Vec<(PathBuf, PathBuf)> = walker
        .filter_map(|e| {
            match e {
                Ok(entry) => {
                    if entry.path().is_file() {
                        let full = entry.path().to_path_buf();
                        if let Ok(rel) = full.strip_prefix(source) {
                            let rel_path = rel.to_path_buf();
                            // Check exclusion patterns
                            for pattern in exclude_patterns {
                                if matches_exclude_pattern(&rel_path, pattern) {
                                    debug!("Excluding: {}", rel_path.display());
                                    return None;
                                }
                            }
                            return Some((full, rel_path));
                        }
                    }
                    None
                }
                Err(e) => {
                    warn!("Walker error: {}", e);
                    walk_errors.push(format!("Could not read part of the source tree: {}", e));
                    None
                }
            }
        })
        .collect();

    // Sort files by priority for more efficient processing
    files.par_sort_by_key(|(full, _)| file_processor::get_file_priority(full));

    info!(
        "📊 Found {} files to process from: {}",
        files.len(),
        source.display()
    );

    Ok((files, walk_errors))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discover_empty_directory() {
        let dir = tempfile::tempdir().unwrap();
        let (files, errors) = discover_files_with_errors(dir.path(), &[]).unwrap();
        assert!(files.is_empty());
        assert!(errors.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn test_unreadable_subdir_is_reported() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("ok.txt"), b"x").unwrap();
        let locked = dir.path().join("locked");
        std::fs::create_dir(&locked).unwrap();
        std::fs::write(locked.join("secret.txt"), b"y").unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        // Running as root bypasses permissions; only assert when it applies.
        let readable_anyway = std::fs::read_dir(&locked).is_ok();
        let (files, errors) = discover_files_with_errors(dir.path(), &[]).unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(files.iter().any(|(_, rel)| rel == Path::new("ok.txt")));
        if !readable_anyway {
            assert!(!errors.is_empty());
        }
    }
}
