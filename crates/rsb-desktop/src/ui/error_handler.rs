/// User-friendly error message handler
/// Masks technical errors and provides localized messages in English
use tracing::warn;

const SECURITY_KEY_ERROR: &str =
    "🔑 Security key error. Please reconnect your security key or verify the connection.";

fn is_security_key_error(e: &str) -> bool {
    ["fido", "webauthn", "ctap", "u2f", "security key", "security-key", "authenticator"]
        .iter()
        .any(|k| e.contains(k))
}

/// Convert technical error messages to user-friendly messages
/// Technical errors are logged but not shown to the user
pub fn format_user_error(error: impl std::fmt::Display, context: &str) -> String {
    let error_str = error.to_string().to_lowercase();

    // Log the real error for debugging
    warn!("[{}] Technical error: {}", context, error_str);

    // Return user-friendly message based on error type
    match error_str.as_str() {
        // Hardware security key (FIDO2/WebAuthn/CTAP) errors. Checked first so
        // e.g. "FIDO2 device timeout" or "WebAuthn credential not found" are not
        // reported as generic timeout/path errors.
        e if is_security_key_error(e) => SECURITY_KEY_ERROR.to_string(),

        // Network/Connection errors
        e if e.contains("connection refused") || e.contains("connection reset") => {
            "❌ Connection error. Please check your network and try again.".to_string()
        }
        e if e.contains("timeout") => {
            "⏱️ The operation took too long. Please try again.".to_string()
        }

        // Authentication errors
        e if e.contains("unauthorized") || e.contains("invalid token") => {
            "🔐 Authentication expired. Please authenticate again.".to_string()
        }
        e if e.contains("authentication failed") => {
            "❌ Authentication failed. Please verify your security key.".to_string()
        }

        // File/Path errors
        e if e.contains("not found") || e.contains("no such file") => {
            "📁 File or folder not found. Please verify the path.".to_string()
        }
        e if e.contains("permission denied") => {
            "🔒 Permission denied. Please check the folder permissions.".to_string()
        }
        e if e.contains("disk space") || e.contains("no space") => {
            "💾 Insufficient disk space. Free up some space and try again.".to_string()
        }

        // Encryption/Decryption errors
        e if e.contains("decryption") || e.contains("decrypt") => {
            "🔐 Failed to decrypt data. Please verify the encryption key.".to_string()
        }
        e if e.contains("encryption") || e.contains("encrypt") => {
            "🔐 Failed to encrypt data. Please try again.".to_string()
        }

        // Backup/Restore errors
        e if e.contains("backup") && e.contains("failed") => {
            "💾 Backup failed. Please check the destination and try again.".to_string()
        }
        e if e.contains("restore") && e.contains("failed") => {
            "📂 Restore failed. Please verify the snapshot and try again.".to_string()
        }

        // JSON/Format errors
        e if e.contains("json") || e.contains("parse") => {
            "📄 Failed to process data. Please try reloading the application.".to_string()
        }

        // Hardware/FIDO2 credential errors
        e if e.contains("credential") => SECURITY_KEY_ERROR.to_string(),

        // Recovery code errors
        e if e.contains("recovery") && e.contains("code") => {
            "🔐 Invalid or already used recovery code.".to_string()
        }

        // Server/API errors
        e if e.contains("500") || e.contains("internal server error") => {
            "🖥️ Server error. Please try again in a few moments.".to_string()
        }
        e if e.contains("503") || e.contains("service unavailable") => {
            "🖥️ Service temporarily unavailable. Please try again later.".to_string()
        }

        // Default: Generic error
        _ => "❌ An unexpected error occurred. Please try again.".to_string(),
    }
}

/// Format error message with specific operation context
pub fn format_operation_error(error: impl std::fmt::Display, operation: &str) -> String {
    let friendly_msg = format_user_error(&error, operation);

    // Add specific operation context if not already in the message
    match operation {
        "backup" => {
            if friendly_msg.contains("Backup") {
                friendly_msg
            } else {
                format!("💾 Backup error: {}", friendly_msg.replace("❌ ", ""))
            }
        }
        "restore" => {
            if friendly_msg.contains("Restore") {
                friendly_msg
            } else {
                format!("📂 Restore error: {}", friendly_msg.replace("❌ ", ""))
            }
        }
        "verify" => {
            if friendly_msg.contains("verification") {
                friendly_msg
            } else {
                format!("🔍 Verification error: {}", friendly_msg.replace("❌ ", ""))
            }
        }
        "auth" | "authentication" => {
            if friendly_msg.contains("Authentication") {
                friendly_msg
            } else {
                format!(
                    "🔐 Authentication error: {}",
                    friendly_msg.replace("❌ ", "")
                )
            }
        }
        "fido2" => {
            if friendly_msg.contains("security key") {
                friendly_msg
            } else {
                format!("🔑 Security key error: {}", friendly_msg.replace("❌ ", ""))
            }
        }
        _ => friendly_msg,
    }
}

/// Extract just the user-friendly message without the emoji prefix
pub fn get_error_message_only(error: impl std::fmt::Display, context: &str) -> String {
    format_user_error(error, context)
        .replace("❌ ", "")
        .replace("🔐 ", "")
        .replace("📁 ", "")
        .replace("⏱️ ", "")
        .replace("💾 ", "")
        .replace("🔒 ", "")
        .replace("📂 ", "")
        .replace("🔑 ", "")
        .replace("📄 ", "")
        .replace("🖥️ ", "")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_error() {
        let error = "Connection refused";
        let result = format_user_error(error, "test");
        assert!(result.contains("Connection error"));
    }

    #[test]
    fn test_file_not_found() {
        let error = "No such file or directory";
        let result = format_user_error(error, "test");
        assert!(result.contains("not found"));
    }

    #[test]
    fn test_fido2_error() {
        let error = "FIDO2 credential failed";
        let result = format_user_error(error, "test");
        assert!(result.contains("security key"));
    }

    #[test]
    fn test_webauthn_errors_map_to_security_key() {
        for err in [
            "WebAuthn assertion timeout",
            "fido2 authentication failed",
            "CTAP2 device not found",
            "Security-Key unplugged",
        ] {
            let result = format_user_error(err, "test");
            assert!(result.contains("security key"), "{err} -> {result}");
        }
        // fido2 operation context must not double-prefix the message.
        let msg = format_operation_error("FIDO2 credential failed", "fido2");
        assert!(!msg.contains("Security key error: "));
    }
}
