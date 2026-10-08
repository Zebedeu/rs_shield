/// Encryption module for credentials at rest
/// Uses AES-256-GCM for authenticated encryption
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use pbkdf2::pbkdf2_hmac;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fmt;
use zeroize::{Zeroize, Zeroizing};

#[derive(Serialize, Deserialize, Clone)]
pub struct EncryptedCredentials {
    /// Ciphertext encoded in base64
    pub cipher: String,
    /// Nonce (IV) encoded in base64 - must be unique for each encryption
    pub nonce: String,
    /// Salt for key derivation
    pub salt: String,
    /// Encryption algorithm version for future compatibility
    pub version: u32,
}

impl fmt::Debug for EncryptedCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedCredentials")
            .field("cipher", &"***REDACTED***")
            .field("nonce", &"***REDACTED***")
            .field("salt", &"***REDACTED***")
            .field("version", &self.version)
            .finish()
    }
}

/// Format version written by `encrypt_credentials`.
pub const CURRENT_VERSION: u32 = 2;
/// PBKDF2 iterations for version 1 files (legacy, read-only).
pub const PBKDF2_ITERATIONS_V1: u32 = 100_000;
/// PBKDF2 iterations for version 2 files (current).
pub const PBKDF2_ITERATIONS: u32 = 600_000;

/// PBKDF2 iteration count for a given file format version.
fn iterations_for_version(version: u32) -> Result<u32, String> {
    match version {
        1 => Ok(PBKDF2_ITERATIONS_V1),
        2 => Ok(PBKDF2_ITERATIONS),
        v => Err(format!("Unsupported credentials file version: {}", v)),
    }
}

impl EncryptedCredentials {
    /// True if this file uses an older format and should be re-encrypted
    /// (with `encrypt_credentials`) after a successful decrypt.
    pub fn needs_upgrade(&self) -> bool {
        self.version < CURRENT_VERSION
    }
}

/// Derive key from master password using PBKDF2. The returned buffer is
/// wiped on drop, on every path (including errors).
fn derive_key_from_password(password: &str, salt: &[u8], iterations: u32) -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, iterations, &mut key[..]);
    key
}

/// Encrypt credentials JSON (always writes the current version)
pub fn encrypt_credentials(
    json: &str,
    master_password: &str,
) -> Result<EncryptedCredentials, String> {
    let mut rng = rand::rng();

    // Generate salt (16 bytes)
    let mut salt = [0u8; 16];
    rng.fill_bytes(&mut salt);

    // Derive key from master password
    let key_bytes = derive_key_from_password(master_password, &salt, PBKDF2_ITERATIONS);
    // new_from_slice avoids an extra un-wiped `Key` copy on the stack.
    let cipher = Aes256Gcm::new_from_slice(&key_bytes[..])
        .map_err(|_| "Invalid key length".to_string())?;

    // Generate unique nonce (12 bytes for GCM)
    let mut nonce_bytes = [0u8; 12];
    rng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt
    let ciphertext = cipher
        .encrypt(nonce, Payload::from(json.as_bytes()))
        .map_err(|e| format!("Encryption failed: {}", e))?;

    // Encode in base64 for storage
    let cipher_b64 = BASE64.encode(&ciphertext);
    let nonce_b64 = BASE64.encode(nonce_bytes);
    let salt_b64 = BASE64.encode(salt);

    Ok(EncryptedCredentials {
        cipher: cipher_b64,
        nonce: nonce_b64,
        salt: salt_b64,
        version: CURRENT_VERSION,
    })
}

/// Decrypt credentials JSON. Supports version 1 (100k PBKDF2 iterations) and
/// version 2 (600k). Callers should check `EncryptedCredentials::needs_upgrade`
/// and re-encrypt after success.
pub fn decrypt_credentials(
    encrypted: &EncryptedCredentials,
    master_password: &str,
) -> Result<Zeroizing<String>, String> {
    let iterations = iterations_for_version(encrypted.version)?;

    // Decode from base64
    let ciphertext = BASE64
        .decode(&encrypted.cipher)
        .map_err(|e| format!("Failed to decode cipher: {}", e))?;
    let nonce_bytes = BASE64
        .decode(&encrypted.nonce)
        .map_err(|e| format!("Failed to decode nonce: {}", e))?;
    let salt = BASE64
        .decode(&encrypted.salt)
        .map_err(|e| format!("Failed to decode salt: {}", e))?;

    // Validate sizes
    if nonce_bytes.len() != 12 {
        return Err("Invalid nonce".to_string());
    }
    if salt.len() != 16 {
        return Err("Invalid salt".to_string());
    }

    // Derive key
    let key_bytes = derive_key_from_password(master_password, &salt, iterations);
    let cipher = Aes256Gcm::new_from_slice(&key_bytes[..])
        .map_err(|_| "Invalid key length".to_string())?;

    // Decrypt
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, Payload::from(ciphertext.as_ref()))
        .map_err(|e| format!("Decryption failed (incorrect password?): {}", e))?;

    // Convert to string (moves the buffer, no copy); wipe it on failure.
    match String::from_utf8(plaintext) {
        Ok(s) => Ok(Zeroizing::new(s)),
        Err(e) => {
            let mut bytes = e.into_bytes();
            bytes.zeroize();
            Err("Invalid JSON: decrypted data is not valid UTF-8".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let original = r#"{"access_key":"AKIA123","secret_key":"secret123"}"#;
        let password = "my-master-password-1234";

        let encrypted = encrypt_credentials(original, password).unwrap();
        let decrypted = decrypt_credentials(&encrypted, password).unwrap();

        assert_eq!(original, decrypted.as_str());
    }

    #[test]
    fn test_wrong_password_fails() {
        let original = r#"{"access_key":"AKIA123","secret_key":"secret123"}"#;
        let password = "correct-password";
        let wrong_password = "wrong-password";

        let encrypted = encrypt_credentials(original, password).unwrap();
        let result = decrypt_credentials(&encrypted, wrong_password);

        assert!(result.is_err());
    }

    #[test]
    fn test_different_encryptions_produce_different_ciphers() {
        let original = r#"{"access_key":"AKIA123"}"#;
        let password = "password";

        let enc1 = encrypt_credentials(original, password).unwrap();
        let enc2 = encrypt_credentials(original, password).unwrap();

        // Same data but different nonces and salts produce different ciphers
        assert_ne!(enc1.cipher, enc2.cipher);
        assert_ne!(enc1.nonce, enc2.nonce);
    }

    #[test]
    fn test_new_files_are_version_2() {
        let enc = encrypt_credentials("{}", "pw").unwrap();
        assert_eq!(enc.version, CURRENT_VERSION);
        assert!(!enc.needs_upgrade());
    }

    /// Build a version 1 blob exactly as the previous release did
    /// (PBKDF2-HMAC-SHA256, 100_000 iterations).
    fn encrypt_v1(json: &str, password: &str) -> EncryptedCredentials {
        let salt = [3u8; 16];
        let nonce_bytes = [5u8; 12];
        let mut key = [0u8; 32];
        pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, 100_000, &mut key);
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), json.as_bytes())
            .unwrap();
        EncryptedCredentials {
            cipher: BASE64.encode(ct),
            nonce: BASE64.encode(nonce_bytes),
            salt: BASE64.encode(salt),
            version: 1,
        }
    }

    #[test]
    fn test_decrypts_v1_with_100k_iterations() {
        let original = r#"{"access_key":"AKIA123","secret_key":"secret123"}"#;
        let v1 = encrypt_v1(original, "legacy-password");
        assert!(v1.needs_upgrade());
        let decrypted = decrypt_credentials(&v1, "legacy-password").unwrap();
        assert_eq!(decrypted.as_str(), original);

        // A v1 blob must NOT decrypt if interpreted as v2.
        let mut as_v2 = v1.clone();
        as_v2.version = 2;
        assert!(decrypt_credentials(&as_v2, "legacy-password").is_err());
    }

    #[test]
    fn test_unknown_version_rejected() {
        let mut enc = encrypt_credentials("{}", "pw").unwrap();
        enc.version = 99;
        assert!(decrypt_credentials(&enc, "pw").is_err());
    }
}
