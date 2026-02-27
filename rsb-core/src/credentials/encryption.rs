/// Módulo de criptografia de credenciais em repouso
/// Usa AES-256-GCM para criptografia autenticada
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce, Key,
};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::fmt;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

#[derive(Serialize, Deserialize, Clone)]
pub struct EncryptedCredentials {
    /// Ciphertext codificado em base64
    pub cipher: String,
    /// Nonce (IV) codificado em base64 - deve ser único para cada encriptação
    pub nonce: String,
    /// Salt para derivação de chave
    pub salt: String,
    /// Versão do algoritmo de criptografia para compatibilidade futura
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

/// Derivar chave a partir de uma senha master usando PBKDF2
fn derive_key_from_password(password: &str, salt: &[u8]) -> [u8; 32] {
    use pbkdf2::pbkdf2_hmac;
    use sha2::Sha256;

    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, 100_000, &mut key);
    key
}

/// Criptografar JSON de credenciais
pub fn encrypt_credentials(
    json: &str,
    master_password: &str,
) -> Result<EncryptedCredentials, String> {
    let mut rng = rand::thread_rng();

    // Gerar salt (16 bytes)
    let salt: [u8; 16] = rng.gen();

    // Derivar chave da senha master
    let key_bytes = derive_key_from_password(master_password, &salt);
    let key = Key::<Aes256Gcm>::from(key_bytes);

    // Gerar nonce único (12 bytes para GCM)
    let nonce_bytes: [u8; 12] = rng.gen();
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Criptografar
    let cipher = Aes256Gcm::new(&key);
    let ciphertext = cipher
        .encrypt(nonce, Payload::from(json.as_bytes()))
        .map_err(|e| format!("Encryption failed: {}", e))?;

    // Codificar em base64 para armazenamento
    let cipher_b64 = BASE64.encode(&ciphertext);
    let nonce_b64 = BASE64.encode(&nonce_bytes);
    let salt_b64 = BASE64.encode(&salt);

    Ok(EncryptedCredentials {
        cipher: cipher_b64,
        nonce: nonce_b64,
        salt: salt_b64,
        version: 1,
    })
}

/// Descriptografar JSON de credenciais
pub fn decrypt_credentials(
    encrypted: &EncryptedCredentials,
    master_password: &str,
) -> Result<String, String> {
    // Decodificar de base64
    let ciphertext = BASE64.decode(&encrypted.cipher)
        .map_err(|e| format!("Failed to decode cipher: {}", e))?;
    let nonce_bytes = BASE64.decode(&encrypted.nonce)
        .map_err(|e| format!("Failed to decode nonce: {}", e))?;
    let salt = BASE64.decode(&encrypted.salt)
        .map_err(|e| format!("Failed to decode salt: {}", e))?;

    // Validar tamanhos
    if nonce_bytes.len() != 12 {
        return Err("Invalid nonce".to_string());
    }
    if salt.len() != 16 {
        return Err("Invalid salt".to_string());
    }

    // Derivar chave
    let key_bytes = derive_key_from_password(master_password, &salt);
    let key = Key::<Aes256Gcm>::from(key_bytes);

    // Descriptografar
    let nonce = Nonce::from_slice(&nonce_bytes);
    let cipher = Aes256Gcm::new(&key);
    let plaintext = cipher
        .decrypt(nonce, Payload::from(ciphertext.as_ref()))
        .map_err(|e| format!("Decryption failed (incorrect password?): {}", e))?;

    // Converter para string
    String::from_utf8(plaintext).map_err(|e| format!("Invalid JSON: {}", e))
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

        assert_eq!(original, &decrypted);
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

        // Mesmo com mesmos dados, nonces e salts diferentes produzem ciphers diferentes
        assert_ne!(enc1.cipher, enc2.cipher);
        assert_ne!(enc1.nonce, enc2.nonce);
    }
}
