use crate::auth::types::SessionClaims;
use chrono::Utc;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use uuid::Uuid;

pub struct JwtManager {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
}

impl JwtManager {
    pub fn new(secret: &str) -> Result<Self, Box<dyn std::error::Error>> {
        if secret.len() < 32 {
            return Err("JWT secret must be at least 32 bytes (256 bits)".into());
        }
        // Fail-closed: refuse the historic hardcoded default that was committed.
        if secret == "rsb-shield-secret-key-256bit" || secret == "test-secret" {
            // Allow "test-secret" only via explicit test path below; production
            // callers must use from_env(). Keep the check here as defense-in-depth.
            return Err("Refusing known-default JWT secret. Set RSB_JWT_SECRET.".into());
        }
        let secret_bytes = secret.as_bytes();

        Ok(Self {
            encoding_key: EncodingKey::from_secret(secret_bytes),
            decoding_key: DecodingKey::from_secret(secret_bytes),
        })
    }

    /// Build from environment (`RSB_JWT_SECRET`) or the persisted secret.
    ///
    /// Ordem: variável de ambiente (override) → keyring ("rsb-shield",
    /// "jwt-secret") → ficheiro 0600 em `~/.rs-shield/jwt_secret` quando não
    /// há keyring disponível. O segredo é criado UMA vez (apenas se não
    /// existir) e reutilizado por todos os processos, para que tokens emitidos
    /// pelo servidor sejam verificáveis pela CLI.
    pub fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        if let Ok(s) = std::env::var("RSB_JWT_SECRET")
            && !s.trim().is_empty()
        {
            return Self::new(&s);
        }
        let secret = load_or_create_persistent_secret()?;
        Self::from_secret_bytes(secret.as_bytes())
    }

    /// Constrói a partir de bytes brutos de um segredo gerado aleatoriamente
    /// (sem a verificação de segredos "default" conhecidos).
    fn from_secret_bytes(secret: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        if secret.len() < 32 {
            return Err("JWT secret must be at least 32 bytes (256 bits)".into());
        }
        Ok(Self {
            encoding_key: EncodingKey::from_secret(secret),
            decoding_key: DecodingKey::from_secret(secret),
        })
    }

    #[cfg(test)]
    pub fn new_for_test() -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(b"test-secret-that-is-long-enough-32b!!"),
            decoding_key: DecodingKey::from_secret(b"test-secret-that-is-long-enough-32b!!"),
        }
    }

    pub fn create_token(
        &self,
        user_id: &str,
        scopes: Vec<String>,
        expires_in_seconds: i64,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let now = Utc::now().timestamp();
        let jti = Uuid::new_v4().to_string();

        let claims = SessionClaims {
            sub: user_id.to_string(),
            scopes,
            jti,
            iat: now,
            exp: now + expires_in_seconds,
            aud: "rsb-shield".to_string(),
            iss: "rsb-shield".to_string(),
        };

        let mut header = Header::new(jsonwebtoken::Algorithm::HS256);
        header.typ = Some("JWT".to_string());
        let token = encode(&header, &claims, &self.encoding_key)?;
        Ok(token)
    }

    pub fn verify_token(&self, token: &str) -> Result<SessionClaims, Box<dyn std::error::Error>> {
        let mut validation = Validation::new(jsonwebtoken::Algorithm::HS256);
        validation.set_audience(&["rsb-shield"]);
        validation.set_issuer(&["rsb-shield"]);
        validation.leeway = 60;
        validation.validate_exp = true;
        validation.required_spec_claims.insert("exp".to_string());
        validation.required_spec_claims.insert("sub".to_string());
        validation.required_spec_claims.insert("jti".to_string());

        let token_data = decode::<SessionClaims>(token, &self.decoding_key, &validation)?;

        Ok(token_data.claims)
    }

    pub fn is_expired(&self, token: &str) -> bool {
        match self.verify_token(token) {
            Ok(claims) => {
                let now = Utc::now().timestamp();
                claims.exp < now
            }
            Err(_) => true,
        }
    }

    pub fn extract_jti(&self, token: &str) -> Option<String> {
        match self.verify_token(token) {
            Ok(claims) => Some(claims.jti),
            Err(_) => None,
        }
    }
}

const JWT_KEYRING_SERVICE: &str = "rsb-shield";
const JWT_KEYRING_USER: &str = "jwt-secret";
const JWT_SECRET_FILE: &str = "jwt_secret";

/// Gera um segredo aleatório de 256 bits, codificado em base64.
fn generate_secret() -> String {
    use rand::Rng;
    let mut buf = [0u8; 32];
    rand::rng().fill_bytes(&mut buf);
    let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, buf);
    zeroize::Zeroize::zeroize(&mut buf);
    encoded
}

/// Obtém (ou cria uma única vez) o segredo persistido.
fn load_or_create_persistent_secret() -> Result<String, Box<dyn std::error::Error>> {
    match keyring::Entry::new(JWT_KEYRING_SERVICE, JWT_KEYRING_USER) {
        Ok(entry) => match entry.get_password() {
            Ok(s) if !s.trim().is_empty() => Ok(s),
            Ok(_) => Err("JWT secret in keyring is empty; refusing to continue".into()),
            Err(keyring::Error::NoEntry) => {
                // Criar APENAS quando a entrada não existe.
                let secret = generate_secret();
                entry
                    .set_password(&secret)
                    .map_err(|e| format!("Failed to store JWT secret in keyring: {}", e))?;
                // Reler: se outro processo criou em simultâneo, usamos o valor final.
                match entry.get_password() {
                    Ok(s) if !s.trim().is_empty() => Ok(s),
                    _ => Ok(secret),
                }
            }
            Err(keyring::Error::PlatformFailure(e)) | Err(keyring::Error::NoStorageAccess(e)) => {
                tracing::warn!(
                    "OS keyring unavailable ({}); using ~/.rs-shield/{} for the JWT secret",
                    e,
                    JWT_SECRET_FILE
                );
                load_or_create_secret_file(&default_secret_file_path()?)
            }
            Err(e) => Err(format!("Failed to read JWT secret from keyring: {}", e).into()),
        },
        Err(e) => {
            tracing::warn!(
                "OS keyring unavailable ({}); using ~/.rs-shield/{} for the JWT secret",
                e,
                JWT_SECRET_FILE
            );
            load_or_create_secret_file(&default_secret_file_path()?)
        }
    }
}

fn default_secret_file_path() -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    Ok(crate::auth::secure_fs::rs_shield_dir()?.join(JWT_SECRET_FILE))
}

/// Fallback sem keyring: ficheiro 0600, criado de forma exclusiva (O_EXCL)
/// apenas se não existir.
pub(crate) fn load_or_create_secret_file(
    path: &std::path::Path,
) -> Result<String, Box<dyn std::error::Error>> {
    if !path.exists() {
        let secret = generate_secret();
        // Se perdermos a corrida para outro processo, lemos o ficheiro dele.
        crate::auth::secure_fs::create_private_exclusive(path, secret.as_bytes())?;
    }
    let s = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read JWT secret file {:?}: {}", path, e))?;
    let s = s.trim().to_string();
    if s.len() < 32 {
        return Err(format!("JWT secret file {:?} is invalid (too short)", path).into());
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwt_create_and_verify() {
        let manager = JwtManager::new_for_test();
        let token = manager
            .create_token("user1", vec!["backup".to_string()], 2592000)
            .unwrap();

        let claims = manager.verify_token(&token).unwrap();
        assert_eq!(claims.sub, "user1");
        assert_eq!(claims.scopes, vec!["backup".to_string()]);
        assert!(!claims.jti.is_empty());
    }

    #[test]
    fn test_jwt_invalid_signature() {
        let manager1 = JwtManager::new_for_test();
        let manager2 = JwtManager::new("a-different-secret-that-is-32-bytes-long!!").unwrap();

        let token = manager1
            .create_token("user1", vec!["backup".to_string()], 3600)
            .unwrap();

        let result = manager2.verify_token(&token);
        assert!(result.is_err());
    }
    #[test]
    fn test_persisted_secret_file_is_stable_and_private() {
        // Regressão: cada from_env() gerava um segredo novo → tokens do
        // servidor falhavam na CLI. O segredo persistido tem de ser estável.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("jwt_secret");

        let s1 = load_or_create_secret_file(&path).unwrap();
        let s2 = load_or_create_secret_file(&path).unwrap();
        assert_eq!(s1, s2);
        assert!(s1.len() >= 32);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        // "Servidor" e "CLI" constroem gestores independentes a partir do
        // mesmo segredo persistido: o token de um tem de validar no outro.
        let server = JwtManager::from_secret_bytes(s1.as_bytes()).unwrap();
        let cli = JwtManager::from_secret_bytes(s2.as_bytes()).unwrap();
        let token = server
            .create_token("user1", vec!["backup".to_string()], 600)
            .unwrap();
        let claims = cli.verify_token(&token).unwrap();
        assert_eq!(claims.sub, "user1");
    }

    #[test]
    fn test_short_secret_rejected() {
        assert!(JwtManager::from_secret_bytes(b"short").is_err());
    }
}
