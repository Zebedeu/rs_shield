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
        if secret.as_bytes().len() < 32 {
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

    /// Build from environment (`RSB_JWT_SECRET`) or OS keyring.
    /// Falls back to a per-boot ephemeral secret so a missing secret
    /// never silently becomes a hardcoded one.
    pub fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        if let Ok(s) = std::env::var("RSB_JWT_SECRET") {
            if !s.trim().is_empty() {
                return Self::new(&s);
            }
        }
        // Try OS keyring (same service used for other secrets).
        #[allow(unused_variables)]
        let from_keyring: Option<String> = (|| {
            let entry = keyring::Entry::new("rsb-shield", "jwt-secret").ok()?;
            entry.get_password().ok()
        })();
        if let Some(s) = from_keyring {
            if !s.trim().is_empty() {
                return Self::new(&s);
            }
        }
        // Ephemeral per-process secret: tokens don't survive restarts,
        // which is the safe failure mode (fail-closed, no cross-install forgery).
        use rand::Rng;
        let mut buf = [0u8; 32];
        rand::rng().fill_bytes(&mut buf);
        let ephemeral = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, buf);
        tracing::warn!(
            "RSB_JWT_SECRET not set: using ephemeral JWT secret (tokens invalid after restart). Set RSB_JWT_SECRET for stable sessions."
        );
        // Bypass the default-secret check via raw keys.
        Ok(Self {
            encoding_key: EncodingKey::from_secret(ephemeral.as_bytes()),
            decoding_key: DecodingKey::from_secret(ephemeral.as_bytes()),
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
}
