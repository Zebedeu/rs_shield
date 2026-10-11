//! Erro público do SDK.
//!
//! Os pontos de entrada públicos (backup, restore, verify, prune,
//! portable_restore, `storage_backend::get_storage`) devolvem
//! [`RsbError`]. Módulos internos podem continuar a usar `io::Error` ou
//! `Box<dyn Error>`: a conversão faz-se na fronteira e preserva a
//! classificação sempre que possível (ex.: falha de autenticação AEAD →
//! [`RsbError::Crypto`] com [`CryptoErrorKind::AuthenticationFailed`]).
//!
//! As mensagens (`Display`) são as mesmas que antes eram devolvidas como
//! `Box<dyn Error>`, para que CLI/desktop mostrem o mesmo texto.

use std::io;

/// Tipo de falha criptográfica.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoErrorKind {
    /// Tag AEAD inválida: chave/password errada ou dados adulterados.
    AuthenticationFailed,
    /// Dados cifrados mal formados/truncados (não é questão de chave).
    Corrupt,
    /// Outra falha (derivação de chave, ...).
    Other,
}

/// Erro devolvido pelas operações públicas do SDK. `Send + Sync`.
#[derive(Debug, thiserror::Error)]
pub enum RsbError {
    /// Erro de I/O (disco, rede do storage, lock do repositório, ...).
    ///
    /// An `io::Error` carrying a typed [`crate::crypto::CryptoError`] is
    /// converted to [`RsbError::Crypto`] instead (see `From<io::Error>`).
    #[error(transparent)]
    Io(io::Error),
    /// Perfil/configuração inválido ou ilegível.
    #[error("{0}")]
    Config(String),
    /// Falha do backend de storage (S3/local) que não é I/O simples.
    #[error("{0}")]
    Storage(String),
    /// Falha criptográfica; `kind` permite distinguir chave errada de
    /// dados corrompidos sem olhar para a mensagem.
    #[error("{message}")]
    Crypto {
        kind: CryptoErrorKind,
        message: String,
    },
    /// Credenciais em falta/inválidas (ex.: S3 sem credenciais).
    #[error("{0}")]
    Auth(String),
    /// Operação cancelada pelo utilizador.
    #[error("Operation cancelled")]
    Cancelled,
    /// Recurso inexistente (pasta de backup, snapshot, ...).
    #[error("{0}")]
    NotFound(String),
    /// Argumentos inválidos (ex.: `keep_last = 0`, estrutura de backup).
    #[error("{0}")]
    InvalidInput(String),
    /// Qualquer outro erro (mensagem preservada).
    #[error("{0}")]
    Other(String),
}

/// `Result` com [`RsbError`].
pub type Result<T> = std::result::Result<T, RsbError>;

impl RsbError {
    /// Erro criptográfico com a mensagem dada.
    pub fn crypto(kind: CryptoErrorKind, message: impl Into<String>) -> Self {
        RsbError::Crypto {
            kind,
            message: message.into(),
        }
    }

    /// `true` se a causa é uma chave errada / dados adulterados (tag AEAD).
    pub fn is_authentication_failure(&self) -> bool {
        match self {
            RsbError::Crypto { kind, .. } => *kind == CryptoErrorKind::AuthenticationFailed,
            RsbError::Io(e) => crate::crypto::is_authentication_error(e),
            _ => false,
        }
    }

    /// `true` para recursos inexistentes (incluindo `io::ErrorKind::NotFound`).
    pub fn is_not_found(&self) -> bool {
        match self {
            RsbError::NotFound(_) => true,
            RsbError::Io(e) => e.kind() == io::ErrorKind::NotFound,
            _ => false,
        }
    }

    /// Converte um erro dinâmico preservando o tipo quando é conhecido
    /// (`RsbError`, `io::Error`, `CryptoError`); senão guarda a mensagem.
    fn from_dyn(e: &(dyn std::error::Error + 'static)) -> Option<Self> {
        if let Some(c) = e.downcast_ref::<crate::crypto::CryptoError>() {
            return Some(Self::from_crypto(*c, c.to_string()));
        }
        None
    }

    fn from_crypto(c: crate::crypto::CryptoError, message: String) -> Self {
        use crate::crypto::CryptoError as C;
        let kind = match c {
            C::AuthenticationFailed => CryptoErrorKind::AuthenticationFailed,
            C::Malformed => CryptoErrorKind::Corrupt,
            C::RepoKeyRequired => CryptoErrorKind::Other,
        };
        RsbError::crypto(kind, message)
    }
}

impl From<io::Error> for RsbError {
    fn from(e: io::Error) -> Self {
        match crate::crypto::crypto_error_of(&e) {
            Some(c) => RsbError::from_crypto(c, e.to_string()),
            None => RsbError::Io(e),
        }
    }
}

impl From<String> for RsbError {
    fn from(s: String) -> Self {
        RsbError::Other(s)
    }
}

impl From<&str> for RsbError {
    fn from(s: &str) -> Self {
        RsbError::Other(s.to_string())
    }
}

impl From<toml::de::Error> for RsbError {
    fn from(e: toml::de::Error) -> Self {
        RsbError::Other(e.to_string())
    }
}

impl From<tokio::task::JoinError> for RsbError {
    fn from(e: tokio::task::JoinError) -> Self {
        RsbError::Other(e.to_string())
    }
}

impl From<crate::crypto::CryptoError> for RsbError {
    fn from(e: crate::crypto::CryptoError) -> Self {
        // Único caso existente hoje: falha de autenticação.
        RsbError::from_dyn(&e).unwrap_or_else(|| RsbError::Other(e.to_string()))
    }
}

impl From<Box<dyn std::error::Error + Send + Sync>> for RsbError {
    fn from(e: Box<dyn std::error::Error + Send + Sync>) -> Self {
        let e = match e.downcast::<RsbError>() {
            Ok(r) => return *r,
            Err(e) => e,
        };
        let e = match e.downcast::<io::Error>() {
            Ok(io) => return RsbError::from(*io),
            Err(e) => e,
        };
        RsbError::from_dyn(&*e).unwrap_or_else(|| RsbError::Other(e.to_string()))
    }
}

impl From<Box<dyn std::error::Error>> for RsbError {
    fn from(e: Box<dyn std::error::Error>) -> Self {
        let e = match e.downcast::<RsbError>() {
            Ok(r) => return *r,
            Err(e) => e,
        };
        let e = match e.downcast::<io::Error>() {
            Ok(io) => return RsbError::from(*io),
            Err(e) => e,
        };
        RsbError::from_dyn(&*e).unwrap_or_else(|| RsbError::Other(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_send_sync<T: Send + Sync + 'static>() {}

    #[test]
    fn rsb_error_is_send_sync() {
        assert_send_sync::<RsbError>();
    }

    #[test]
    fn display_preserves_messages() {
        assert_eq!(RsbError::from("boom").to_string(), "boom");
        assert_eq!(
            RsbError::InvalidInput("bad input".into()).to_string(),
            "bad input"
        );
        let io = io::Error::new(io::ErrorKind::NotFound, "no file");
        assert_eq!(RsbError::from(io).to_string(), "no file");
    }

    #[test]
    fn boxed_errors_keep_their_type() {
        let boxed: Box<dyn std::error::Error> =
            Box::new(RsbError::crypto(CryptoErrorKind::Corrupt, "bad blob"));
        assert!(matches!(
            RsbError::from(boxed),
            RsbError::Crypto {
                kind: CryptoErrorKind::Corrupt,
                ..
            }
        ));

        let boxed: Box<dyn std::error::Error + Send + Sync> =
            Box::new(io::Error::new(io::ErrorKind::NotFound, "x"));
        assert!(RsbError::from(boxed).is_not_found());

        let auth: io::Error = crate::crypto::CryptoError::AuthenticationFailed.into();
        assert!(RsbError::from(auth).is_authentication_failure());
        let auth: io::Error = crate::crypto::CryptoError::AuthenticationFailed.into();
        assert!(matches!(
            RsbError::from(auth),
            RsbError::Crypto {
                kind: CryptoErrorKind::AuthenticationFailed,
                ..
            }
        ));
        let bad: io::Error = crate::crypto::CryptoError::Malformed.into();
        assert!(matches!(
            RsbError::from(bad),
            RsbError::Crypto {
                kind: CryptoErrorKind::Corrupt,
                ..
            }
        ));

        let boxed: Box<dyn std::error::Error> =
            Box::new(crate::crypto::CryptoError::AuthenticationFailed);
        assert!(RsbError::from(boxed).is_authentication_failure());
    }
}
