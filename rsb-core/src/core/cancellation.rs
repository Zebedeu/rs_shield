use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Token que permite sinalizar cancelamento de uma operação
#[derive(Clone)]
pub struct CancellationToken {
    inner: Arc<AtomicBool>,
}

impl CancellationToken {
    /// Cria um novo token de cancelamento
    pub fn new() -> Self {
        Self {
            inner: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Sinaliza que a operação deve ser cancelada
    pub fn cancel(&self) {
        self.inner.store(true, Ordering::SeqCst);
    }

    /// Verifica se a operação foi cancelada
    pub fn is_cancelled(&self) -> bool {
        self.inner.load(Ordering::SeqCst)
    }
}

impl Default for CancellationToken {
    fn default() -> Self {
        Self::new()
    }
}
