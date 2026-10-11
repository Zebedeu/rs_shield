use crate::auth::types::RateLimitCounter;
use chrono::{Duration, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Número máximo de chaves mantidas em memória (evita crescimento sem limite
/// quando um cliente roda identificadores).
pub const MAX_TRACKED_KEYS: usize = 10_000;

pub struct RateLimiter {
    // key -> RateLimitCounter
    counters: Arc<RwLock<HashMap<String, RateLimitCounter>>>,
    max_requests: u32,
    window_seconds: i64,
    max_keys: usize,
}

impl RateLimiter {
    pub fn new(max_requests: u32, window_seconds: i64) -> Self {
        Self::with_capacity(max_requests, window_seconds, MAX_TRACKED_KEYS)
    }

    pub fn with_capacity(max_requests: u32, window_seconds: i64, max_keys: usize) -> Self {
        Self {
            counters: Arc::new(RwLock::new(HashMap::new())),
            max_requests,
            window_seconds,
            max_keys: max_keys.max(1),
        }
    }

    /// Verifica e consome uma unidade do limite para `key`.
    pub async fn is_allowed(&self, key: &str) -> bool {
        self.is_allowed_n(key, self.max_requests).await
    }

    /// Como `is_allowed`, mas com um limite específico para esta chave.
    pub async fn is_allowed_n(&self, key: &str, max_requests: u32) -> bool {
        let mut counters = self.counters.write().await;
        let now = Utc::now();

        if !counters.contains_key(key) && !Self::make_room(&mut counters, self.max_keys) {
            // Tabela cheia de janelas ativas: fail-closed.
            return false;
        }

        let window = self.window_seconds;
        let counter = counters
            .entry(key.to_string())
            .or_insert_with(|| RateLimitCounter {
                user_id: key.to_string(),
                counter: 0,
                reset_at: now + Duration::seconds(window),
            });

        // Reset se janela expirou
        if now > counter.reset_at {
            counter.counter = 0;
            counter.reset_at = now + Duration::seconds(window);
        }

        if counter.counter < max_requests {
            counter.counter += 1;
            true
        } else {
            false
        }
    }

    /// Verifica sem registar nada (não cria entradas para chaves novas).
    pub async fn check(&self, key: &str) -> bool {
        let counters = self.counters.read().await;
        match counters.get(key) {
            Some(c) => Utc::now() > c.reset_at || c.counter < self.max_requests,
            None => true,
        }
    }

    /// Regista uma tentativa (ex.: falha) para `key`, sem decidir nada.
    pub async fn record(&self, key: &str) {
        let _ = self.is_allowed_n(key, u32::MAX).await;
    }

    fn make_room(counters: &mut HashMap<String, RateLimitCounter>, max_keys: usize) -> bool {
        if counters.len() < max_keys {
            return true;
        }
        let now = Utc::now();
        counters.retain(|_, c| c.reset_at > now);
        counters.len() < max_keys
    }

    /// Limpeza de janelas expiradas (chamada pela tarefa periódica).
    pub async fn cleanup_expired(&self) {
        let mut counters = self.counters.write().await;
        let now = Utc::now();
        counters.retain(|_, c| c.reset_at > now);
    }

    pub async fn len(&self) -> usize {
        self.counters.read().await.len()
    }

    pub async fn is_empty(&self) -> bool {
        self.counters.read().await.is_empty()
    }

    pub async fn get_remaining(&self, user_id: &str) -> u32 {
        let counters = self.counters.read().await;
        let now = Utc::now();

        if let Some(counter) = counters.get(user_id) {
            if now > counter.reset_at {
                self.max_requests
            } else {
                self.max_requests.saturating_sub(counter.counter)
            }
        } else {
            self.max_requests
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rate_limit_allows_requests() {
        let limiter = RateLimiter::new(5, 60);

        for _ in 0..5 {
            assert!(limiter.is_allowed("user1").await);
        }

        assert!(!limiter.is_allowed("user1").await);
    }

    #[tokio::test]
    async fn test_rate_limit_different_users() {
        let limiter = RateLimiter::new(2, 60);

        assert!(limiter.is_allowed("user1").await);
        assert!(limiter.is_allowed("user1").await);
        assert!(!limiter.is_allowed("user1").await);

        assert!(limiter.is_allowed("user2").await);
        assert!(limiter.is_allowed("user2").await);
        assert!(!limiter.is_allowed("user2").await);
    }
    #[tokio::test]
    async fn test_check_does_not_insert_and_record_counts() {
        let limiter = RateLimiter::new(2, 60);
        assert!(limiter.check("ghost").await);
        assert_eq!(limiter.len().await, 0);

        limiter.record("u").await;
        limiter.record("u").await;
        assert!(!limiter.check("u").await);
    }

    #[tokio::test]
    async fn test_capacity_is_bounded() {
        let limiter = RateLimiter::with_capacity(5, 60, 3);
        assert!(limiter.is_allowed("a").await);
        assert!(limiter.is_allowed("b").await);
        assert!(limiter.is_allowed("c").await);
        // Chave nova com tabela cheia → recusada, sem crescer.
        assert!(!limiter.is_allowed("d").await);
        assert_eq!(limiter.len().await, 3);
        // Chaves existentes continuam a funcionar.
        assert!(limiter.is_allowed("a").await);
    }
}
