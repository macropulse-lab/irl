/// Per-token sliding-window rate limiter.
///
/// Uses a DashMap to maintain one second-aligned counter per bearer token.
/// Each counter stores `(window_second, request_count)`.
///
/// At the start of a new second, the counter resets to 1.
/// Within the same second, each call increments the counter.
/// If the counter reaches `max_per_second`, the request is rejected with 429.
///
/// Thread-safe: DashMap provides per-shard locking; no global mutex.
///
/// Configuration:
///   `RATE_LIMIT_PER_SECOND` — requests per token per second (default: 100)
///   Set to 0 to disable rate limiting entirely.
use crate::errors::AppError;
use dashmap::DashMap;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug)]
pub struct RateLimiter {
    /// token_hash → (window_second, request_count)
    counters: DashMap<String, (u64, u32)>,
    max_per_second: u32,
}

impl RateLimiter {
    pub fn new(max_per_second: u32) -> Arc<Self> {
        Arc::new(Self {
            counters: DashMap::new(),
            max_per_second,
        })
    }

    /// Check and record a request for the given token.
    ///
    /// Returns Ok(()) if the request is within the rate limit.
    /// Returns Err(AppError::RateLimitExceeded) if the limit is reached.
    /// If `max_per_second == 0`, rate limiting is disabled and Ok is always returned.
    pub fn check(&self, token: &str) -> Result<(), AppError> {
        if self.max_per_second == 0 {
            return Ok(());
        }

        let now_sec = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Key by SHA-256 hash so raw credentials never live in process memory.
        let key = hex::encode(Sha256::digest(token.as_bytes()));

        let mut entry = self.counters.entry(key).or_insert((now_sec, 0));

        if entry.0 != now_sec {
            // New second: reset counter.
            *entry = (now_sec, 1);
            Ok(())
        } else if entry.1 < self.max_per_second {
            entry.1 += 1;
            Ok(())
        } else {
            Err(AppError::RateLimitExceeded)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_requests_within_limit() {
        let limiter = RateLimiter::new(10);
        for _ in 0..10 {
            assert!(limiter.check("token-a").is_ok());
        }
    }

    #[test]
    fn blocks_after_limit_exceeded() {
        let limiter = RateLimiter::new(3);
        assert!(limiter.check("token-a").is_ok());
        assert!(limiter.check("token-a").is_ok());
        assert!(limiter.check("token-a").is_ok());
        assert!(limiter.check("token-a").is_err()); // 4th request in same second
    }

    #[test]
    fn limits_are_per_token() {
        let limiter = RateLimiter::new(2);
        assert!(limiter.check("token-a").is_ok());
        assert!(limiter.check("token-a").is_ok());
        assert!(limiter.check("token-a").is_err()); // token-a exhausted
        assert!(limiter.check("token-b").is_ok()); // token-b independent
    }

    #[test]
    fn disabled_when_limit_is_zero() {
        let limiter = RateLimiter::new(0);
        for _ in 0..1000 {
            assert!(limiter.check("token-a").is_ok());
        }
    }
}
