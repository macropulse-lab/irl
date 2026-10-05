//! DB-backed shadow mode cache.
//!
//! `ShadowModeCache` wraps an `AtomicBool` (hot-path, lock-free) backed by the
//! `irl.system_config` row with key = 'shadow_mode'.
//!
//! Lifecycle:
//! 1. `ShadowModeCache::new()` — reads the DB row; if absent, inserts it with
//!    the env-var default and uses that value.
//! 2. `is_enabled()` — O(1) atomic read, no DB round-trip.
//! 3. `set()` — writes DB row + updates AtomicBool immediately.
//! 4. Background loop (spawned in main.rs) — calls `refresh()` every 30 s so
//!    out-of-band DB edits are picked up without a restart.

use crate::errors::AppError;
use sqlx::PgPool;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

pub struct ShadowModeCache {
    value: AtomicBool,
    pool: PgPool,
}

impl ShadowModeCache {
    /// Create a new cache.
    ///
    /// Queries `irl.system_config` for key = 'shadow_mode'. If the row exists,
    /// uses its `value_bool`. If absent, inserts a seed row with `env_default`
    /// and uses that value.
    pub async fn new(pool: PgPool, env_default: bool) -> Result<Arc<Self>, AppError> {
        let row: Option<(Option<bool>,)> =
            sqlx::query_as("SELECT value_bool FROM irl.system_config WHERE key = 'shadow_mode'")
                .fetch_optional(&pool)
                .await?;

        let current = match row {
            Some((Some(v),)) => v,
            Some((None,)) => env_default, // row exists but value_bool is NULL — use env default
            None => {
                // Row absent — seed it and use env_default.
                sqlx::query(
                    r#"
                    INSERT INTO irl.system_config (key, value_bool, updated_by)
                    VALUES ('shadow_mode', $1, 'system')
                    ON CONFLICT (key) DO NOTHING
                    "#,
                )
                .bind(env_default)
                .execute(&pool)
                .await?;
                env_default
            }
        };

        Ok(Arc::new(Self {
            value: AtomicBool::new(current),
            pool,
        }))
    }

    /// Returns the current shadow mode value.
    ///
    /// Uses `Ordering::Acquire` — pairs with the `Release` in `set()` and
    /// `refresh()` to guarantee visibility of any preceding store.
    #[inline]
    pub fn is_enabled(&self) -> bool {
        self.value.load(Ordering::Acquire)
    }

    /// Write a new value to the DB and update the in-process cache immediately.
    ///
    /// `updated_by` should be the operator ID (token id or user id) performing
    /// the change — it is stored in `irl.system_config.updated_by`.
    pub async fn set(&self, new_value: bool, updated_by: &str) -> Result<(), AppError> {
        sqlx::query(
            r#"
            UPDATE irl.system_config
            SET value_bool = $1, updated_at = now(), updated_by = $2
            WHERE key = 'shadow_mode'
            "#,
        )
        .bind(new_value)
        .bind(updated_by)
        .execute(&self.pool)
        .await?;

        self.value.store(new_value, Ordering::Release);
        Ok(())
    }

    /// Re-read the DB row and update the in-process cache.
    ///
    /// Called by the background refresh loop every 30 s.
    pub async fn refresh(&self) -> Result<(), AppError> {
        let row: Option<(Option<bool>,)> =
            sqlx::query_as("SELECT value_bool FROM irl.system_config WHERE key = 'shadow_mode'")
                .fetch_optional(&self.pool)
                .await?;

        if let Some((Some(v),)) = row {
            self.value.store(v, Ordering::Release);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test the AtomicBool semantics directly (pure unit tests, no DB required).
    /// is_enabled() uses Ordering::Acquire; set_direct() uses Ordering::Release.
    #[test]
    fn atomic_bool_true_initial() {
        let flag = AtomicBool::new(true);
        assert!(flag.load(Ordering::Acquire));
    }

    #[test]
    fn atomic_bool_false_initial() {
        let flag = AtomicBool::new(false);
        assert!(!flag.load(Ordering::Acquire));
    }

    #[test]
    fn atomic_bool_store_and_load() {
        let flag = AtomicBool::new(false);
        assert!(!flag.load(Ordering::Acquire));
        flag.store(true, Ordering::Release);
        assert!(flag.load(Ordering::Acquire));
        flag.store(false, Ordering::Release);
        assert!(!flag.load(Ordering::Acquire));
    }
}
