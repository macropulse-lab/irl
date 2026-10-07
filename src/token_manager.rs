/// DB-backed token manager.
///
/// Bridges the environment-variable token bootstrap and the `irl.api_tokens`
/// database table introduced in migration 008.
///
/// Lifecycle:
/// 1. **Startup sync** — each token from `IRL_API_TOKENS` is hashed (SHA-256)
///    and upserted into `api_tokens` (source = 'env').  Tokens already present
///    are left untouched; revoked env tokens stay revoked.
/// 2. **In-memory cache** — active token hashes are loaded into a DashMap for
///    O(1) per-request validation with no per-request DB round-trip.
/// 3. **Background refresh** — the cache is refreshed every 60 s so that tokens
///    revoked via the DB take effect promptly without restarting the server.
/// 4. **Last-used tracking** — each validated request fire-and-forgets an
///    UPDATE to `last_used_at`, debounced to at most once per minute per token.
///
/// Configuration:
///   `IRL_API_TOKENS` — comma-separated bearer tokens (bootstrap only)
///   Revoke a token at runtime: UPDATE irl.api_tokens SET status='revoked' WHERE ...
use crate::errors::AppError;
use dashmap::DashMap;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;

/// Identity of an active token, cached for per-request authorization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TokenInfo {
    /// `irl.api_tokens.token_id` — what `agent_registry.owner_token_id` references.
    pub token_id: Uuid,
    /// True for owner-role (operator) tokens, which bypass tenant scoping.
    pub is_owner: bool,
}

pub struct TokenManager {
    /// SHA-256 hex hash of each active token → its identity.
    cache: DashMap<String, TokenInfo>,
    /// Per-token debounce for last_used_at updates (avoids per-request writes).
    last_bumped: DashMap<String, Instant>,
    pool: PgPool,
}

impl TokenManager {
    /// Build a token manager, sync env tokens to DB, and prime the cache.
    pub async fn new(pool: PgPool, env_tokens: &[String]) -> Result<Arc<Self>, AppError> {
        // Sync env-var tokens to the DB (insert if not already present).
        for token in env_tokens {
            let hash = sha256_hex(token);
            sqlx::query(
                r#"
                -- Env-loaded tokens are owner-level (bootstrap/operator tokens),
                -- per migration 014. Set role here so tokens synced AFTER that
                -- one-time migration also get owner (previously defaulted to client).
                INSERT INTO irl.api_tokens (token_hash, client_name, source, status, role)
                VALUES ($1, 'env-loaded', 'env', 'active', 'owner')
                ON CONFLICT (token_hash) DO NOTHING
                "#,
            )
            .bind(&hash)
            .execute(&pool)
            .await?;
        }

        let mgr = Arc::new(Self {
            cache: DashMap::new(),
            last_bumped: DashMap::new(),
            pool,
        });

        mgr.refresh_cache().await?;
        Ok(mgr)
    }

    /// Check whether `raw_token` is currently active.
    /// O(1) — reads the in-memory cache only.
    pub fn is_valid(&self, raw_token: &str) -> bool {
        self.cache.contains_key(&sha256_hex(raw_token))
    }

    /// Identity of `raw_token` if it is currently active.
    /// O(1) — reads the in-memory cache only.
    pub fn lookup(&self, raw_token: &str) -> Option<TokenInfo> {
        self.cache.get(&sha256_hex(raw_token)).map(|e| *e.value())
    }

    /// Fire-and-forget update to `last_used_at`.
    /// Debounced: at most one DB write per token per 60 s.
    pub fn bump_last_used(self: &Arc<Self>, raw_token: &str) {
        let hash = sha256_hex(raw_token);

        // Debounce: skip if this token was bumped recently.
        let should_bump = self
            .last_bumped
            .get(&hash)
            .map(|t| t.elapsed() >= Duration::from_secs(60))
            .unwrap_or(true);

        if !should_bump {
            return;
        }
        self.last_bumped.insert(hash.clone(), Instant::now());

        let mgr = Arc::clone(self);
        tokio::spawn(async move {
            let _ =
                sqlx::query("UPDATE irl.api_tokens SET last_used_at = now() WHERE token_hash = $1")
                    .bind(&hash)
                    .execute(&mgr.pool)
                    .await;
        });
    }

    /// Reload active token hashes from the DB.
    /// Called at startup and by the background refresh task.
    pub async fn refresh_cache(&self) -> Result<(), AppError> {
        let rows: Vec<(String, Uuid, String)> = sqlx::query_as(
            "SELECT token_hash, token_id, role FROM irl.api_tokens WHERE status = 'active'",
        )
        .fetch_all(&self.pool)
        .await?;

        // Insert/overwrite first, then drop entries no longer active, so a
        // concurrent request never sees a valid token missing mid-refresh.
        let active: std::collections::HashSet<String> =
            rows.iter().map(|(hash, _, _)| hash.clone()).collect();
        for (hash, token_id, role) in rows {
            self.cache.insert(
                hash,
                TokenInfo {
                    token_id,
                    is_owner: role == "owner",
                },
            );
        }
        self.cache.retain(|hash, _| active.contains(hash));
        Ok(())
    }

    /// Query the DB for the role of the given raw token.
    /// Returns None if the token is not found or not active.
    pub async fn get_token_role(&self, raw_token: &str) -> Option<String> {
        let hash = sha256_hex(raw_token);
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT role FROM irl.api_tokens WHERE token_hash = $1 AND status = 'active'",
        )
        .bind(&hash)
        .fetch_optional(&self.pool)
        .await
        .ok()
        .flatten();
        row.map(|(r,)| r)
    }
}

/// SHA-256 hex digest of a string. Exported for use in auth and admin modules.
pub fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}
