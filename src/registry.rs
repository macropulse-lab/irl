#![allow(clippy::type_complexity)]

/// Multi-Agent Registry (MAR) — whitepaper v3 §10.
///
/// Each agent in a fleet is a unique cryptographic entity identified by:
/// - `agent_id` (UUID, primary key)
/// - `model_hash_hex` (SHA-256 of model version + config)
///
/// Authorization logic (§10.3):
/// 1. Agent must exist and be Active
/// 2. Running model hash must match registered model_hash_hex
/// 3. Current regime must be in allowed_regimes
/// 4. Intent notional must be ≤ max_notional
use crate::errors::{AppError, PolicyError};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct AgentProfile {
    pub agent_id: Uuid,
    pub name: String,
    pub model_hash_hex: String,
    pub policy_module_id: String,
    /// NULL = allow all regime IDs (correct default for custom MTA operators).
    pub allowed_regimes: Option<Vec<i16>>,
    pub max_notional: f64,
    /// Stored for the agent's mandate; not enforced, because the authorize
    /// request carries no leverage figure to check it against.
    pub max_leverage: f64,
    /// NULL = any venue. Enforced at authorize (case-insensitive `venue_id`).
    pub allowed_venues: Option<Vec<String>>,
    /// NULL = any asset. Enforced at authorize (case-insensitive `asset`).
    pub allowed_assets: Option<Vec<String>>,
    pub status: String,
    /// NULL = accept any MTA operator. Non-NULL = only accept operators whose
    /// Ed25519 pubkey hex fingerprint is in this list (MTA-01).
    pub allowed_mta_pubkeys: Option<Vec<String>>,
}

const PROFILE_COLUMNS: &str = "agent_id, name, model_hash_hex, policy_module_id,      allowed_regimes, max_notional::float8 AS max_notional,      max_leverage::float8 AS max_leverage, allowed_venues, allowed_assets,      status, allowed_mta_pubkeys";

/// Request body for POST /irl/agents.
#[derive(Debug, Deserialize)]
pub struct RegisterAgentRequest {
    pub name: String,
    /// Hex-encoded SHA-256 of the model version + config (64 hex chars = 32 bytes).
    pub model_hash_hex: String,
    pub policy_module_id: Option<String>,
    pub allowed_regimes: Option<Vec<i16>>,
    pub max_notional: Option<f64>,
    pub max_leverage: Option<f64>,
    pub allowed_venues: Option<Vec<String>>,
    pub allowed_assets: Option<Vec<String>>,
    /// Optional list of accepted MTA operator pubkey hex fingerprints (MTA-01).
    /// NULL = accept any MTA operator.
    pub allowed_mta_pubkeys: Option<Vec<String>>,
}

/// Request body for PATCH /irl/agents/:id/status.
#[derive(Debug, Deserialize)]
pub struct UpdateStatusRequest {
    pub status: String,
}

/// Verify an agent's identity and regime authorization.
///
/// Called at the start of every POST /irl/authorize before snapshot construction.
/// Returns the agent profile (used downstream for notional cap in policy::enforce).
///
/// Checks:
/// 1. Agent must be Active
/// 2. Running model hash must match registered model_hash_hex
/// 3. Current regime_id must be in agent's allowed_regimes whitelist
/// 4. MTA operator pubkey must be in agent's allowed_mta_pubkeys
/// 5. venue_id and asset must be in the agent's allowed_venues / allowed_assets
///
/// Notional enforcement is handled by `policy::enforce`, which applies
/// the regime-level `max_notional_scale` on top of `profile.max_notional`.
pub async fn authorize_agent(
    pool: &PgPool,
    agent_id: Uuid,
    observed_model_hash: &[u8; 32],
    current_regime: u8,
    mta_pubkey_fingerprint: &str,
    venue_id: &str,
    asset: &str,
) -> Result<AgentProfile, AppError> {
    let profile = fetch_profile(pool, agent_id).await?;

    // 1. Agent must be Active
    if profile.status != "Active" {
        return Err(AppError::Policy(PolicyError::AgentNotActive));
    }

    // 2. Model hash must match
    let registered_hash = hex::decode(&profile.model_hash_hex).map_err(|_| {
        AppError::Serialization("Corrupted model_hash_hex in agent registry".into())
    })?;
    if registered_hash != observed_model_hash.as_ref() {
        return Err(AppError::Policy(PolicyError::ModelHashMismatch));
    }

    // 3. Current regime must be in allowed_regimes (None = allow all)
    if let Some(ref allowed) = profile.allowed_regimes {
        if !allowed.contains(&(current_regime as i16)) {
            return Err(AppError::Policy(PolicyError::RegimeUnauthorized {
                regime_id: current_regime,
            }));
        }
    }

    // 4. MTA-02: MTA pubkey must be in agent's allowed set (None = allow any)
    if let Some(ref allowed_keys) = profile.allowed_mta_pubkeys {
        if !allowed_keys.iter().any(|k| k == mta_pubkey_fingerprint) {
            return Err(AppError::Policy(PolicyError::MtaPubkeyUnauthorized {
                pubkey: mta_pubkey_fingerprint.to_string(),
            }));
        }
    }

    // 5. Trading scope: venue and asset allowlists (None = allow any)
    check_scope(&profile, venue_id, asset)?;

    Ok(profile)
}

/// Pre-trade scope check against the agent's venue and asset allowlists.
/// Matching is trimmed and case-insensitive; `None` means unrestricted, while
/// an empty list permits nothing.
pub fn check_scope(profile: &AgentProfile, venue_id: &str, asset: &str) -> Result<(), AppError> {
    if !in_allowlist(profile.allowed_venues.as_deref(), venue_id) {
        return Err(AppError::Policy(PolicyError::VenueUnauthorized {
            venue: venue_id.to_string(),
        }));
    }
    if !in_allowlist(profile.allowed_assets.as_deref(), asset) {
        return Err(AppError::Policy(PolicyError::AssetUnauthorized {
            asset: asset.to_string(),
        }));
    }
    Ok(())
}

fn in_allowlist(allowed: Option<&[String]>, value: &str) -> bool {
    match allowed {
        None => true,
        Some(list) => list
            .iter()
            .any(|a| a.trim().eq_ignore_ascii_case(value.trim())),
    }
}

/// Fetch an agent profile from the DB. Returns AgentNotFound if not present.
pub async fn fetch_profile(pool: &PgPool, agent_id: Uuid) -> Result<AgentProfile, AppError> {
    let sql = format!("SELECT {PROFILE_COLUMNS} FROM irl.agent_registry WHERE agent_id = $1");
    sqlx::query_as::<_, AgentProfile>(&sql)
        .bind(agent_id)
        .fetch_optional(pool)
        .await?
        .ok_or(AppError::Policy(PolicyError::AgentNotFound))
}

/// Register a new agent and return the assigned agent_id.
/// `owner_token_id` is the registering token; client tokens may only act on
/// agents they own (see `tenancy`).
pub async fn register_agent(
    pool: &PgPool,
    req: &RegisterAgentRequest,
    owner_token_id: Uuid,
) -> Result<Uuid, AppError> {
    // None = allow all regime IDs. Use Some(vec![...]) to restrict to specific IDs.
    let allowed_regimes = req.allowed_regimes.clone();
    let max_notional = req.max_notional.unwrap_or(1_000_000.0);
    let max_leverage = req.max_leverage.unwrap_or(4.0);
    let policy_module_id = req
        .policy_module_id
        .clone()
        .unwrap_or_else(|| "default".to_string());

    let row: (Uuid,) = sqlx::query_as(
        r#"
        INSERT INTO irl.agent_registry
            (name, model_hash_hex, policy_module_id, allowed_regimes,
             max_notional, max_leverage, allowed_venues, allowed_assets, allowed_mta_pubkeys,
             owner_token_id)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        RETURNING agent_id
        "#,
    )
    .bind(&req.name)
    .bind(&req.model_hash_hex)
    .bind(&policy_module_id)
    .bind(&allowed_regimes)
    .bind(max_notional)
    .bind(max_leverage)
    .bind(&req.allowed_venues)
    .bind(&req.allowed_assets)
    .bind(&req.allowed_mta_pubkeys)
    .bind(owner_token_id)
    .fetch_one(pool)
    .await?;

    Ok(row.0)
}

/// Update agent status (Active | Suspended | Deregistered).
///
/// Uses a CTE to atomically capture the old status before updating,
/// returning it for audit log details. Returns Err(AgentNotFound) if no row matched.
pub async fn update_status(
    pool: &PgPool,
    agent_id: Uuid,
    status: &str,
) -> Result<Option<String>, AppError> {
    let row: Option<(String,)> = sqlx::query_as(
        r#"
        WITH old AS (
            SELECT status FROM irl.agent_registry WHERE agent_id = $1
        ),
        updated AS (
            UPDATE irl.agent_registry SET status = $2, updated_at = now()
            WHERE agent_id = $1
            RETURNING agent_id
        )
        SELECT old.status FROM old, updated
        "#,
    )
    .bind(agent_id)
    .bind(status)
    .fetch_optional(pool)
    .await?;

    if row.is_none() {
        return Err(AppError::Policy(PolicyError::AgentNotFound));
    }
    Ok(row.map(|(s,)| s))
}

/// List all agents (owner-only route).
pub async fn list_agents(pool: &PgPool) -> Result<Vec<AgentProfile>, AppError> {
    let sql =
        format!("SELECT {PROFILE_COLUMNS} FROM irl.agent_registry ORDER BY registered_at DESC");
    Ok(sqlx::query_as::<_, AgentProfile>(&sql)
        .fetch_all(pool)
        .await?)
}

// ── Unit tests — MTA pubkey allowlist logic (MTA-01, MTA-02) ─────────────────
//
// These tests verify the check logic in authorize_agent without requiring
// a live DB. They construct AgentProfile values directly and exercise
// the pubkey check conditions.

#[cfg(test)]
mod mta_pubkey_tests {
    use super::*;

    fn make_profile(allowed_mta_pubkeys: Option<Vec<String>>) -> AgentProfile {
        AgentProfile {
            agent_id: Uuid::new_v4(),
            name: "test-agent".to_string(),
            model_hash_hex: "a".repeat(64),
            policy_module_id: "default".to_string(),
            allowed_regimes: None,
            max_notional: 1_000_000.0,
            max_leverage: 4.0,
            allowed_venues: None,
            allowed_assets: None,
            status: "Active".to_string(),
            allowed_mta_pubkeys,
        }
    }

    fn check_mta(profile: &AgentProfile, fingerprint: &str) -> Result<(), AppError> {
        if let Some(ref allowed_keys) = profile.allowed_mta_pubkeys {
            if !allowed_keys.iter().any(|k| k == fingerprint) {
                return Err(AppError::Policy(PolicyError::MtaPubkeyUnauthorized {
                    pubkey: fingerprint.to_string(),
                }));
            }
        }
        Ok(())
    }

    #[test]
    fn none_allowed_mta_pubkeys_accepts_any_fingerprint() {
        // MTA-01: NULL allowed_mta_pubkeys → accept any MTA operator (backward-compat).
        let profile = make_profile(None);
        assert!(check_mta(&profile, "any_fingerprint_at_all").is_ok());
    }

    #[test]
    fn matching_fingerprint_in_allowed_set_passes() {
        // MTA-02: fingerprint in allowed set → authorized.
        let fp = "aabbcc".repeat(10) + "aabb";
        let profile = make_profile(Some(vec![fp.clone(), "other_key".to_string()]));
        assert!(check_mta(&profile, &fp).is_ok());
    }

    #[test]
    fn fingerprint_not_in_allowed_set_is_rejected() {
        // MTA-02: fingerprint NOT in allowed set → MtaPubkeyUnauthorized error.
        let allowed = "allowed_key_fingerprint".to_string();
        let profile = make_profile(Some(vec![allowed]));
        let result = check_mta(&profile, "unauthorized_key");
        assert!(result.is_err());
        match result.unwrap_err() {
            AppError::Policy(PolicyError::MtaPubkeyUnauthorized { pubkey }) => {
                assert_eq!(pubkey, "unauthorized_key");
            }
            e => panic!("expected MtaPubkeyUnauthorized, got {e:?}"),
        }
    }

    #[test]
    fn empty_allowed_set_rejects_all_fingerprints() {
        // Edge case: Some(vec![]) — no operator is trusted.
        let profile = make_profile(Some(vec![]));
        assert!(check_mta(&profile, "any_key").is_err());
    }

    #[test]
    fn single_key_allowlist_is_accepted_for_matching_key() {
        // MTA-02: single-key set is the degenerate case of multi-MTA.
        let fp = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string();
        let profile = make_profile(Some(vec![fp.clone()]));
        assert!(check_mta(&profile, &fp).is_ok());
    }
}

#[cfg(test)]
mod scope_tests {
    use super::*;

    fn profile(venues: Option<&[&str]>, assets: Option<&[&str]>) -> AgentProfile {
        let owned = |l: Option<&[&str]>| l.map(|v| v.iter().map(|s| s.to_string()).collect());
        AgentProfile {
            agent_id: Uuid::new_v4(),
            name: "scope-agent".to_string(),
            model_hash_hex: "a".repeat(64),
            policy_module_id: "default".to_string(),
            allowed_regimes: None,
            max_notional: 1_000.0,
            max_leverage: 1.0,
            allowed_venues: owned(venues),
            allowed_assets: owned(assets),
            status: "Active".to_string(),
            allowed_mta_pubkeys: None,
        }
    }

    #[test]
    fn unrestricted_profile_allows_any_venue_and_asset() {
        assert!(check_scope(&profile(None, None), "anywhere", "ANYTHING").is_ok());
    }

    #[test]
    fn listed_venue_and_asset_pass_case_insensitively() {
        let p = profile(Some(&["binance"]), Some(&["BTCUSDT", "ETHUSDT"]));
        assert!(check_scope(&p, "BINANCE", "btcusdt").is_ok());
        assert!(check_scope(&p, " binance ", "ETHUSDT").is_ok());
    }

    #[test]
    fn unlisted_venue_is_rejected_with_its_name() {
        let p = profile(Some(&["binance"]), None);
        match check_scope(&p, "kraken", "BTCUSDT") {
            Err(AppError::Policy(PolicyError::VenueUnauthorized { venue })) => {
                assert_eq!(venue, "kraken")
            }
            other => panic!("expected VenueUnauthorized, got {other:?}"),
        }
    }

    #[test]
    fn unlisted_asset_is_rejected_with_its_name() {
        let p = profile(None, Some(&["BTCUSDT"]));
        match check_scope(&p, "binance", "DOGEUSDT") {
            Err(AppError::Policy(PolicyError::AssetUnauthorized { asset })) => {
                assert_eq!(asset, "DOGEUSDT")
            }
            other => panic!("expected AssetUnauthorized, got {other:?}"),
        }
    }

    #[test]
    fn empty_allowlist_permits_nothing() {
        assert!(check_scope(&profile(Some(&[]), None), "binance", "BTCUSDT").is_err());
        assert!(check_scope(&profile(None, Some(&[])), "binance", "BTCUSDT").is_err());
    }

    #[test]
    fn scope_errors_map_to_403_codes() {
        let venue = AppError::Policy(PolicyError::VenueUnauthorized { venue: "x".into() });
        let asset = AppError::Policy(PolicyError::AssetUnauthorized { asset: "y".into() });
        assert_eq!(venue.error_code(), "VENUE_UNAUTHORIZED");
        assert_eq!(asset.error_code(), "ASSET_UNAUTHORIZED");
    }
}
