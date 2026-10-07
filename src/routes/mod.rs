pub mod admin;
pub mod agents;
pub mod attestation;
pub mod authorize;
pub mod batch;
pub mod bind;
pub mod chain;
pub mod tokens;
pub mod traces;

use crate::auth::Caller;
use crate::db;
use crate::errors::AppError;
use crate::metrics;
use crate::tenancy;
use crate::AppState;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Extension, Json,
};
use serde::Deserialize;
use uuid::Uuid;

/// GET /irl/trace/:trace_id
///
/// Returns the full Reasoning_Trace_v1 JSON for forensic audit replay.
/// Overlays live binding fields (final_proof, verification_status) on the stored trace.
/// Decrypts encrypted rows (encryption_version=1) transparently.
pub async fn get_trace(
    State(state): State<AppState>,
    Extension(caller): Extension<Caller>,
    Path(trace_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let pool = state.readonly_pool.as_ref().unwrap_or(&state.pool);
    tenancy::ensure_trace(&state.pool, &caller, trace_id).await?;
    let trace = db::get_trace_json(pool, trace_id, state.key_provider.as_deref()).await?;
    Ok(Json(trace))
}

#[derive(Deserialize)]
pub struct PendingQuery {
    /// Minimum age in seconds before a trace appears in the pending list.
    /// Default: 0 (show all PENDING traces).
    pub age_seconds: Option<i64>,
}

/// GET /irl/pending
///
/// Returns PENDING traces older than `age_seconds` (default: all PENDING).
/// Used by operators to identify unconfirmed intents awaiting bind-execution.
/// Decrypts encrypted rows (encryption_version=1) transparently.
/// Layer 2 v2: the current verified regime and the `mta_ref` agents send
/// with authorize. `previous_mta_ref` is still accepted for the grace window
/// after a regime change.
pub async fn regime(State(state): State<AppState>) -> Result<Json<serde_json::Value>, AppError> {
    let mta = state.mta_client.fetch_verified().await?;
    let previous = state.mta_client.previous_ref();
    Ok(Json(serde_json::json!({
        "mta_ref": mta.hash,
        "regime_id": mta.regime_id,
        "regime_label": mta.regime_label,
        "version": mta.version,
        "broadcast_time": mta.broadcast_time,
        "signal_mode": mta.signal_mode,
        "layer2_mode": format!("{:?}", state.config.layer2_mode).to_lowercase(),
        "mta_ref_grace_secs": state.config.mta_ref_grace_secs,
        "previous_mta_ref": previous.as_ref().map(|(r, _)| r.clone()),
        "previous_replaced_at_ms": previous.map(|(_, at)| at),
    })))
}

pub async fn get_pending(
    State(state): State<AppState>,
    Extension(caller): Extension<Caller>,
    Query(q): Query<PendingQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let age = q.age_seconds.unwrap_or(0);
    let pool = state.readonly_pool.as_ref().unwrap_or(&state.pool);
    let traces =
        db::get_pending_traces(pool, age, caller.scope(), state.key_provider.as_deref()).await?;
    Ok(Json(
        serde_json::json!({ "count": traces.len(), "traces": traces }),
    ))
}

/// GET /irl/orphans
///
/// Returns EXPIRED and DIVERGENT traces — trades that were either never confirmed
/// or where the exchange execution differed from the authorized intent.
/// Decrypts encrypted rows (encryption_version=1) transparently.
pub async fn get_orphans(
    State(state): State<AppState>,
    Extension(caller): Extension<Caller>,
) -> Result<Json<serde_json::Value>, AppError> {
    let pool = state.readonly_pool.as_ref().unwrap_or(&state.pool);
    let traces = db::get_orphan_traces(pool, caller.scope(), state.key_provider.as_deref()).await?;
    Ok(Json(
        serde_json::json!({ "count": traces.len(), "traces": traces }),
    ))
}

/// GET /irl/shadow-violations
///
/// Returns traces where SHADOW_MODE intercepted a policy violation.
/// Used by compliance teams to tune policies before switching to enforcement.
/// Only populated when `SHADOW_MODE=true` has been active.
/// Decrypts encrypted rows (encryption_version=1) transparently.
pub async fn get_shadow_violations(
    State(state): State<AppState>,
    Extension(caller): Extension<Caller>,
) -> Result<Json<serde_json::Value>, AppError> {
    let pool = state.readonly_pool.as_ref().unwrap_or(&state.pool);
    let traces =
        db::get_shadow_violations(pool, caller.scope(), state.key_provider.as_deref()).await?;
    Ok(Json(
        serde_json::json!({ "count": traces.len(), "traces": traces }),
    ))
}

/// GET /metrics
///
/// Prometheus text exposition format.
/// When METRICS_TOKEN is set, requires `Authorization: Bearer <token>`.
/// When unset, the endpoint is open — suitable when restricted at the network layer.
pub async fn metrics_handler(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if let Some(expected) = &state.config.metrics_token {
        let provided = headers
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "));
        if provided != Some(expected.as_str()) {
            return StatusCode::UNAUTHORIZED.into_response();
        }
    }
    match metrics::render() {
        Ok(body) => (
            StatusCode::OK,
            [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
            body,
        )
            .into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    }
}

/// GET /irl/health
///
/// Returns `{"status": "ok"}` with HTTP 200.
/// When MTLS_ENABLED=true, also includes `cert_expiry_status`.
/// Intended for load-balancer and container health probes.
/// Liveness plus real dependency checks. Previously a static `{"status":"ok"}`,
/// which stayed green through a signing-key mismatch and a missing column
/// that broke every authorize.
///
/// - 503 `unavailable`: the database does not answer (container unhealthy,
///   deploy rolls back).
/// - 200 `degraded`: MTA state not verified recently, so authorize will fail
///   closed. Kept at 200 so an MTA outage does not restart-loop the engine.
pub async fn health(
    State(state): State<AppState>,
) -> (axum::http::StatusCode, Json<serde_json::Value>) {
    use crate::mta::{unix_ms_now, MtaFreshness, FALLBACK_TTL_SECS};
    use crate::tls::expiry::{check_cert_expiry, CertExpiryStatus};

    let db_ok = matches!(
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            sqlx::query("SELECT 1").execute(&state.pool),
        )
        .await,
        Ok(Ok(_))
    );

    let (mta, mta_age_ms) = match state.mta_client.freshness() {
        MtaFreshness::Untracked => ("untracked", None),
        MtaFreshness::NeverVerified => ("never_verified", None),
        MtaFreshness::VerifiedAt(at) => {
            let age = unix_ms_now().saturating_sub(at);
            let fresh = age <= FALLBACK_TTL_SECS * 1000;
            (if fresh { "ok" } else { "stale" }, Some(age))
        }
    };

    let status = if !db_ok {
        "unavailable"
    } else if matches!(mta, "never_verified" | "stale") {
        "degraded"
    } else {
        "ok"
    };

    let mut body = serde_json::json!({
        "status": status,
        "db_ok": db_ok,
        "mta": mta,
        "mta_age_ms": mta_age_ms,
    });
    if state.config.mtls_enabled {
        if let Some(not_after) = state.cert_expiry_not_after {
            body["cert_expiry_status"] = match check_cert_expiry(not_after) {
                CertExpiryStatus::Ok => serde_json::json!("ok"),
                CertExpiryStatus::ExpiringSoon { days_remaining } => {
                    serde_json::json!({ "warning": format!("expires in {days_remaining} day(s)") })
                }
                CertExpiryStatus::Expired => serde_json::json!("expired"),
            };
        }
    }

    let code = if db_ok {
        axum::http::StatusCode::OK
    } else {
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    };
    (code, Json(body))
}
