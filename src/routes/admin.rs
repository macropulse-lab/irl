#![allow(clippy::type_complexity)]

/// Admin endpoints for shadow mode management and audit log queries.
///
/// All routes in this module require owner-level token (enforced by require_owner middleware).
///
/// GET  /irl/admin/shadow-mode   — Current shadow mode state from DB
/// POST /irl/admin/shadow-mode   — Enable or disable shadow mode
/// GET  /irl/admin/audit-log     — Paginated audit log with optional filters
use crate::audit::{self, AuditAction};
use crate::auth::{ClientIp, OperatorId};
use crate::errors::AppError;
use crate::AppState;
use axum::{
    body::Body,
    extract::{Extension, Path, Query, State},
    http::{header, HeaderValue},
    response::Response,
    Json,
};
use chrono::{DateTime, NaiveDate, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct SetShadowModeRequest {
    pub enabled: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ShadowModeResponse {
    pub shadow_mode: bool,
    pub updated_at: Option<DateTime<Utc>>,
    pub updated_by: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AuditLogQuery {
    pub action: Option<String>,
    pub target_id: Option<String>,
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    pub before_id: Option<Uuid>,
    pub limit: Option<i64>,
}

/// GET /irl/admin/shadow-mode
///
/// Returns current shadow mode value and metadata from irl.system_config.
pub async fn shadow_mode_get(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, AppError> {
    let row: Option<(bool, Option<DateTime<Utc>>, Option<String>)> = sqlx::query_as(
        r#"
        SELECT value_bool, updated_at, updated_by
        FROM irl.system_config
        WHERE key = 'shadow_mode'
        "#,
    )
    .fetch_optional(&state.pool)
    .await?;

    match row {
        Some((enabled, updated_at, updated_by)) => Ok(Json(serde_json::json!({
            "shadow_mode": enabled,
            "updated_at": updated_at,
            "updated_by": updated_by,
        }))),
        None => Ok(Json(serde_json::json!({
            "shadow_mode": false,
            "updated_at": null,
            "updated_by": null,
        }))),
    }
}

/// POST /irl/admin/shadow-mode
///
/// Enable or disable shadow mode. Requires owner-level token.
/// Writes an audit row with old and new values.
pub async fn shadow_mode_set(
    State(state): State<AppState>,
    Extension(operator): Extension<OperatorId>,
    Extension(client_ip): Extension<ClientIp>,
    Json(req): Json<SetShadowModeRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let old = state.shadow_mode.is_enabled();

    state.shadow_mode.set(req.enabled, &operator.0).await?;

    audit::insert_audit_log(
        &state.pool,
        &operator.0,
        AuditAction::ShadowModeChange,
        None,
        Some(serde_json::json!({
            "old_value": old,
            "new_value": req.enabled,
            "reason": req.reason,
        })),
        client_ip.0,
    )
    .await?;

    Ok(Json(serde_json::json!({
        "shadow_mode": req.enabled,
        "changed_by": operator.0,
    })))
}

/// GET /irl/admin/audit-log
///
/// Returns paginated audit log entries with optional filters.
/// Supports filtering by action, target_id, time range, and cursor-based pagination.
pub async fn audit_log_query(
    State(state): State<AppState>,
    Query(params): Query<AuditLogQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let limit = params.limit.unwrap_or(50).clamp(1, 500);

    // Fetch one extra row to determine if there are more pages.
    let rows: Vec<(
        Uuid,
        String,
        String,
        Option<String>,
        Option<String>,
        Option<serde_json::Value>,
        Option<String>,
        DateTime<Utc>,
    )> = sqlx::query_as(
        r#"
        SELECT id, operator_id, action, target_type, target_id, details_json,
               ip_address::text, created_at
        FROM irl.admin_audit_log
        WHERE ($1::text IS NULL OR action = $1)
          AND ($2::text IS NULL OR target_id = $2)
          AND ($3::timestamptz IS NULL OR created_at >= $3)
          AND ($4::timestamptz IS NULL OR created_at <= $4)
          AND ($5::uuid IS NULL OR id < $5)
        ORDER BY id DESC
        LIMIT $6
        "#,
    )
    .bind(params.action.as_deref())
    .bind(params.target_id.as_deref())
    .bind(params.from)
    .bind(params.to)
    .bind(params.before_id)
    .bind(limit + 1)
    .fetch_all(state.readonly_pool.as_ref().unwrap_or(&state.pool))
    .await?;

    let has_more = rows.len() as i64 > limit;
    let entries: Vec<_> = rows
        .into_iter()
        .take(limit as usize)
        .map(
            |(
                id,
                operator_id,
                action,
                target_type,
                target_id,
                details_json,
                ip_address,
                created_at,
            )| {
                serde_json::json!({
                    "id": id,
                    "operator_id": operator_id,
                    "action": action,
                    "target_type": target_type,
                    "target_id": target_id,
                    "details_json": details_json,
                    "ip_address": ip_address,
                    "created_at": created_at,
                })
            },
        )
        .collect();

    let next_cursor = if has_more {
        entries
            .last()
            .and_then(|e| e["id"].as_str().map(String::from))
    } else {
        None
    };

    Ok(Json(serde_json::json!({
        "count": entries.len(),
        "entries": entries,
        "next_cursor": next_cursor,
    })))
}

/// POST /irl/admin/gdpr-erase/:agent_id
///
/// GDPR Art. 17 erasure endpoint. Decrypts all trace_json rows for the agent,
/// nullifies PII fields (agent.agent_id, agent.latent_fingerprint,
/// agent.feature_schema_id, execution.client_order_id, execution.venue_id),
/// re-encrypts with fresh DEK + nonce, and records an audit row.
///
/// Requires: owner-level token. Requires: KMS key_provider configured.
/// Returns: 200 { agent_id, gdpr_request_id, traces_erased, status }
/// Returns: 500 if encryption not configured (key_provider is None).
pub async fn gdpr_erase_handler(
    State(state): State<AppState>,
    Extension(operator): Extension<OperatorId>,
    Extension(client_ip): Extension<ClientIp>,
    Path(agent_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let gdpr_request_id = Uuid::new_v4();

    let key_provider = state.key_provider.as_deref().ok_or_else(|| {
        AppError::Encryption(
            "KMS provider required for GDPR erasure — configure KMS_PROVIDER".into(),
        )
    })?;

    let erased_count =
        crate::gdpr::gdpr_erase_agent(&state.pool, agent_id, gdpr_request_id, key_provider).await?;

    crate::audit::insert_audit_log(
        &state.pool,
        &operator.0,
        crate::audit::AuditAction::GdprErasure,
        Some(&agent_id.to_string()),
        Some(serde_json::json!({
            "gdpr_request_id": gdpr_request_id,
            "traces_erased": erased_count,
        })),
        client_ip.0,
    )
    .await?;

    Ok(Json(serde_json::json!({
        "agent_id": agent_id,
        "gdpr_request_id": gdpr_request_id,
        "traces_erased": erased_count,
        "status": "erased",
    })))
}

#[derive(Debug, Deserialize)]
pub struct EvidenceExportQuery {
    pub from: String,
    pub to: String,
}

/// GET /irl/admin/evidence?from=YYYY-MM-DD&to=YYYY-MM-DD
///
/// Returns a SOC 2 evidence ZIP archive for the given date range.
/// Contains audit_log.csv, key_rotations.csv, policy_decisions.csv, MANIFEST.txt.
/// Intended to be handed directly to a SOC 2 auditor.
pub async fn evidence_export(
    State(state): State<AppState>,
    Query(params): Query<EvidenceExportQuery>,
) -> Result<Response, AppError> {
    let from_date = NaiveDate::parse_from_str(&params.from, "%Y-%m-%d").map_err(|_| {
        AppError::BadRequest(format!("from must be YYYY-MM-DD, got '{}'", params.from))
    })?;
    let to_date = NaiveDate::parse_from_str(&params.to, "%Y-%m-%d")
        .map_err(|_| AppError::BadRequest(format!("to must be YYYY-MM-DD, got '{}'", params.to)))?;

    let from = Utc.from_utc_datetime(&from_date.and_hms_opt(0, 0, 0).unwrap());
    let to = Utc.from_utc_datetime(&to_date.and_hms_opt(23, 59, 59).unwrap());

    let pool = state.readonly_pool.as_ref().unwrap_or(&state.pool);
    let zip_bytes = crate::evidence::build_zip_for_range(pool, from, to).await?;

    let filename = format!("irl-evidence-{}-{}.zip", params.from, params.to);
    let disposition = HeaderValue::from_str(&format!("attachment; filename=\"{filename}\""))
        .unwrap_or_else(|_| HeaderValue::from_static("attachment; filename=\"evidence.zip\""));

    let resp = Response::builder()
        .status(200)
        .header(header::CONTENT_TYPE, "application/zip")
        .header(header::CONTENT_DISPOSITION, disposition)
        .body(Body::from(zip_bytes))
        .map_err(|e| AppError::Serialization(e.to_string()))?;

    Ok(resp)
}
