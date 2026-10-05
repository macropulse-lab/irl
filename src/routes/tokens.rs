/// Admin token management endpoints.
///
/// All routes in this module require owner-level token (enforced by require_owner middleware).
///
/// POST   /irl/admin/tokens          — Issue a new client token (returned once, never stored)
/// DELETE /irl/admin/tokens/:token_id — Soft-revoke a token by its 12-char hash prefix
use crate::audit::{self, AuditAction};
use crate::auth::{ClientIp, OperatorId};
use crate::errors::AppError;
use crate::token_manager::sha256_hex;
use crate::AppState;
use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    Json,
};
use rand::Rng;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct TokenIssueRequest {
    pub client_name: String,
}

/// POST /irl/admin/tokens
///
/// Issue a new client-role API token. The raw token is returned exactly once
/// and is never stored — only its SHA-256 hash is persisted in irl.api_tokens.
pub async fn token_issue(
    State(state): State<AppState>,
    Extension(operator): Extension<OperatorId>,
    Extension(client_ip): Extension<ClientIp>,
    Json(req): Json<TokenIssueRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), AppError> {
    if req.client_name.trim().is_empty() {
        return Err(AppError::Serialization(
            "client_name must not be empty".to_string(),
        ));
    }

    // Generate a cryptographically random 32-byte token encoded as 64 hex chars.
    let raw_bytes: [u8; 32] = rand::thread_rng().gen();
    let raw_token = hex::encode(raw_bytes);
    let hash = sha256_hex(&raw_token);
    let token_id = &hash[..12];

    sqlx::query(
        r#"
        INSERT INTO irl.api_tokens (token_hash, client_name, source, status, role)
        VALUES ($1, $2, 'api', 'active', 'client')
        "#,
    )
    .bind(&hash)
    .bind(&req.client_name)
    .execute(&state.pool)
    .await?;

    // Refresh cache so new token is active immediately.
    state.token_manager.refresh_cache().await?;

    audit::insert_audit_log(
        &state.pool,
        &operator.0,
        AuditAction::TokenIssue,
        Some(token_id),
        Some(serde_json::json!({ "client_name": req.client_name })),
        client_ip.0,
    )
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "token_id": token_id,
            "client_name": req.client_name,
            "token": raw_token,
        })),
    ))
}

/// DELETE /irl/admin/tokens/:token_id
///
/// Soft-revoke a token by its 12-char hash prefix (returned at issue time).
/// Takes effect immediately — cache is refreshed after DB update.
pub async fn token_revoke(
    State(state): State<AppState>,
    Extension(operator): Extension<OperatorId>,
    Extension(client_ip): Extension<ClientIp>,
    Path(token_id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    if token_id.len() != 12 {
        return Err(AppError::Serialization(
            "token_id must be exactly 12 characters".to_string(),
        ));
    }

    // Look up full hash and client_name by 12-char prefix.
    let row: Option<(String, String)> = sqlx::query_as(
        r#"
        SELECT token_hash, client_name
        FROM irl.api_tokens
        WHERE LEFT(token_hash, 12) = $1 AND status = 'active'
        "#,
    )
    .bind(&token_id)
    .fetch_optional(&state.pool)
    .await?;

    let (full_hash, client_name) = match row {
        Some(r) => r,
        None => {
            return Err(AppError::Serialization(format!(
                "No active token found with id: {token_id}"
            )))
        }
    };

    sqlx::query("UPDATE irl.api_tokens SET status = 'revoked' WHERE token_hash = $1")
        .bind(&full_hash)
        .execute(&state.pool)
        .await?;

    // Refresh cache so revocation takes effect immediately.
    state.token_manager.refresh_cache().await?;

    audit::insert_audit_log(
        &state.pool,
        &operator.0,
        AuditAction::TokenRevoke,
        Some(&token_id),
        Some(serde_json::json!({ "client_name": client_name })),
        client_ip.0,
    )
    .await?;

    Ok(Json(serde_json::json!({
        "token_id": token_id,
        "status": "revoked",
    })))
}
