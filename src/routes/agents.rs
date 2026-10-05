/// Multi-Agent Registry CRUD routes.
///
/// POST   /irl/agents                  — Register a new agent
/// GET    /irl/agents                  — List all agents
/// GET    /irl/agents/:id              — Get agent profile
/// PATCH  /irl/agents/:id/status       — Suspend / deregister an agent
use crate::audit::{self, AuditAction};
use crate::auth::{ClientIp, OperatorId};
use crate::errors::AppError;
use crate::registry::{self, RegisterAgentRequest, UpdateStatusRequest};
use crate::AppState;
use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    Json,
};
use serde_json::json;
use uuid::Uuid;

pub async fn register_agent(
    State(state): State<AppState>,
    Extension(operator): Extension<OperatorId>,
    Extension(client_ip): Extension<ClientIp>,
    Json(req): Json<RegisterAgentRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), AppError> {
    // Basic validation: model_hash_hex must be 64 hex chars (32 bytes)
    if req.model_hash_hex.len() != 64 || hex::decode(&req.model_hash_hex).is_err() {
        return Err(AppError::Serialization(
            "model_hash_hex must be a 64-character hex string (32 bytes SHA-256)".to_string(),
        ));
    }

    let agent_id = registry::register_agent(&state.pool, &req).await?;

    // Write audit row after successful registration.
    audit::insert_audit_log(
        &state.pool,
        &operator.0,
        AuditAction::AgentRegister,
        Some(&agent_id.to_string()),
        Some(serde_json::json!({
            "name": req.name,
            "model_hash_hex": req.model_hash_hex,
            "policy_module_id": req.policy_module_id,
            "max_notional": req.max_notional.unwrap_or(1_000_000.0),
        })),
        client_ip.0,
    )
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "agent_id": agent_id,
            "model_hash_hex": req.model_hash_hex,
            "status": "Active",
        })),
    ))
}

pub async fn list_agents(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, AppError> {
    let agents = registry::list_agents(&state.pool).await?;
    Ok(Json(json!({ "agents": agents })))
}

pub async fn get_agent(
    State(state): State<AppState>,
    Path(agent_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let profile = registry::fetch_profile(&state.pool, agent_id).await?;
    let value =
        serde_json::to_value(profile).map_err(|e| AppError::Serialization(e.to_string()))?;
    Ok(Json(value))
}

pub async fn update_agent_status(
    State(state): State<AppState>,
    Extension(operator): Extension<OperatorId>,
    Extension(client_ip): Extension<ClientIp>,
    Path(agent_id): Path<Uuid>,
    Json(req): Json<UpdateStatusRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let valid = ["Active", "Suspended", "Deregistered"];
    if !valid.contains(&req.status.as_str()) {
        return Err(AppError::Serialization(format!(
            "status must be one of: {}",
            valid.join(", ")
        )));
    }
    let old_status = registry::update_status(&state.pool, agent_id, &req.status).await?;

    // Determine the specific audit action based on new status.
    let action = match req.status.as_str() {
        "Suspended" => AuditAction::AgentSuspend,
        "Active" => AuditAction::AgentActivate,
        _ => AuditAction::AgentStatusChange,
    };

    audit::insert_audit_log(
        &state.pool,
        &operator.0,
        action,
        Some(&agent_id.to_string()),
        Some(serde_json::json!({
            "old_status": old_status,
            "new_status": req.status,
        })),
        client_ip.0,
    )
    .await?;

    Ok(Json(json!({ "agent_id": agent_id, "status": req.status })))
}
