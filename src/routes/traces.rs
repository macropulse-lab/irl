use crate::{db, errors::AppError, AppState};
use axum::{
    extract::{Query, State},
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct TraceListQuery {
    /// Filter by agent UUID.
    pub agent_id: Option<uuid::Uuid>,
    /// Unix ms — start of time range.
    pub from: Option<i64>,
    /// Unix ms — end of time range.
    pub to: Option<i64>,
    /// Filter by verification_status (PENDING, MATCHED, DIVERGENT, ORPHAN, EXPIRED, SHADOW_HALTED).
    pub status: Option<String>,
    /// Maximum rows to return. Default 500, max 5000.
    pub limit: Option<i64>,
}

#[derive(Serialize)]
pub struct TraceListResponse {
    pub count: usize,
    pub traces: Vec<serde_json::Value>,
}

/// GET /irl/traces — compliance export endpoint.
///
/// Returns a filtered, paginated list of reasoning traces.
/// All query parameters are optional.
///
/// Requires: Authorization: Bearer <token>
pub async fn list_traces(
    State(state): State<AppState>,
    Query(q): Query<TraceListQuery>,
) -> Result<impl IntoResponse, AppError> {
    let limit = q.limit.unwrap_or(500).min(5000);
    let pool = state.readonly_pool.as_ref().unwrap_or(&state.pool);
    let traces = db::list_traces(pool, q.agent_id, q.from, q.to, q.status, limit).await?;
    let count = traces.len();
    Ok(Json(TraceListResponse { count, traces }))
}
