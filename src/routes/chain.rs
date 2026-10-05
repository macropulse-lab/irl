use crate::db;
use crate::errors::AppError;
use crate::AppState;
use axum::{
    extract::{Path, State},
    Json,
};
use uuid::Uuid;

/// GET /irl/trace/:trace_id/chain
///
/// Returns the full ancestry chain for a trace plus its direct children.
///
/// Response:
/// ```json
/// {
///   "trace_id": "<requested>",
///   "ancestry": [
///     { "trace_id": "<root>",      "depth": 2, "parent_trace_id": null, ... },
///     { "trace_id": "<mid>",       "depth": 1, "parent_trace_id": "<root>", ... },
///     { "trace_id": "<requested>", "depth": 0, "parent_trace_id": "<mid>", ... }
///   ],
///   "children": [
///     { "trace_id": "<sub-agent1>", "parent_trace_id": "<requested>", ... }
///   ]
/// }
/// ```
///
/// Useful for multi-agent compliance audits: given any trace in a causal chain,
/// returns the full orchestrator lineage and all sub-agents dispatched from it.
pub async fn get_trace_chain(
    State(state): State<AppState>,
    Path(trace_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let chain = db::get_trace_chain(&state.pool, trace_id).await?;
    Ok(Json(chain))
}
