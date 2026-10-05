use crate::binding::{self, BindExecutionRequest, VerificationStatus};
use crate::db;
use crate::errors::AppError;
use crate::metrics;
use crate::AppState;
use axum::{extract::State, Json};

/// POST /irl/bind-execution
///
/// Called by the agent after receiving exchange confirmation.
/// Reconciles the execution report against the authorized intent and closes
/// the audit chain:
///   Agent Reasoning → IRL Snapshot (reasoning_hash) → Exchange Order (final_proof)
///
/// Reconciliation rules (§11.3):
///   - Asset mismatch              → DIVERGENT
///   - Quantity outside tolerance  → DIVERGENT
///   - All checks pass             → MATCHED
///
/// Idempotency: if the trace is already bound (not PENDING), returns 409
/// TRACE_ALREADY_BOUND. Callers must not re-bind a completed trace; duplicate
/// calls indicate a bug in the agent's exchange integration.
pub async fn bind_execution(
    State(state): State<AppState>,
    Json(req): Json<BindExecutionRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    // Fetch authorized intent fields for reconciliation.
    // Also returns current verification_status so we can enforce idempotency.
    let (
        reasoning_hash,
        intent_asset,
        intent_action,
        intent_quantity,
        current_status,
        agent_id,
        intent_venue,
        intent_currency,
        intent_multiplier,
    ) = db::get_intent_for_binding(&state.pool, req.trace_id).await?;

    // Idempotency guard: only PENDING traces may be bound.
    // Re-binding a MATCHED/DIVERGENT/EXPIRED trace would overwrite the final_proof
    // and corrupt the audit chain.
    if current_status != "PENDING" {
        return Err(AppError::TraceAlreadyBound(
            req.trace_id.to_string(),
            current_status,
        ));
    }

    let size_tolerance = state.config.bind_size_tolerance;

    let result = binding::reconcile(
        req.trace_id,
        &reasoning_hash,
        &req,
        &intent_asset,
        &intent_action,
        intent_quantity,
        size_tolerance,
    );

    db::update_binding(&state.pool, &result, &req).await?;

    // Wire the position ledger: update net_quantity for MATCHED fills.
    // quantity_delta is signed: positive for Long (increases net exposure),
    // negative for Short (decreases / builds short exposure).
    if matches!(result.verification_status, VerificationStatus::Matched) {
        if let Some(aid) = agent_id {
            let fill_qty = req.executed_quantity.unwrap_or(0.0);
            // Resolve direction from the stored action string using the same
            // keyword logic as TradeAction::direction().
            let quantity_delta = {
                let lower = intent_action.to_ascii_lowercase();
                let lower = lower.trim();
                if lower.starts_with("long")
                    || lower.contains("open_long")
                    || lower.starts_with("buy")
                    || lower == "open"
                {
                    fill_qty
                } else if lower.starts_with("short")
                    || lower.contains("close_short")
                    || lower.starts_with("sell")
                    || lower == "close"
                    || lower == "exit"
                    || lower == "reverse"
                {
                    -fill_qty
                } else {
                    0.0 // Neutral, Custom(unknown), or flat — no position change
                }
            };

            if quantity_delta != 0.0 {
                db::upsert_position(
                    &state.pool,
                    aid,
                    &intent_asset,
                    &intent_venue,
                    &intent_currency,
                    quantity_delta,
                    req.execution_price,
                    intent_multiplier,
                    req.trace_id,
                )
                .await?;
            }
        }
    }

    let bind_label = match &result.verification_status {
        VerificationStatus::Matched => "matched",
        VerificationStatus::Divergent => "divergent",
        VerificationStatus::Orphan => "orphan",
        _ => "other",
    };
    metrics::get()
        .bind_total
        .with_label_values(&[bind_label])
        .inc();

    let mut resp = serde_json::json!({
        "trace_id": result.trace_id,
        "final_proof": result.final_proof,
        "verification_status": result.verification_status.to_string(),
        "execution_status": result.execution_status,
        "execution_time": result.execution_time,
    });

    if let Some(reason) = &result.divergence_reason {
        resp["divergence_reason"] = serde_json::Value::String(reason.clone());
    }

    Ok(Json(resp))
}
