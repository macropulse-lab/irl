//! Tenant isolation: client tokens act only on agents they registered.
//!
//! Every agent-scoped route calls one of these guards. Owner-role tokens
//! bypass them. A client that names an agent or trace it does not own gets
//! the same NOT_FOUND as for one that does not exist, so ids from other
//! tenants cannot be probed.
//!
//! List queries take `scope: Option<Uuid>` (`Caller::scope()`) and filter with
//! `($n::uuid IS NULL OR agent_id IN (SELECT agent_id FROM irl.agent_registry
//! WHERE owner_token_id = $n))`; NULL (owner token) matches every row.

use crate::auth::Caller;
use crate::errors::{AppError, PolicyError};
use sqlx::PgPool;
use uuid::Uuid;

/// Ok if `caller` may act on `agent_id`; AGENT_NOT_FOUND otherwise.
pub async fn ensure_agent(pool: &PgPool, caller: &Caller, agent_id: Uuid) -> Result<(), AppError> {
    let Some(scope) = caller.scope() else {
        return Ok(());
    };
    let owned: Option<(bool,)> = sqlx::query_as(
        "SELECT owner_token_id IS NOT DISTINCT FROM $2 FROM irl.agent_registry WHERE agent_id = $1",
    )
    .bind(agent_id)
    .bind(scope)
    .fetch_optional(pool)
    .await?;
    match owned {
        Some((true,)) => Ok(()),
        _ => Err(AppError::Policy(PolicyError::AgentNotFound)),
    }
}

/// Ok if `caller` may act on the trace's agent; TRACE_NOT_FOUND otherwise
/// (including traces with no agent, which are operator-only).
pub async fn ensure_trace(pool: &PgPool, caller: &Caller, trace_id: Uuid) -> Result<(), AppError> {
    let Some(scope) = caller.scope() else {
        return Ok(());
    };
    let owned: Option<(bool,)> = sqlx::query_as(
        r#"
        SELECT EXISTS (
            SELECT 1 FROM irl.agent_registry a
            WHERE a.agent_id = t.agent_id AND a.owner_token_id = $2
        )
        FROM irl.reasoning_traces t
        WHERE t.trace_id = $1
        LIMIT 1
        "#,
    )
    .bind(trace_id)
    .bind(scope)
    .fetch_optional(pool)
    .await?;
    match owned {
        Some((true,)) => Ok(()),
        _ => Err(AppError::TraceNotFound(trace_id.to_string())),
    }
}
