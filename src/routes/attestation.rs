use crate::attestation::{self, ProofBundle};
use crate::errors::AppError;
use crate::AppState;
use axum::{
    extract::{Query, State},
    Json,
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct AttestationQuery {
    /// Start of period, RFC 3339 (exclusive).
    pub from: DateTime<Utc>,
    /// End of period, RFC 3339 (inclusive).
    pub to: DateTime<Utc>,
    /// Optional: restrict traces to a single agent.
    pub agent_id: Option<Uuid>,
}

/// GET /irl/anchors — public Merkle anchor transparency feed.
///
/// No authentication: an anchor exposes only the period bounds, the leaf
/// count, the 32-byte Merkle root, and OTS status — nothing about trace
/// contents. Publishing roots is what makes the audit chain publicly
/// auditable: any party can match a proof bundle's anchors against this feed
/// and against the Bitcoin blockchain.
pub async fn list_anchors(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, AppError> {
    let pool = state.readonly_pool.as_ref().unwrap_or(&state.pool);

    type Row = (
        DateTime<Utc>,
        DateTime<Utc>,
        i32,
        String,
        bool,
        Option<DateTime<Utc>>,
        DateTime<Utc>,
    );
    let rows: Vec<Row> = sqlx::query_as(
        r#"
        SELECT period_start, period_end, leaf_count, merkle_root,
               (ots_receipt IS NOT NULL OR ots_complete_receipt IS NOT NULL) AS has_ots_receipt,
               ots_upgraded_at, created_at
        FROM irl.merkle_anchors
        ORDER BY period_end DESC
        LIMIT 100
        "#,
    )
    .fetch_all(pool)
    .await?;

    let anchors: Vec<serde_json::Value> = rows
        .into_iter()
        .map(
            |(start, end, leaves, root, has_receipt, upgraded_at, created_at)| {
                serde_json::json!({
                    "period_start": start,
                    "period_end": end,
                    "leaf_count": leaves,
                    "merkle_root": root,
                    "has_ots_receipt": has_receipt,
                    "ots_upgraded_at": upgraded_at,
                    "created_at": created_at,
                })
            },
        )
        .collect();

    Ok(Json(serde_json::json!({
        "count": anchors.len(),
        "anchors": anchors,
        "spec": "binary SHA-256 Merkle root over reasoning_hash leaves ordered by txn_time; \
                 roots committed to Bitcoin via OpenTimestamps",
    })))
}

/// GET /irl/attestation — proof bundle export.
///
/// Returns a self-contained evidence file: every trace in `(from, to]` plus
/// every overlapping Merkle anchor with its full leaf list and OTS receipt.
/// Verifiable fully offline with the `irl-verify` CLI — the verifying party
/// needs no access to this server and no trust in its operator.
///
/// Requires: Authorization: Bearer <token>
pub async fn get_attestation(
    State(state): State<AppState>,
    Query(q): Query<AttestationQuery>,
) -> Result<Json<ProofBundle>, AppError> {
    let pool = state.readonly_pool.as_ref().unwrap_or(&state.pool);
    let bundle = attestation::build_bundle(pool, q.from, q.to, q.agent_id).await?;
    Ok(Json(bundle))
}
