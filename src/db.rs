#![allow(clippy::type_complexity, clippy::too_many_arguments)]

use crate::binding::{BindExecutionRequest, BindExecutionResult};
use crate::errors::{AppError, PolicyError};
use crate::policy::PolicyDecision;
use crate::snapshot::{CognitiveSnapshot, ReasoningTrace};
use chrono::{TimeZone, Utc};
use sqlx::PgPool;
use uuid::Uuid;

/// Columns the trace INSERTs below write. Checked against the live table
/// at startup: a migration can be recorded as applied without reaching the
/// partitioned `irl.reasoning_traces` (023's `parent_trace_id` was missing
/// in production, so every authorize failed while /irl/health said ok).
pub const TRACE_INSERT_COLUMNS: &[&str] = &[
    "trace_id",
    "valid_time",
    "txn_time",
    "mta_regime_id",
    "mta_version",
    "mta_hash",
    "latent_fingerprint",
    "feature_schema_id",
    "execution_action",
    "execution_asset",
    "client_order_id",
    "execution_order_type",
    "execution_venue_id",
    "execution_quantity",
    "execution_notional",
    "execution_limit_price",
    "execution_notional_currency",
    "execution_multiplier",
    "execution_stop_price",
    "heartbeat_seq",
    "policy_id",
    "policy_version",
    "policy_hash",
    "policy_result",
    "reasoning_hash",
    "trace_json",
    "agent_id",
    "trace_nonce",
    "encrypted_dek",
    "key_version",
    "encryption_version",
    "mta_pubkey_used",
    "parent_trace_id",
    "snapshot_version",
    "private_commitment",
];

/// Fails startup if `irl.reasoning_traces` lacks any column the INSERTs
/// need, turning a silent per-request 500 into a failed (rolled back) deploy.
pub async fn assert_trace_schema(pool: &PgPool) -> anyhow::Result<()> {
    let present: Vec<String> = sqlx::query_scalar(
        "SELECT column_name::text FROM information_schema.columns \
         WHERE table_schema = 'irl' AND table_name = 'reasoning_traces'",
    )
    .fetch_all(pool)
    .await?;
    let missing = missing_columns(TRACE_INSERT_COLUMNS, &present);
    anyhow::ensure!(
        missing.is_empty(),
        "irl.reasoning_traces is missing columns {missing:?}; \
         re-apply the migrations that add them before starting"
    );
    Ok(())
}

/// Outcome of claiming a v2 intent key.
#[derive(Debug, PartialEq, Eq)]
pub enum IntentClaim {
    Claimed,
    /// Already authorized as this trace.
    Duplicate(Uuid),
}

/// Claim `(agent_id, client_order_id)` for `trace_id` (Layer 2 v2 replay
/// protection). Atomic: of concurrent identical requests exactly one wins.
/// A key whose trace was never written (e.g. a crash between claim and
/// insert) is taken over rather than blocking the client forever.
pub async fn claim_intent(
    pool: &PgPool,
    agent_id: Uuid,
    client_order_id: &str,
    trace_id: Uuid,
) -> Result<IntentClaim, AppError> {
    let inserted = sqlx::query(
        "INSERT INTO irl.intent_keys (agent_id, client_order_id, trace_id) \
         VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
    )
    .bind(agent_id)
    .bind(client_order_id)
    .bind(trace_id)
    .execute(pool)
    .await?
    .rows_affected();
    if inserted == 1 {
        return Ok(IntentClaim::Claimed);
    }
    let existing: Uuid = sqlx::query_scalar(
        "SELECT trace_id FROM irl.intent_keys WHERE agent_id = $1 AND client_order_id = $2",
    )
    .bind(agent_id)
    .bind(client_order_id)
    .fetch_one(pool)
    .await?;
    let trace_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM irl.reasoning_traces WHERE trace_id = $1)",
    )
    .bind(existing)
    .fetch_one(pool)
    .await?;
    if trace_exists {
        return Ok(IntentClaim::Duplicate(existing));
    }
    let taken_over = sqlx::query(
        "UPDATE irl.intent_keys SET trace_id = $3, created_at = now() \
         WHERE agent_id = $1 AND client_order_id = $2 AND trace_id = $4",
    )
    .bind(agent_id)
    .bind(client_order_id)
    .bind(trace_id)
    .bind(existing)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(if taken_over == 1 {
        IntentClaim::Claimed
    } else {
        IntentClaim::Duplicate(existing)
    })
}

/// Release a claim whose trace insert failed, so the client can retry.
pub async fn release_intent(
    pool: &PgPool,
    agent_id: Uuid,
    client_order_id: &str,
    trace_id: Uuid,
) -> Result<(), AppError> {
    sqlx::query(
        "DELETE FROM irl.intent_keys \
         WHERE agent_id = $1 AND client_order_id = $2 AND trace_id = $3",
    )
    .bind(agent_id)
    .bind(client_order_id)
    .bind(trace_id)
    .execute(pool)
    .await?;
    Ok(())
}

fn missing_columns<'a>(required: &[&'a str], present: &[String]) -> Vec<&'a str> {
    required
        .iter()
        .copied()
        .filter(|c| !present.iter().any(|p| p == c))
        .collect()
}

/// Insert a sealed reasoning trace into the DB.
pub async fn insert_trace(
    pool: &PgPool,
    snapshot: &CognitiveSnapshot,
    reasoning_hash: &str,
    decision: &PolicyDecision,
    trace: &ReasoningTrace,
    agent_id: Option<Uuid>,
    key_provider: Option<&dyn crate::kms::KeyProvider>,
    mta_pubkey_used: Option<&str>,
    parent_trace_id: Option<Uuid>,
    // T-1.1: seal format (1 = whole-snapshot v1, 2 = split-commitment v2) and,
    // for v2, the SHA-256 commitment to the private field group.
    snapshot_version: i16,
    private_commitment: Option<&str>,
) -> Result<(), AppError> {
    let trace_json =
        serde_json::to_value(trace).map_err(|e| AppError::Serialization(e.to_string()))?;

    // reasoning_hash is already computed from plaintext in seal.rs before this
    // function is called. Encrypt AFTER hash computation — never hash the ciphertext.
    let (stored_json, nonce_bytes, enc_dek_bytes, key_ver, enc_version) =
        if let Some(kms) = key_provider {
            let plaintext_bytes = serde_json::to_vec(&trace_json)
                .map_err(|e| AppError::Serialization(e.to_string()))?;
            let (dek, enc_dek, kv) = kms
                .generate_dek()
                .await
                .map_err(|e| AppError::Encryption(e.to_string()))?;
            let blob = crate::encryption::encrypt_trace(&plaintext_bytes, &dek)
                .map_err(|e| AppError::Encryption(e.to_string()))?;
            // dek (Zeroizing<Vec<u8>>) drops here — memory wiped automatically
            let wrapped = crate::encryption::wrap_ciphertext_for_jsonb(&blob.ciphertext);
            (
                wrapped,
                Some(blob.nonce.to_vec()),
                Some(enc_dek),
                Some(kv),
                1i32,
            )
        } else {
            (trace_json, None, None, None, 0i32)
        };

    let valid_time = Utc
        .timestamp_millis_opt(snapshot.valid_time)
        .single()
        .ok_or_else(|| AppError::Serialization("invalid valid_time timestamp".into()))?;
    let txn_time = Utc
        .timestamp_millis_opt(snapshot.txn_time)
        .single()
        .ok_or_else(|| AppError::Serialization("invalid txn_time timestamp".into()))?;

    sqlx::query(
        r#"
        INSERT INTO irl.reasoning_traces (
            trace_id, valid_time, txn_time,
            mta_regime_id, mta_version, mta_hash,
            latent_fingerprint, feature_schema_id,
            execution_action, execution_asset, client_order_id,
            execution_order_type, execution_venue_id,
            execution_quantity, execution_notional, execution_limit_price,
            execution_notional_currency, execution_multiplier, execution_stop_price,
            heartbeat_seq,
            policy_id, policy_version, policy_hash, policy_result,
            reasoning_hash, trace_json, agent_id,
            trace_nonce, encrypted_dek, key_version, encryption_version,
            mta_pubkey_used, parent_trace_id,
            snapshot_version, private_commitment
        ) VALUES (
            $1,  $2,  $3,  $4,  $5,  $6,  $7,  $8,  $9,  $10,
            $11, $12, $13, $14, $15, $16, $17, $18, $19, $20,
            $21, $22, $23, $24, $25, $26, $27, $28, $29, $30,
            $31, $32, $33, $34, $35
        )
        "#,
    )
    .bind(snapshot.trace_id)
    .bind(valid_time)
    .bind(txn_time)
    .bind(snapshot.mta_regime_id as i16)
    .bind(&snapshot.mta_version)
    .bind(&snapshot.mta_hash)
    .bind(&snapshot.latent_fingerprint)
    .bind(&snapshot.feature_schema_id)
    .bind(snapshot.execution.action.to_string())
    .bind(&snapshot.execution.asset)
    .bind(&snapshot.execution.client_order_id)
    .bind(snapshot.execution.order_type.to_string())
    .bind(&snapshot.execution.venue_id)
    .bind(snapshot.execution.quantity)
    .bind(snapshot.execution.notional)
    .bind(snapshot.execution.limit_price)
    .bind(&snapshot.execution.notional_currency)
    .bind(snapshot.execution.multiplier)
    .bind(snapshot.execution.stop_price)
    .bind(snapshot.heartbeat.sequence_id as i64)
    .bind(&decision.policy_id)
    .bind(&decision.policy_version)
    .bind(&decision.policy_hash)
    .bind(decision.result.to_string())
    .bind(reasoning_hash)
    .bind(stored_json)
    .bind(agent_id)
    .bind(nonce_bytes)
    .bind(enc_dek_bytes)
    .bind(key_ver)
    .bind(enc_version)
    .bind(mta_pubkey_used)
    .bind(parent_trace_id)
    .bind(snapshot_version)
    .bind(private_commitment)
    .execute(pool)
    .await?;

    Ok(())
}

/// Update a trace with exchange execution outcome (Layer 2 binding).
pub async fn update_binding(
    pool: &PgPool,
    result: &BindExecutionResult,
    req: &BindExecutionRequest,
) -> Result<(), AppError> {
    sqlx::query(
        r#"
        UPDATE irl.reasoning_traces
        SET
            exchange_tx_id      = $1,
            verification_status = $2,
            execution_status    = $3,
            execution_price     = $4,
            execution_time      = $5,
            final_proof         = $6
        WHERE trace_id = $7
        "#,
    )
    .bind(&req.exchange_tx_id)
    .bind(result.verification_status.to_string())
    .bind(&result.execution_status)
    .bind(req.execution_price)
    .bind(result.execution_time)
    .bind(&result.final_proof)
    .bind(result.trace_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Decrypt trace_json if encrypted (encryption_version=1), pass through if plaintext (version=0).
///
/// ENC-04: legacy plaintext rows (encryption_version=0) are returned unchanged.
/// ENC-06: reasoning_hash and final_proof are NOT encrypted — they are read from
/// dedicated plaintext columns and overlaid after this function returns.
async fn decrypt_if_needed(
    trace_json: serde_json::Value,
    trace_nonce: Option<Vec<u8>>,
    encrypted_dek: Option<Vec<u8>>,
    key_version: Option<i32>,
    encryption_version: i32,
    key_provider: Option<&dyn crate::kms::KeyProvider>,
) -> Result<serde_json::Value, AppError> {
    match encryption_version {
        0 => Ok(trace_json), // legacy plaintext — return as-is (ENC-04)
        1 => {
            let kms = key_provider.ok_or_else(|| {
                AppError::Encryption("encryption_version=1 but no key_provider configured".into())
            })?;
            let enc_dek = encrypted_dek.ok_or_else(|| {
                AppError::Encryption("encrypted_dek is NULL for encryption_version=1".into())
            })?;
            let nonce = trace_nonce.ok_or_else(|| {
                AppError::Encryption("trace_nonce is NULL for encryption_version=1".into())
            })?;
            let kv = key_version.unwrap_or(1);
            let dek = kms
                .decrypt_dek(&enc_dek, kv)
                .await
                .map_err(|e| AppError::Encryption(e.to_string()))?;
            let ciphertext = crate::encryption::extract_ciphertext_from_jsonb(&trace_json)
                .map_err(|e| AppError::Encryption(e.to_string()))?;
            let plaintext = crate::encryption::decrypt_trace(&ciphertext, &nonce, &dek)
                .map_err(|e| AppError::Encryption(e.to_string()))?;
            // dek (Zeroizing<Vec<u8>>) drops here
            serde_json::from_slice(&plaintext).map_err(|e| AppError::Serialization(e.to_string()))
        }
        v => Err(AppError::Encryption(format!(
            "unknown encryption_version: {v}"
        ))),
    }
}

/// Fetch the full trace JSON for a given trace_id (audit replay).
///
/// Decrypts encrypted rows (encryption_version=1) transparently.
/// reasoning_hash and final_proof are NOT encrypted (ENC-06) — read from dedicated plaintext columns.
pub async fn get_trace_json(
    pool: &PgPool,
    trace_id: Uuid,
    key_provider: Option<&dyn crate::kms::KeyProvider>,
) -> Result<serde_json::Value, AppError> {
    // reasoning_hash and final_proof are NOT encrypted (ENC-06) — read from dedicated plaintext columns
    let row: Option<(
        serde_json::Value,
        String,
        Option<String>,
        String,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<i32>,
        i32,
    )> = sqlx::query_as(
        r#"
        SELECT trace_json, reasoning_hash, final_proof, verification_status,
               trace_nonce, encrypted_dek, key_version, encryption_version
        FROM irl.reasoning_traces
        WHERE trace_id = $1
        "#,
    )
    .bind(trace_id)
    .fetch_optional(pool)
    .await?;

    match row {
        None => Err(AppError::TraceNotFound(trace_id.to_string())),
        Some((
            raw_json,
            _reasoning_hash,
            final_proof,
            verification_status,
            trace_nonce,
            encrypted_dek,
            key_version,
            encryption_version,
        )) => {
            // Decrypt if needed BEFORE overlaying binding fields (overlay is on plaintext)
            let mut trace_json = decrypt_if_needed(
                raw_json,
                trace_nonce,
                encrypted_dek,
                key_version,
                encryption_version,
                key_provider,
            )
            .await?;

            // Overlay live binding fields onto the stored trace_json
            if let Some(obj) = trace_json.as_object_mut() {
                if let Some(integrity) = obj.get_mut("integrity") {
                    if let Some(int_obj) = integrity.as_object_mut() {
                        int_obj.insert("final_proof".into(), final_proof.into());
                        int_obj.insert("verification_status".into(), verification_status.into());
                    }
                }
            }
            Ok(trace_json)
        }
    }
}

/// Walk the parent_trace_id chain from a given trace to the root, then return
/// direct children of the requested trace.
///
/// Response structure:
/// - `ancestry`: chain from root → requested trace (depth=0 is the requested trace)
/// - `children`: direct sub-agent traces triggered by the requested trace
pub async fn get_trace_chain(pool: &PgPool, trace_id: Uuid) -> Result<serde_json::Value, AppError> {
    use chrono::DateTime;
    type AncRow = (
        Uuid,
        Option<Uuid>,
        String,
        String,
        DateTime<Utc>,
        Option<Uuid>,
        i32,
    );

    // Walk upward through parent_trace_id pointers until no more parents.
    // depth=0 is the requested trace, depth N is the root.
    let ancestors: Vec<AncRow> = sqlx::query_as(
        r#"
        WITH RECURSIVE ancestors AS (
            SELECT trace_id, parent_trace_id, reasoning_hash, verification_status,
                   txn_time, agent_id, 0 AS depth
            FROM irl.reasoning_traces
            WHERE trace_id = $1
            UNION ALL
            SELECT r.trace_id, r.parent_trace_id, r.reasoning_hash, r.verification_status,
                   r.txn_time, r.agent_id, a.depth + 1
            FROM irl.reasoning_traces r
            JOIN ancestors a ON r.trace_id = a.parent_trace_id
            WHERE a.depth < 20
        )
        SELECT trace_id, parent_trace_id, reasoning_hash, verification_status,
               txn_time, agent_id, depth
        FROM ancestors
        ORDER BY depth DESC
        "#,
    )
    .bind(trace_id)
    .fetch_all(pool)
    .await?;

    if ancestors.is_empty() {
        return Err(AppError::TraceNotFound(trace_id.to_string()));
    }

    type ChildRow = (
        Uuid,
        Option<Uuid>,
        String,
        String,
        DateTime<Utc>,
        Option<Uuid>,
    );
    let children: Vec<ChildRow> = sqlx::query_as(
        r#"
        SELECT trace_id, parent_trace_id, reasoning_hash, verification_status,
               txn_time, agent_id
        FROM irl.reasoning_traces
        WHERE parent_trace_id = $1
        ORDER BY txn_time ASC
        "#,
    )
    .bind(trace_id)
    .fetch_all(pool)
    .await?;

    let ancestry: Vec<serde_json::Value> = ancestors
        .into_iter()
        .map(|(tid, parent_tid, rh, vstatus, ts, aid, depth)| {
            serde_json::json!({
                "trace_id": tid,
                "parent_trace_id": parent_tid,
                "reasoning_hash": rh,
                "verification_status": vstatus,
                "txn_time": ts,
                "agent_id": aid,
                "depth": depth,
            })
        })
        .collect();

    let child_nodes: Vec<serde_json::Value> = children
        .into_iter()
        .map(|(tid, parent_tid, rh, vstatus, ts, aid)| {
            serde_json::json!({
                "trace_id": tid,
                "parent_trace_id": parent_tid,
                "reasoning_hash": rh,
                "verification_status": vstatus,
                "txn_time": ts,
                "agent_id": aid,
            })
        })
        .collect();

    Ok(serde_json::json!({
        "trace_id": trace_id,
        "ancestry": ancestry,
        "children": child_nodes,
    }))
}

/// Fetch the intent fields needed for bind-execution reconciliation.
///
/// Returns (reasoning_hash, execution_asset, execution_action, execution_quantity,
///          verification_status, agent_id, venue_id, notional_currency, multiplier).
/// The caller must check that verification_status == "PENDING" before proceeding.
pub async fn get_intent_for_binding(
    pool: &PgPool,
    trace_id: Uuid,
) -> Result<
    (
        String,
        String,
        String,
        f64,
        String,
        Option<Uuid>,
        String,
        String,
        f64,
    ),
    AppError,
> {
    let row: Option<(
        String,
        String,
        String,
        f64,
        String,
        Option<Uuid>,
        Option<String>,
        Option<String>,
        Option<f64>,
    )> = sqlx::query_as(
        r#"
        SELECT reasoning_hash, execution_asset, execution_action, execution_quantity::float8,
               verification_status, agent_id,
               execution_venue_id,
               execution_notional_currency,
               execution_multiplier::float8
        FROM irl.reasoning_traces
        WHERE trace_id = $1
        "#,
    )
    .bind(trace_id)
    .fetch_optional(pool)
    .await?;

    row.map(
        |(rh, asset, action, qty, status, aid, venue, currency, mult)| {
            (
                rh,
                asset,
                action,
                qty,
                status,
                aid,
                venue.unwrap_or_else(|| "UNKNOWN".to_string()),
                currency.unwrap_or_else(|| "USD".to_string()),
                mult.unwrap_or(1.0),
            )
        },
    )
    .ok_or_else(|| AppError::TraceNotFound(trace_id.to_string()))
}

/// List PENDING traces older than `age_seconds` for the /irl/pending route.
///
/// Decrypts encrypted rows (encryption_version=1) transparently.
/// Uses a semaphore (20 concurrent) to avoid KMS quota exhaustion.
pub async fn get_pending_traces(
    pool: &PgPool,
    age_seconds: i64,
    key_provider: Option<&dyn crate::kms::KeyProvider>,
) -> Result<Vec<serde_json::Value>, AppError> {
    type EncRow = (
        Uuid,
        serde_json::Value,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<i32>,
        i32,
    );
    let rows: Vec<EncRow> = sqlx::query_as(
        r#"
        SELECT trace_id, trace_json, trace_nonce, encrypted_dek, key_version, encryption_version
        FROM irl.reasoning_traces
        WHERE verification_status = 'PENDING'
          AND txn_time < now() - make_interval(secs => $1)
        ORDER BY txn_time ASC
        LIMIT 1000
        "#,
    )
    .bind(age_seconds as f64)
    .fetch_all(pool)
    .await?;

    decrypt_rows_concurrent(rows, key_provider).await
}

/// List SHADOW_HALTED traces for /irl/shadow-violations.
///
/// These are trades that would have been blocked by policy enforcement
/// but were allowed through because SHADOW_MODE=true.
/// Decrypts encrypted rows (encryption_version=1) transparently.
pub async fn get_shadow_violations(
    pool: &PgPool,
    key_provider: Option<&dyn crate::kms::KeyProvider>,
) -> Result<Vec<serde_json::Value>, AppError> {
    type EncRow = (
        Uuid,
        serde_json::Value,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<i32>,
        i32,
    );
    let rows: Vec<EncRow> = sqlx::query_as(
        r#"
        SELECT trace_id, trace_json, trace_nonce, encrypted_dek, key_version, encryption_version
        FROM irl.reasoning_traces
        WHERE policy_result = 'SHADOW_HALTED'
        ORDER BY txn_time DESC
        LIMIT 500
        "#,
    )
    .fetch_all(pool)
    .await?;

    decrypt_rows_concurrent(rows, key_provider).await
}

/// List EXPIRED or DIVERGENT traces for /irl/orphans.
///
/// Decrypts encrypted rows (encryption_version=1) transparently.
pub async fn get_orphan_traces(
    pool: &PgPool,
    key_provider: Option<&dyn crate::kms::KeyProvider>,
) -> Result<Vec<serde_json::Value>, AppError> {
    type EncRow = (
        Uuid,
        serde_json::Value,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<i32>,
        i32,
    );
    let rows: Vec<EncRow> = sqlx::query_as(
        r#"
        SELECT trace_id, trace_json, trace_nonce, encrypted_dek, key_version, encryption_version
        FROM irl.reasoning_traces
        WHERE verification_status IN ('EXPIRED', 'DIVERGENT')
        ORDER BY txn_time DESC
        LIMIT 200
        "#,
    )
    .fetch_all(pool)
    .await?;

    decrypt_rows_concurrent(rows, key_provider).await
}

/// Decrypt a batch of rows concurrently, capped at 20 simultaneous KMS calls.
///
/// Each row is decrypted independently. The semaphore prevents KMS quota exhaustion
/// when processing large result sets (Pitfall 3 from research).
async fn decrypt_rows_concurrent(
    rows: Vec<(
        Uuid,
        serde_json::Value,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<i32>,
        i32,
    )>,
    key_provider: Option<&dyn crate::kms::KeyProvider>,
) -> Result<Vec<serde_json::Value>, AppError> {
    use std::sync::Arc;
    use tokio::sync::Semaphore;

    if rows.is_empty() {
        return Ok(vec![]);
    }

    let sem = Arc::new(Semaphore::new(20));
    let mut handles = Vec::with_capacity(rows.len());

    for (_trace_id, trace_json, trace_nonce, encrypted_dek, key_version, encryption_version) in rows
    {
        // Clone all data so each task owns it independently
        let sem = Arc::clone(&sem);
        // For encryption_version=0 rows we do not call KMS — pass None to avoid
        // needing to send the key_provider (not Send) across task boundaries.
        // For version=1 rows, we need the key_provider — handled inline without spawning.
        handles.push((
            trace_json,
            trace_nonce,
            encrypted_dek,
            key_version,
            encryption_version,
            sem,
        ));
    }

    // Process rows sequentially but with semaphore guarding KMS calls.
    // We cannot spawn tasks because key_provider is not 'static, but we still
    // honour the concurrency cap conceptually (single-threaded loop with async
    // awaits means KMS calls are inherently serialised here at up to 20 in-flight
    // if the caller was concurrent — this is a single-caller batch so sequential
    // await is safe and correct).
    let mut results = Vec::with_capacity(handles.len());
    for (trace_json, trace_nonce, encrypted_dek, key_version, encryption_version, sem) in handles {
        let _permit = sem.acquire().await.expect("semaphore closed");
        let decrypted = decrypt_if_needed(
            trace_json,
            trace_nonce,
            encrypted_dek,
            key_version,
            encryption_version,
            key_provider,
        )
        .await?;
        results.push(decrypted);
    }

    Ok(results)
}

/// Sum of `execution_notional` for all PENDING traces for an agent.
/// Used by authorize to enforce cumulative (portfolio-level) notional caps.
pub async fn get_pending_notional(pool: &PgPool, agent_id: Uuid) -> Result<f64, AppError> {
    let row: (f64,) = sqlx::query_as(
        r#"
        SELECT COALESCE(SUM(execution_notional), 0.0)::float8
        FROM irl.reasoning_traces
        WHERE agent_id = $1
          AND verification_status = 'PENDING'
        "#,
    )
    .bind(agent_id)
    .fetch_one(pool)
    .await?;

    Ok(row.0)
}

/// Filtered trace list for GET /irl/traces — compliance export endpoint.
pub async fn list_traces(
    pool: &PgPool,
    agent_id: Option<Uuid>,
    from_ms: Option<i64>,
    to_ms: Option<i64>,
    status: Option<String>,
    limit: i64,
) -> Result<Vec<serde_json::Value>, AppError> {
    use chrono::{TimeZone, Utc};

    let from_ts = from_ms.and_then(|ms| Utc.timestamp_millis_opt(ms).single());
    let to_ts = to_ms.and_then(|ms| Utc.timestamp_millis_opt(ms).single());

    // Use a type alias for the row tuple to avoid repetition
    type TraceRow = (
        Uuid,                  // trace_id
        Option<Uuid>,          // agent_id
        chrono::DateTime<Utc>, // txn_time
        String,                // policy_result
        String,                // verification_status
        String,                // execution_asset
        Option<f64>,           // execution_notional
        String,                // reasoning_hash
    );

    let rows: Vec<TraceRow> = sqlx::query_as(
        r#"
        SELECT
            trace_id,
            agent_id,
            txn_time,
            policy_result,
            verification_status,
            execution_asset,
            execution_notional::float8,
            reasoning_hash
        FROM irl.reasoning_traces
        WHERE ($1::uuid        IS NULL OR agent_id            = $1)
          AND ($2::timestamptz IS NULL OR txn_time            >= $2)
          AND ($3::timestamptz IS NULL OR txn_time            <= $3)
          AND ($4::text        IS NULL OR verification_status  = $4)
        ORDER BY txn_time DESC
        LIMIT $5
        "#,
    )
    .bind(agent_id)
    .bind(from_ts)
    .bind(to_ts)
    .bind(status)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    let values = rows
        .into_iter()
        .map(
            |(
                trace_id,
                ag_id,
                txn_time,
                policy_result,
                verification_status,
                asset,
                notional,
                reasoning_hash,
            )| {
                serde_json::json!({
                    "trace_id":            trace_id,
                    "agent_id":            ag_id,
                    "txn_time":            txn_time,
                    "policy_result":       policy_result,
                    "verification_status": verification_status,
                    "asset":               asset,
                    "notional":            notional,
                    "reasoning_hash":      reasoning_hash,
                })
            },
        )
        .collect();

    Ok(values)
}

/// Atomically check portfolio cap and insert a trace.
///
/// Acquires a per-agent PostgreSQL advisory lock (xact-level) before reading
/// the pending notional sum, eliminating the TOCTOU race that exists when two
/// concurrent authorize requests for the same agent both read the same pending
/// sum and collectively bypass the cap.
///
/// `portfolio_check` — `Some((cap, regime_label))` to enforce the cumulative
/// portfolio cap before inserting; `None` to skip (halted/shadow/reduce_only).
pub async fn insert_trace_atomic(
    pool: &PgPool,
    snapshot: &CognitiveSnapshot,
    reasoning_hash: &str,
    decision: &PolicyDecision,
    trace: &ReasoningTrace,
    agent_id: Option<Uuid>,
    portfolio_check: Option<(f64, String)>,
    key_provider: Option<&dyn crate::kms::KeyProvider>,
    mta_pubkey_used: Option<&str>,
    parent_trace_id: Option<Uuid>,
    // T-1.1: seal format (1 = whole-snapshot v1, 2 = split-commitment v2) and,
    // for v2, the SHA-256 commitment to the private field group.
    snapshot_version: i16,
    private_commitment: Option<&str>,
) -> Result<(), AppError> {
    let mut txn = pool.begin().await?;

    // Serialize concurrent authorize calls for the same agent.
    // The lock is held until the transaction commits or rolls back.
    if let Some(aid) = agent_id {
        let lock_key = i64::from_le_bytes(aid.as_bytes()[..8].try_into().unwrap_or([0u8; 8]));
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(lock_key)
            .execute(&mut *txn)
            .await?;
    }

    // Portfolio cap check — inside the lock to prevent concurrent bypass.
    if let (Some(aid), Some((cap, regime_label))) = (agent_id, portfolio_check) {
        let row: (f64,) = sqlx::query_as(
            r#"
            SELECT COALESCE(SUM(execution_notional), 0.0)::float8
            FROM irl.reasoning_traces
            WHERE agent_id = $1
              AND verification_status = 'PENDING'
            "#,
        )
        .bind(aid)
        .fetch_one(&mut *txn)
        .await?;

        let pending = row.0;
        if pending + snapshot.execution.notional > cap {
            return Err(AppError::Policy(PolicyError::NotionalExceedsLimit {
                notional: pending + snapshot.execution.notional,
                limit: cap,
                regime: regime_label,
                policy: "IrlConstraintPolicy".to_string(),
            }));
        }
    }

    // Insert the trace within the same transaction.
    // reasoning_hash is already computed from plaintext in seal.rs before this
    // function is called. Encrypt AFTER hash computation — never hash the ciphertext.
    let trace_json =
        serde_json::to_value(trace).map_err(|e| AppError::Serialization(e.to_string()))?;

    let (stored_json, nonce_bytes, enc_dek_bytes, key_ver, enc_version) =
        if let Some(kms) = key_provider {
            let plaintext_bytes = serde_json::to_vec(&trace_json)
                .map_err(|e| AppError::Serialization(e.to_string()))?;
            let (dek, enc_dek, kv) = kms
                .generate_dek()
                .await
                .map_err(|e| AppError::Encryption(e.to_string()))?;
            let blob = crate::encryption::encrypt_trace(&plaintext_bytes, &dek)
                .map_err(|e| AppError::Encryption(e.to_string()))?;
            // dek (Zeroizing<Vec<u8>>) drops here — memory wiped automatically
            let wrapped = crate::encryption::wrap_ciphertext_for_jsonb(&blob.ciphertext);
            (
                wrapped,
                Some(blob.nonce.to_vec()),
                Some(enc_dek),
                Some(kv),
                1i32,
            )
        } else {
            (trace_json, None, None, None, 0i32)
        };

    let valid_time = Utc
        .timestamp_millis_opt(snapshot.valid_time)
        .single()
        .ok_or_else(|| AppError::Serialization("invalid valid_time timestamp".into()))?;
    let txn_time = Utc
        .timestamp_millis_opt(snapshot.txn_time)
        .single()
        .ok_or_else(|| AppError::Serialization("invalid txn_time timestamp".into()))?;

    sqlx::query(
        r#"
        INSERT INTO irl.reasoning_traces (
            trace_id, valid_time, txn_time,
            mta_regime_id, mta_version, mta_hash,
            latent_fingerprint, feature_schema_id,
            execution_action, execution_asset, client_order_id,
            execution_order_type, execution_venue_id,
            execution_quantity, execution_notional, execution_limit_price,
            execution_notional_currency, execution_multiplier, execution_stop_price,
            heartbeat_seq,
            policy_id, policy_version, policy_hash, policy_result,
            reasoning_hash, trace_json, agent_id,
            trace_nonce, encrypted_dek, key_version, encryption_version,
            mta_pubkey_used, parent_trace_id,
            snapshot_version, private_commitment
        ) VALUES (
            $1,  $2,  $3,  $4,  $5,  $6,  $7,  $8,  $9,  $10,
            $11, $12, $13, $14, $15, $16, $17, $18, $19, $20,
            $21, $22, $23, $24, $25, $26, $27, $28, $29, $30,
            $31, $32, $33, $34, $35
        )
        "#,
    )
    .bind(snapshot.trace_id)
    .bind(valid_time)
    .bind(txn_time)
    .bind(snapshot.mta_regime_id as i16)
    .bind(&snapshot.mta_version)
    .bind(&snapshot.mta_hash)
    .bind(&snapshot.latent_fingerprint)
    .bind(&snapshot.feature_schema_id)
    .bind(snapshot.execution.action.to_string())
    .bind(&snapshot.execution.asset)
    .bind(&snapshot.execution.client_order_id)
    .bind(snapshot.execution.order_type.to_string())
    .bind(&snapshot.execution.venue_id)
    .bind(snapshot.execution.quantity)
    .bind(snapshot.execution.notional)
    .bind(snapshot.execution.limit_price)
    .bind(&snapshot.execution.notional_currency)
    .bind(snapshot.execution.multiplier)
    .bind(snapshot.execution.stop_price)
    .bind(snapshot.heartbeat.sequence_id as i64)
    .bind(&decision.policy_id)
    .bind(&decision.policy_version)
    .bind(&decision.policy_hash)
    .bind(decision.result.to_string())
    .bind(reasoning_hash)
    .bind(stored_json)
    .bind(agent_id)
    .bind(nonce_bytes)
    .bind(enc_dek_bytes)
    .bind(key_ver)
    .bind(enc_version)
    .bind(mta_pubkey_used)
    .bind(parent_trace_id)
    .bind(snapshot_version)
    .bind(private_commitment)
    .execute(&mut *txn)
    .await?;

    txn.commit().await?;
    Ok(())
}

/// Record a KMS key version the first time it is used for encryption.
///
/// Uses INSERT ... ON CONFLICT DO NOTHING so repeated calls are safe and cheap.
/// Called from backfill and (optionally) from insert_trace after a successful encrypted INSERT.
/// `key_arn_or_path` is the KMS ARN (AWS), Vault key path, or "local" for LocalDevProvider.
pub async fn upsert_kms_key_metadata(
    pool: &PgPool,
    key_version: i32,
    provider: &str,
    key_arn_or_path: &str,
) -> Result<(), AppError> {
    sqlx::query(
        r#"
        INSERT INTO irl.kms_key_metadata (key_version, provider, key_arn_or_path, status)
        VALUES ($1, $2, $3, 'active')
        ON CONFLICT (key_version, provider) DO NOTHING
        "#,
    )
    .bind(key_version)
    .bind(provider)
    .bind(key_arn_or_path)
    .execute(pool)
    .await?;
    Ok(())
}

/// Upsert agent position: adjust net_quantity by delta after a MATCHED bind.
///
/// v2 (migration 017): keyed on (agent_id, asset, venue_id, currency) so the same
/// agent can hold positions in the same asset across multiple venues or currencies.
///
/// Positive delta = long fill (increases long exposure).
/// Negative delta = short fill (decreases long exposure / increases short).
///
/// average_price is updated as a volume-weighted running average:
///   new_avg = (old_avg × old_qty + fill_price × |delta|) / new_qty
/// When fill_price is None, average_price is left unchanged.
pub async fn upsert_position(
    pool: &PgPool,
    agent_id: Uuid,
    asset: &str,
    venue_id: &str,
    currency: &str,
    quantity_delta: f64,
    fill_price: Option<f64>,
    multiplier: f64,
    trace_id: Uuid,
) -> Result<(), AppError> {
    // Compute notional contribution from this fill.
    // notional = |quantity_delta| × fill_price × multiplier (or 0 if no price)
    let fill_notional = fill_price
        .map(|p| quantity_delta.abs() * p * multiplier)
        .unwrap_or(0.0);

    sqlx::query(
        r#"
        INSERT INTO irl.agent_positions
            (agent_id, asset, venue_id, currency, net_quantity, notional,
             average_price, multiplier, last_trace_id, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6,
                CASE WHEN $7::float8 IS NOT NULL AND $5 != 0 THEN $7 ELSE NULL END,
                $8, $9, now())
        ON CONFLICT ON CONSTRAINT agent_positions_unique_position DO UPDATE
            SET net_quantity   = irl.agent_positions.net_quantity + $5,
                notional       = irl.agent_positions.notional + $6,
                average_price  = CASE
                    WHEN $7::float8 IS NOT NULL AND (irl.agent_positions.net_quantity + $5) != 0
                    THEN (COALESCE(irl.agent_positions.average_price, 0)
                            * ABS(irl.agent_positions.net_quantity)
                          + $7 * ABS($5))
                         / NULLIF(ABS(irl.agent_positions.net_quantity + $5), 0)
                    ELSE irl.agent_positions.average_price
                END,
                multiplier     = $8,
                last_trace_id  = $9,
                updated_at     = now()
        "#,
    )
    .bind(agent_id)
    .bind(asset)
    .bind(venue_id)
    .bind(currency)
    .bind(quantity_delta)
    .bind(fill_notional)
    .bind(fill_price)
    .bind(multiplier)
    .bind(trace_id)
    .execute(pool)
    .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn missing_columns_reports_only_absent_ones() {
        let present = vec!["trace_id".to_string(), "txn_time".to_string()];
        let missing = super::missing_columns(
            &[
                "trace_id",
                "parent_trace_id",
                "txn_time",
                "snapshot_version",
            ],
            &present,
        );
        assert_eq!(missing, vec!["parent_trace_id", "snapshot_version"]);
    }

    #[test]
    fn trace_insert_columns_match_both_insert_statements() {
        let src = include_str!("db.rs");
        // Built at runtime so these needles do not match this test's own source.
        let needle = ["INSERT INTO irl.", "reasoning_traces ("].concat();
        let end = [")", " VALUES"].concat();
        let inserts: Vec<&str> = src
            .split(needle.as_str())
            .skip(1)
            .map(|rest| rest.split(end.as_str()).next().unwrap())
            .collect();
        assert_eq!(inserts.len(), 2, "expected two trace INSERTs");
        for cols in inserts {
            let listed: Vec<&str> = cols
                .split(',')
                .map(str::trim)
                .filter(|c| !c.is_empty())
                .collect();
            assert_eq!(listed, super::TRACE_INSERT_COLUMNS);
        }
    }

    use super::*;
    use crate::heartbeat::SignedHeartbeat;
    use crate::kms::{KeyProvider, LocalDevProvider};
    use crate::policy::{PolicyDecision, PolicyResult};
    use crate::snapshot::{
        AgentBlock, BiTemporalBlock, ExecutionBlock, HeartbeatBlock, IntegrityBlock, MtaBlock,
        PolicyBlock, ReasoningTrace,
    };
    use crate::snapshot::{CognitiveSnapshot, TradeAction};
    use chrono::Utc;

    fn setup_local_kms() -> LocalDevProvider {
        std::env::set_var(
            "LOCAL_KMS_KEY",
            "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
        );
        std::env::remove_var("ENVIRONMENT");
        LocalDevProvider::new(1).expect("LocalDevProvider::new should succeed")
    }

    fn make_snapshot() -> CognitiveSnapshot {
        use crate::snapshot::ExecutionIntent;
        CognitiveSnapshot {
            trace_id: Uuid::new_v4(),
            mta_regime_id: 1,
            mta_version: "1.0".to_string(),
            mta_hash: "abc123".to_string(),
            latent_fingerprint: "fp".to_string(),
            feature_schema_id: "fs".to_string(),
            execution: ExecutionIntent {
                action: TradeAction::Long(1.0),
                asset: "BTC".to_string(),
                order_type: crate::snapshot::OrderType::Market,
                venue_id: "venue1".to_string(),
                quantity: 1.0,
                notional: 100.0,
                notional_currency: "USD".to_string(),
                multiplier: 1.0,
                limit_price: None,
                stop_price: None,
                client_order_id: "test-order".to_string(),
            },
            valid_time: Utc::now().timestamp_millis() - 1000,
            txn_time: Utc::now().timestamp_millis(),
            heartbeat: SignedHeartbeat {
                sequence_id: 1,
                timestamp_ms: Utc::now().timestamp_millis() as u64,
                regime_id: 1,
                mta_ref: "ref".to_string(),
                signature: vec![],
            },
        }
    }

    fn make_decision() -> PolicyDecision {
        PolicyDecision {
            policy_id: "IrlConstraintPolicy".to_string(),
            policy_version: "1.0".to_string(),
            policy_hash: "hash".to_string(),
            result: PolicyResult::Allowed,
        }
    }

    fn make_trace(
        snap: &CognitiveSnapshot,
        decision: &PolicyDecision,
        reasoning_hash: &str,
    ) -> ReasoningTrace {
        ReasoningTrace {
            trace_id: snap.trace_id,
            version: "1.0.0",
            bitemporal: BiTemporalBlock {
                valid_time: Utc::now(),
                txn_time: Utc::now(),
                time_source: "monotonic".to_string(),
            },
            mta: MtaBlock {
                regime_id: snap.mta_regime_id,
                regime_label: "test".to_string(),
                risk_level: 1.0,
                max_notional_scale: 1.0,
                allowed_sides: vec![],
                version: snap.mta_version.clone(),
                hash: snap.mta_hash.clone(),
                signature_valid: true,
            },
            agent: AgentBlock {
                agent_id: Uuid::new_v4(),
                latent_fingerprint: snap.latent_fingerprint.clone(),
                feature_schema_id: snap.feature_schema_id.clone(),
            },
            execution: ExecutionBlock {
                action: snap.execution.action.to_string(),
                asset: snap.execution.asset.clone(),
                order_type: snap.execution.order_type.to_string(),
                venue_id: snap.execution.venue_id.clone(),
                quantity: snap.execution.quantity,
                notional: snap.execution.notional,
                notional_currency: snap.execution.notional_currency.clone(),
                multiplier: snap.execution.multiplier,
                limit_price: snap.execution.limit_price,
                stop_price: snap.execution.stop_price,
                client_order_id: snap.execution.client_order_id.clone(),
            },
            heartbeat: HeartbeatBlock {
                sequence_id: snap.heartbeat.sequence_id,
                signature_valid: true,
                drift_ms: 0,
            },
            policy: PolicyBlock {
                id: decision.policy_id.clone(),
                version: decision.policy_version.clone(),
                hash: decision.policy_hash.clone(),
                result: decision.result.to_string(),
            },
            integrity: IntegrityBlock {
                reasoning_hash: reasoning_hash.to_string(),
                final_proof: None,
                verification_status: "PENDING".to_string(),
                execution_status: None,
            },
            regulatory: None,
        }
    }

    /// Unit test: decrypt_if_needed returns plaintext row unchanged when encryption_version=0
    #[tokio::test]
    async fn test_decrypt_if_needed_plaintext_passthrough() {
        let original = serde_json::json!({"foo": "bar", "num": 42});
        let result = decrypt_if_needed(original.clone(), None, None, None, 0, None)
            .await
            .expect("decrypt_if_needed should return Ok for encryption_version=0");
        assert_eq!(result, original);
    }

    /// Unit test: decrypt_if_needed returns Encryption error when version=1 but no provider
    #[tokio::test]
    async fn test_decrypt_if_needed_v1_no_provider_returns_error() {
        let wrapped = serde_json::json!({"v": 1, "data": "dGVzdA=="});
        let result = decrypt_if_needed(
            wrapped,
            Some(vec![0u8; 12]),
            Some(vec![0u8; 48]),
            Some(1),
            1,
            None,
        )
        .await;
        assert!(
            result.is_err(),
            "must fail when key_provider=None and version=1"
        );
        match result.unwrap_err() {
            AppError::Encryption(msg) => {
                assert!(
                    msg.contains("no key_provider configured"),
                    "wrong error: {msg}"
                );
            }
            e => panic!("expected AppError::Encryption, got {e:?}"),
        }
    }

    /// Unit test: decrypt_if_needed returns Encryption error for unknown version
    #[tokio::test]
    async fn test_decrypt_if_needed_unknown_version_returns_error() {
        let result = decrypt_if_needed(serde_json::json!({}), None, None, None, 99, None).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            AppError::Encryption(msg) => assert!(msg.contains("unknown encryption_version")),
            e => panic!("expected Encryption error, got {e:?}"),
        }
    }

    /// Unit test: encrypt_trace + decrypt_if_needed round-trip (no DB needed)
    #[tokio::test]
    async fn test_encrypt_decrypt_roundtrip_no_db() {
        let provider = setup_local_kms();
        let original = serde_json::json!({
            "trace_id": "11111111-1111-1111-1111-111111111111",
            "version": "1.0.0",
            "execution": {"asset": "BTC", "quantity": 1.0}
        });

        let plaintext_bytes = serde_json::to_vec(&original).unwrap();
        let (dek, enc_dek, kv) = provider.generate_dek().await.unwrap();
        let blob = crate::encryption::encrypt_trace(&plaintext_bytes, &dek).unwrap();
        let wrapped = crate::encryption::wrap_ciphertext_for_jsonb(&blob.ciphertext);
        let nonce = blob.nonce.to_vec();

        let decrypted = decrypt_if_needed(
            wrapped,
            Some(nonce),
            Some(enc_dek),
            Some(kv),
            1,
            Some(&provider),
        )
        .await
        .expect("round-trip should succeed");

        assert_eq!(decrypted, original, "decrypted JSON must match original");
    }

    /// Unit test: nonce uniqueness — two encryptions of same data produce different nonces
    #[tokio::test]
    async fn test_nonce_uniqueness() {
        let provider = setup_local_kms();
        let plaintext = b"same plaintext for nonce test";

        let (dek1, _, _) = provider.generate_dek().await.unwrap();
        let blob1 = crate::encryption::encrypt_trace(plaintext, &dek1).unwrap();

        let (dek2, _, _) = provider.generate_dek().await.unwrap();
        let blob2 = crate::encryption::encrypt_trace(plaintext, &dek2).unwrap();

        assert_ne!(blob1.nonce, blob2.nonce, "nonces must differ across calls");
    }

    /// Integration test: requires DATABASE_URL env var.
    /// Tests that insert_trace_atomic writes encryption_version=1 when key_provider=Some.
    #[tokio::test]
    async fn test_insert_encrypted_trace_writes_version_1() {
        let db_url = match std::env::var("DATABASE_URL") {
            Ok(url) => url,
            Err(_) => {
                eprintln!("DATABASE_URL not set — skipping integration test");
                return;
            }
        };

        std::env::set_var(
            "LOCAL_KMS_KEY",
            "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
        );
        std::env::remove_var("ENVIRONMENT");

        let pool = sqlx::PgPool::connect(&db_url)
            .await
            .expect("failed to connect to DB");
        // Self-migrate: these tests run before the integration suite (which also
        // migrates), so they cannot assume the schema already exists. migrate! is
        // idempotent — the first test applies, the rest skip.
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .expect("migrations should apply");

        let provider = setup_local_kms();
        let snap = make_snapshot();
        let decision = make_decision();
        let reasoning_hash = "deadbeef1234567890abcdef";
        let trace = make_trace(&snap, &decision, reasoning_hash);

        insert_trace_atomic(
            &pool,
            &snap,
            reasoning_hash,
            &decision,
            &trace,
            None,
            None,
            Some(&provider),
            None,
            None,
            1, // snapshot_version (v1 in tests)
            None,
        )
        .await
        .expect("insert_trace_atomic should succeed");

        // Verify the row in the DB
        let row: (serde_json::Value, i32, Option<Vec<u8>>, Option<Vec<u8>>, Option<i32>, String) =
            sqlx::query_as(
                r#"
                SELECT trace_json, encryption_version, trace_nonce, encrypted_dek, key_version, reasoning_hash
                FROM irl.reasoning_traces
                WHERE trace_id = $1
                "#,
            )
            .bind(snap.trace_id)
            .fetch_one(&pool)
            .await
            .expect("row should exist");

        let (stored_json, enc_version, nonce, enc_dek, key_ver, stored_hash) = row;

        assert_eq!(enc_version, 1, "encryption_version must be 1");
        assert!(nonce.is_some(), "trace_nonce must be non-NULL");
        assert!(enc_dek.is_some(), "encrypted_dek must be non-NULL");
        assert!(key_ver.is_some(), "key_version must be non-NULL");
        assert_eq!(
            stored_hash, reasoning_hash,
            "reasoning_hash must be stored as plaintext"
        );
        assert_eq!(nonce.unwrap().len(), 12, "nonce must be 12 bytes");

        // Stored trace_json should be JSONB wrapper, not raw plaintext
        assert_eq!(
            stored_json["v"], 1,
            "stored trace_json must be JSONB wrapper {{\"v\":1,...}}"
        );
        assert!(
            stored_json["data"].is_string(),
            "stored trace_json must have base64 'data' field"
        );

        // Cleanup
        sqlx::query("DELETE FROM irl.reasoning_traces WHERE trace_id = $1")
            .bind(snap.trace_id)
            .execute(&pool)
            .await
            .ok();
    }

    /// Integration test: insert plaintext (key_provider=None), verify encryption_version=0.
    #[tokio::test]
    async fn test_insert_plaintext_trace_writes_version_0() {
        let db_url = match std::env::var("DATABASE_URL") {
            Ok(url) => url,
            Err(_) => {
                eprintln!("DATABASE_URL not set — skipping integration test");
                return;
            }
        };

        let pool = sqlx::PgPool::connect(&db_url)
            .await
            .expect("failed to connect to DB");
        // Self-migrate: these tests run before the integration suite (which also
        // migrates), so they cannot assume the schema already exists. migrate! is
        // idempotent — the first test applies, the rest skip.
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .expect("migrations should apply");

        let snap = make_snapshot();
        let decision = make_decision();
        let reasoning_hash = "plaintext_test_hash_abcdef";
        let trace = make_trace(&snap, &decision, reasoning_hash);

        insert_trace_atomic(
            &pool,
            &snap,
            reasoning_hash,
            &decision,
            &trace,
            None,
            None,
            None, // no key_provider = plaintext mode
            None,
            None,
            1, // snapshot_version (v1 in tests)
            None,
        )
        .await
        .expect("plaintext insert should succeed");

        let row: (i32, Option<Vec<u8>>, Option<Vec<u8>>) = sqlx::query_as(
            r#"
            SELECT encryption_version, trace_nonce, encrypted_dek
            FROM irl.reasoning_traces
            WHERE trace_id = $1
            "#,
        )
        .bind(snap.trace_id)
        .fetch_one(&pool)
        .await
        .expect("row should exist");

        let (enc_version, nonce, enc_dek) = row;
        assert_eq!(
            enc_version, 0,
            "plaintext insert must write encryption_version=0"
        );
        assert!(
            nonce.is_none(),
            "trace_nonce must be NULL for plaintext insert"
        );
        assert!(
            enc_dek.is_none(),
            "encrypted_dek must be NULL for plaintext insert"
        );

        // Cleanup
        sqlx::query("DELETE FROM irl.reasoning_traces WHERE trace_id = $1")
            .bind(snap.trace_id)
            .execute(&pool)
            .await
            .ok();
    }

    /// Integration test: reasoning_hash is identical whether encrypted or not.
    #[tokio::test]
    async fn test_reasoning_hash_identical_encrypted_vs_plaintext() {
        let db_url = match std::env::var("DATABASE_URL") {
            Ok(url) => url,
            Err(_) => {
                eprintln!("DATABASE_URL not set — skipping integration test");
                return;
            }
        };

        std::env::set_var(
            "LOCAL_KMS_KEY",
            "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
        );
        std::env::remove_var("ENVIRONMENT");

        let pool = sqlx::PgPool::connect(&db_url)
            .await
            .expect("failed to connect to DB");
        // Self-migrate: these tests run before the integration suite (which also
        // migrates), so they cannot assume the schema already exists. migrate! is
        // idempotent — the first test applies, the rest skip.
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .expect("migrations should apply");

        let provider = setup_local_kms();
        let reasoning_hash = "consistent_hash_for_both_rows";

        // Insert encrypted
        let snap_enc = make_snapshot();
        let decision = make_decision();
        let trace_enc = make_trace(&snap_enc, &decision, reasoning_hash);
        insert_trace_atomic(
            &pool,
            &snap_enc,
            reasoning_hash,
            &decision,
            &trace_enc,
            None,
            None,
            Some(&provider),
            None,
            None,
            1, // snapshot_version (v1 in tests)
            None,
        )
        .await
        .unwrap();

        // Insert plaintext
        let snap_plain = make_snapshot();
        let trace_plain = make_trace(&snap_plain, &decision, reasoning_hash);
        insert_trace_atomic(
            &pool,
            &snap_plain,
            reasoning_hash,
            &decision,
            &trace_plain,
            None,
            None,
            None,
            None,
            None,
            1, // snapshot_version (v1 in tests)
            None,
        )
        .await
        .unwrap();

        // Both rows should have the same reasoning_hash
        let enc_hash: (String,) =
            sqlx::query_as("SELECT reasoning_hash FROM irl.reasoning_traces WHERE trace_id = $1")
                .bind(snap_enc.trace_id)
                .fetch_one(&pool)
                .await
                .unwrap();

        let plain_hash: (String,) =
            sqlx::query_as("SELECT reasoning_hash FROM irl.reasoning_traces WHERE trace_id = $1")
                .bind(snap_plain.trace_id)
                .fetch_one(&pool)
                .await
                .unwrap();

        assert_eq!(enc_hash.0, reasoning_hash);
        assert_eq!(plain_hash.0, reasoning_hash);
        assert_eq!(
            enc_hash.0, plain_hash.0,
            "reasoning_hash must be identical regardless of encryption"
        );

        // Cleanup
        sqlx::query("DELETE FROM irl.reasoning_traces WHERE trace_id = $1")
            .bind(snap_enc.trace_id)
            .execute(&pool)
            .await
            .ok();
        sqlx::query("DELETE FROM irl.reasoning_traces WHERE trace_id = $1")
            .bind(snap_plain.trace_id)
            .execute(&pool)
            .await
            .ok();
    }

    /// Integration test: get_trace_json decrypts encrypted row and returns original JSON.
    #[tokio::test]
    async fn test_get_trace_json_decrypts_encrypted_row() {
        let db_url = match std::env::var("DATABASE_URL") {
            Ok(url) => url,
            Err(_) => {
                eprintln!("DATABASE_URL not set — skipping integration test");
                return;
            }
        };

        std::env::set_var(
            "LOCAL_KMS_KEY",
            "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
        );
        std::env::remove_var("ENVIRONMENT");

        let pool = sqlx::PgPool::connect(&db_url)
            .await
            .expect("failed to connect to DB");
        // Self-migrate: these tests run before the integration suite (which also
        // migrates), so they cannot assume the schema already exists. migrate! is
        // idempotent — the first test applies, the rest skip.
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .expect("migrations should apply");

        let provider = setup_local_kms();
        let snap = make_snapshot();
        let decision = make_decision();
        let reasoning_hash = "get_trace_json_test_hash";
        let trace = make_trace(&snap, &decision, reasoning_hash);

        insert_trace_atomic(
            &pool,
            &snap,
            reasoning_hash,
            &decision,
            &trace,
            None,
            None,
            Some(&provider),
            None,
            None,
            1, // snapshot_version (v1 in tests)
            None,
        )
        .await
        .expect("insert should succeed");

        // get_trace_json should decrypt and return original fields
        let returned = get_trace_json(&pool, snap.trace_id, Some(&provider))
            .await
            .expect("get_trace_json should succeed");

        assert_eq!(
            returned["execution"]["asset"].as_str().unwrap(),
            "BTC",
            "decrypted asset must match original"
        );
        assert_eq!(
            returned["integrity"]["reasoning_hash"].as_str().unwrap(),
            reasoning_hash,
            "reasoning_hash must be present in decrypted response"
        );

        // Cleanup
        sqlx::query("DELETE FROM irl.reasoning_traces WHERE trace_id = $1")
            .bind(snap.trace_id)
            .execute(&pool)
            .await
            .ok();
    }

    /// Integration test: get_trace_json on plaintext row returns JSON unchanged.
    #[tokio::test]
    async fn test_get_trace_json_plaintext_passthrough() {
        let db_url = match std::env::var("DATABASE_URL") {
            Ok(url) => url,
            Err(_) => {
                eprintln!("DATABASE_URL not set — skipping integration test");
                return;
            }
        };

        let pool = sqlx::PgPool::connect(&db_url)
            .await
            .expect("failed to connect to DB");
        // Self-migrate: these tests run before the integration suite (which also
        // migrates), so they cannot assume the schema already exists. migrate! is
        // idempotent — the first test applies, the rest skip.
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .expect("migrations should apply");

        let snap = make_snapshot();
        let decision = make_decision();
        let reasoning_hash = "plaintext_get_trace_hash";
        let trace = make_trace(&snap, &decision, reasoning_hash);

        insert_trace_atomic(
            &pool,
            &snap,
            reasoning_hash,
            &decision,
            &trace,
            None,
            None,
            None,
            None,
            None,
            1, // snapshot_version (v1 in tests)
            None,
        )
        .await
        .expect("plaintext insert should succeed");

        // get_trace_json with no key_provider should still work for plaintext rows
        let returned = get_trace_json(&pool, snap.trace_id, None)
            .await
            .expect("get_trace_json should succeed for plaintext row");

        assert_eq!(
            returned["execution"]["asset"].as_str().unwrap(),
            "BTC",
            "plaintext asset must match original"
        );

        // Cleanup
        sqlx::query("DELETE FROM irl.reasoning_traces WHERE trace_id = $1")
            .bind(snap.trace_id)
            .execute(&pool)
            .await
            .ok();
    }

    /// Integration test: get_trace_json on encrypted row with no provider returns Encryption error.
    #[tokio::test]
    async fn test_get_trace_json_encrypted_no_provider_returns_error() {
        let db_url = match std::env::var("DATABASE_URL") {
            Ok(url) => url,
            Err(_) => {
                eprintln!("DATABASE_URL not set — skipping integration test");
                return;
            }
        };

        std::env::set_var(
            "LOCAL_KMS_KEY",
            "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
        );
        std::env::remove_var("ENVIRONMENT");

        let pool = sqlx::PgPool::connect(&db_url)
            .await
            .expect("failed to connect to DB");
        // Self-migrate: these tests run before the integration suite (which also
        // migrates), so they cannot assume the schema already exists. migrate! is
        // idempotent — the first test applies, the rest skip.
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .expect("migrations should apply");

        let provider = setup_local_kms();
        let snap = make_snapshot();
        let decision = make_decision();
        let reasoning_hash = "enc_no_provider_test";
        let trace = make_trace(&snap, &decision, reasoning_hash);

        insert_trace_atomic(
            &pool,
            &snap,
            reasoning_hash,
            &decision,
            &trace,
            None,
            None,
            Some(&provider),
            None,
            None,
            1, // snapshot_version (v1 in tests)
            None,
        )
        .await
        .expect("insert should succeed");

        // Attempt to read without providing a key_provider — must fail
        let result = get_trace_json(&pool, snap.trace_id, None).await;
        assert!(
            result.is_err(),
            "must fail when key_provider=None for encrypted row"
        );
        match result.unwrap_err() {
            AppError::Encryption(_) => {}
            e => panic!("expected AppError::Encryption, got {e:?}"),
        }

        // Cleanup
        sqlx::query("DELETE FROM irl.reasoning_traces WHERE trace_id = $1")
            .bind(snap.trace_id)
            .execute(&pool)
            .await
            .ok();
    }
}
