//! GDPR Article 17 field-level erasure.
//!
//! Provides `gdpr_erase_agent()` which iterates all reasoning traces for a given
//! agent, decrypts each one, nullifies the 5 PII fields inside `trace_json`,
//! re-encrypts with a fresh DEK + nonce, and updates the row.
//!
//! The `reasoning_hash` column is intentionally left unchanged — the hash mismatch
//! is reconciled by the `gdpr_erased_at` tombstone column per GDPR-02.

use crate::errors::AppError;
use crate::kms::KeyProvider;
use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

/// Nullify the 5 PII fields inside a decoded `trace_json` Value.
///
/// Fields zeroed (path notation):
/// - `agent.agent_id`
/// - `agent.latent_fingerprint`
/// - `agent.feature_schema_id`
/// - `execution.client_order_id`
/// - `execution.venue_id`
///
/// All other keys are left intact (integrity.reasoning_hash, mta.*, bitemporal.*,
/// execution.asset, execution.action, execution.notional, etc.).
/// If a parent key does not exist as an Object, the field is silently skipped.
/// The function is idempotent — calling it twice produces the same result.
pub fn null_pii_fields(json: &mut serde_json::Value) {
    // agent sub-object
    if let Some(agent) = json.get_mut("agent") {
        if let Some(obj) = agent.as_object_mut() {
            obj.insert("agent_id".to_string(), serde_json::Value::Null);
            obj.insert("latent_fingerprint".to_string(), serde_json::Value::Null);
            obj.insert("feature_schema_id".to_string(), serde_json::Value::Null);
        }
    }
    // execution sub-object
    if let Some(execution) = json.get_mut("execution") {
        if let Some(obj) = execution.as_object_mut() {
            obj.insert("client_order_id".to_string(), serde_json::Value::Null);
            obj.insert("venue_id".to_string(), serde_json::Value::Null);
        }
    }
}

/// GDPR Art. 17 erasure for all traces belonging to a given agent.
///
/// For each trace:
/// 1. Detects whether the DB is pre-cutover (reasoning_traces_unified view exists)
///    or post-cutover (directly queries irl.reasoning_traces).
/// 2. Decrypts the trace_json (upgrading plaintext rows to encrypted in the process).
/// 3. Nullifies the 5 PII fields via `null_pii_fields()`.
/// 4. Re-encrypts with a fresh DEK + nonce (never reuses old nonce — Pitfall 3).
/// 5. UPDATEs the row including txn_time in WHERE clause (Pitfall 1 — partition key).
/// 6. Sets gdpr_erased_at = now() and gdpr_request_id on every updated row.
///
/// Traces are processed in batches of 100 (each batch is its own transaction)
/// to avoid long-running transactions that would block autovacuum (Pitfall 5).
///
/// Returns the total number of erased traces.
///
/// # Errors
/// Returns `AppError::Encryption` immediately if called without a key_provider.
pub async fn gdpr_erase_agent(
    pool: &PgPool,
    agent_id: Uuid,
    gdpr_request_id: Uuid,
    key_provider: &dyn KeyProvider,
) -> Result<u64, AppError> {
    // Step 1 — detect schema state: pre-cutover (unified view) or post-cutover
    let row: (bool,) = sqlx::query_as(
        "SELECT to_regclass('irl.reasoning_traces_unified') IS NOT NULL AS unified_exists",
    )
    .fetch_one(pool)
    .await?;
    let source_table = if row.0 {
        "irl.reasoning_traces_unified"
    } else {
        "irl.reasoning_traces"
    };

    // Row type: (trace_id, txn_time, trace_json, trace_nonce, encrypted_dek, key_version, encryption_version)
    type TraceRow = (
        Uuid,
        chrono::DateTime<Utc>,
        serde_json::Value,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<i32>,
        i32,
    );

    let erased_at = Utc::now();
    let mut total_erased: u64 = 0;
    let batch_size: i64 = 100;
    let mut offset: i64 = 0;

    loop {
        // Step 2 — fetch a batch of traces for this agent
        let query = format!(
            "SELECT trace_id, txn_time, trace_json, trace_nonce, encrypted_dek, \
             key_version, encryption_version \
             FROM {source_table} \
             WHERE agent_id = $1 \
             ORDER BY txn_time ASC \
             LIMIT $2 OFFSET $3"
        );

        let rows: Vec<TraceRow> = sqlx::query_as(&query)
            .bind(agent_id)
            .bind(batch_size)
            .bind(offset)
            .fetch_all(pool)
            .await?;

        if rows.is_empty() {
            break;
        }

        let batch_len = rows.len();

        // Step 3 — process each trace in this batch
        for (trace_id, txn_time, raw_json, trace_nonce, encrypted_dek, key_version, enc_version) in
            rows
        {
            // a. Decrypt (replicate decrypt_if_needed logic from db.rs)
            let decrypted = decrypt_trace_json(
                raw_json,
                trace_nonce,
                encrypted_dek,
                key_version,
                enc_version,
                key_provider,
            )
            .await?;

            // b. Nullify PII fields
            let mut patched = decrypted;
            null_pii_fields(&mut patched);

            // c. Serialize to bytes
            let plaintext_bytes =
                serde_json::to_vec(&patched).map_err(|e| AppError::Serialization(e.to_string()))?;

            // d. Generate a fresh DEK (never reuse old nonce — Pitfall 3)
            let (dek, new_enc_dek, new_key_version) = key_provider
                .generate_dek()
                .await
                .map_err(|e| AppError::Encryption(e.to_string()))?;

            // e. Encrypt with fresh nonce
            let blob = crate::encryption::encrypt_trace(&plaintext_bytes, &dek)
                .map_err(|e| AppError::Encryption(e.to_string()))?;

            // f. Wrap ciphertext for JSONB storage
            let new_trace_json = crate::encryption::wrap_ciphertext_for_jsonb(&blob.ciphertext);
            let new_nonce = blob.nonce.to_vec();

            // g. UPDATE — always include txn_time in WHERE for partition pruning (Pitfall 1)
            sqlx::query(
                "UPDATE irl.reasoning_traces \
                 SET trace_json        = $1, \
                     trace_nonce       = $2, \
                     encrypted_dek     = $3, \
                     key_version       = $4, \
                     encryption_version = 1, \
                     gdpr_erased_at    = $5, \
                     gdpr_request_id   = $6 \
                 WHERE trace_id = $7 \
                   AND txn_time  = $8",
            )
            .bind(new_trace_json)
            .bind(new_nonce)
            .bind(new_enc_dek)
            .bind(new_key_version)
            .bind(erased_at)
            .bind(gdpr_request_id)
            .bind(trace_id)
            .bind(txn_time)
            .execute(pool)
            .await?;

            total_erased += 1;
        }

        offset += batch_len as i64;
        if batch_len < batch_size as usize {
            break;
        }
    }

    Ok(total_erased)
}

/// Decrypt trace_json if encrypted (encryption_version=1), else return as-is.
/// Mirrors the private `decrypt_if_needed` function in db.rs.
async fn decrypt_trace_json(
    trace_json: serde_json::Value,
    trace_nonce: Option<Vec<u8>>,
    encrypted_dek: Option<Vec<u8>>,
    key_version: Option<i32>,
    encryption_version: i32,
    key_provider: &dyn KeyProvider,
) -> Result<serde_json::Value, AppError> {
    match encryption_version {
        0 => {
            // Plaintext passthrough — trace_json is already the decoded Value
            Ok(trace_json)
        }
        1 => {
            let enc_dek = encrypted_dek.ok_or_else(|| {
                AppError::Encryption("encrypted_dek is NULL for encryption_version=1".into())
            })?;
            let nonce = trace_nonce.ok_or_else(|| {
                AppError::Encryption("trace_nonce is NULL for encryption_version=1".into())
            })?;
            let kv = key_version.unwrap_or(1);
            let dek = key_provider
                .decrypt_dek(&enc_dek, kv)
                .await
                .map_err(|e| AppError::Encryption(e.to_string()))?;
            let ciphertext = crate::encryption::extract_ciphertext_from_jsonb(&trace_json)
                .map_err(|e| AppError::Encryption(e.to_string()))?;
            let plaintext = crate::encryption::decrypt_trace(&ciphertext, &nonce, &dek)
                .map_err(|e| AppError::Encryption(e.to_string()))?;
            serde_json::from_slice(&plaintext).map_err(|e| AppError::Serialization(e.to_string()))
        }
        v => Err(AppError::Encryption(format!(
            "unknown encryption_version: {v}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_trace_json() -> serde_json::Value {
        json!({
            "agent": {
                "agent_id": "550e8400-e29b-41d4-a716-446655440000",
                "latent_fingerprint": "aabbccdd",
                "feature_schema_id": "schema-v1",
                "model_id": "gpt-4",
            },
            "execution": {
                "client_order_id": "ord-12345",
                "venue_id": "XNAS",
                "asset": "BTC-PERP",
                "action": "Long",
                "notional": 50000.0,
            },
            "integrity": {
                "reasoning_hash": "deadbeef1234567890abcdef",
            },
            "mta": {
                "regime_id": 1,
                "regime_version": "v1",
            },
            "bitemporal": {
                "valid_time": 1234567890000_i64,
                "txn_time": 1234567890100_i64,
            }
        })
    }

    #[test]
    fn test_null_pii_fields_basic() {
        let mut json = sample_trace_json();
        null_pii_fields(&mut json);

        // PII fields must be null
        assert_eq!(json["agent"]["agent_id"], serde_json::Value::Null);
        assert_eq!(json["agent"]["latent_fingerprint"], serde_json::Value::Null);
        assert_eq!(json["agent"]["feature_schema_id"], serde_json::Value::Null);
        assert_eq!(
            json["execution"]["client_order_id"],
            serde_json::Value::Null
        );
        assert_eq!(json["execution"]["venue_id"], serde_json::Value::Null);

        // Non-PII fields must be unchanged
        assert_eq!(
            json["integrity"]["reasoning_hash"],
            "deadbeef1234567890abcdef"
        );
        assert_eq!(json["mta"]["regime_id"], 1);
        assert_eq!(json["bitemporal"]["valid_time"], 1234567890000_i64);
        assert_eq!(json["execution"]["asset"], "BTC-PERP");
        assert_eq!(json["execution"]["action"], "Long");
        assert_eq!(json["execution"]["notional"], 50000.0);
        assert_eq!(json["agent"]["model_id"], "gpt-4");
    }

    #[test]
    fn test_null_pii_fields_idempotent() {
        let mut json1 = sample_trace_json();
        null_pii_fields(&mut json1);

        let mut json2 = sample_trace_json();
        null_pii_fields(&mut json2);
        null_pii_fields(&mut json2); // called twice

        assert_eq!(json1, json2, "null_pii_fields must be idempotent");
    }

    #[test]
    fn test_null_pii_fields_missing_keys() {
        // No "agent" key at all — should not panic
        let mut json = json!({
            "execution": {
                "asset": "ETH-PERP",
            }
        });
        // Should not panic
        null_pii_fields(&mut json);
        // execution.client_order_id inserted as null
        assert_eq!(
            json["execution"]["client_order_id"],
            serde_json::Value::Null
        );
        assert_eq!(json["execution"]["venue_id"], serde_json::Value::Null);
        // agent key still absent (not created by null_pii_fields)
        assert!(json.get("agent").is_none());
    }
}
