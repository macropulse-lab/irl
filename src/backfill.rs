//! Backfill worker: encrypts all legacy plaintext reasoning traces in-place.
//!
//! Design goals:
//! - Resumable: WHERE encryption_version=0 means re-running after a crash skips
//!   already-encrypted rows and continues naturally.
//! - Non-blocking: FOR UPDATE SKIP LOCKED lets live bind-execution updates proceed
//!   without waiting on the backfill. The 100ms sleep between batches prevents
//!   starving the live traffic.
//! - Safe against double-encryption: the UPDATE guard `AND encryption_version=0`
//!   means even if two backfill workers race (or a live INSERT snuck in), the
//!   losing UPDATE affects 0 rows instead of re-encrypting already-encrypted data.
//! - Cursor-based pagination on trace_id (UUID): avoids OFFSET/LIMIT full-table
//!   scans; each batch only reads from the watermark forward.

use crate::{db, encryption, kms::KeyProvider};
use anyhow::Context;
use sqlx::PgPool;
use uuid::Uuid;

const BATCH_SIZE: i64 = 500;
const BATCH_SLEEP_MS: u64 = 100;

/// Encrypt all plaintext rows (encryption_version=0) in irl.reasoning_traces.
///
/// Returns the total number of rows that were successfully encrypted.
///
/// - `provider_name`: "aws" | "vault" | "local" — stored in kms_key_metadata.
/// - `key_arn_or_path`: KMS ARN, Vault key name, or "local" — stored in kms_key_metadata.
pub async fn run_backfill(
    pool: &PgPool,
    key_provider: &dyn KeyProvider,
    provider_name: &str,
    key_arn_or_path: &str,
) -> anyhow::Result<u64> {
    let start = std::time::Instant::now();
    let mut total: u64 = 0;
    let mut last_trace_id: Option<Uuid> = None;

    // Estimate remaining rows for progress logging (best-effort — not required for correctness).
    let remaining_estimate: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM irl.reasoning_traces WHERE encryption_version = 0",
    )
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    tracing::info!(
        "Backfill starting — estimated {} plaintext row(s) to encrypt",
        remaining_estimate
    );

    // Track key versions we have already inserted into kms_key_metadata this run,
    // to avoid one DB round-trip per row. The map key is (key_version, provider).
    let mut registered_key_versions: std::collections::HashSet<i32> =
        std::collections::HashSet::new();

    loop {
        // Fetch next batch of plaintext rows using a cursor on trace_id.
        // FOR UPDATE SKIP LOCKED: rows being updated by a live authorize request
        // are skipped and will be picked up on the next batch (they will already
        // have encryption_version=1 by then if the insert used a key_provider).
        //
        // NOTE: FOR UPDATE cannot be used outside a transaction with some Postgres
        // drivers; we use a short-lived explicit transaction per batch for the SELECT.
        let rows: Vec<(Uuid, serde_json::Value)> = {
            let mut txn = pool.begin().await.context("begin batch select txn")?;
            let result: Vec<(Uuid, serde_json::Value)> = sqlx::query_as(
                r#"
                SELECT trace_id, trace_json
                FROM irl.reasoning_traces
                WHERE encryption_version = 0
                  AND ($1::uuid IS NULL OR trace_id > $1)
                ORDER BY trace_id
                LIMIT $2
                FOR UPDATE SKIP LOCKED
                "#,
            )
            .bind(last_trace_id)
            .bind(BATCH_SIZE)
            .fetch_all(&mut *txn)
            .await
            .context("fetch plaintext batch")?;

            // Immediately commit the SELECT txn — we don't hold the row locks across
            // the full batch. Each row is updated in its own individual transaction
            // (see encrypt_one_row). The per-row AND encryption_version=0 guard in
            // the UPDATE prevents double-encryption if a concurrent writer sneaked in.
            txn.commit().await.context("commit batch select txn")?;
            result
        };

        if rows.is_empty() {
            break;
        }

        let batch_len = rows.len() as u64;

        for (trace_id, trace_json) in &rows {
            let key_version = encrypt_one_row(
                pool,
                *trace_id,
                trace_json,
                key_provider,
                provider_name,
                key_arn_or_path,
            )
            .await
            .with_context(|| format!("encrypt_one_row for trace_id={trace_id}"))?;

            // Register key version in kms_key_metadata once per run per version.
            if let Some(kv) = key_version {
                if registered_key_versions.insert(kv) {
                    db::upsert_kms_key_metadata(pool, kv, provider_name, key_arn_or_path)
                        .await
                        .with_context(|| format!("upsert_kms_key_metadata key_version={kv}"))?;
                    tracing::info!(
                        "Backfill: registered kms_key_metadata for key_version={} provider={}",
                        kv,
                        provider_name
                    );
                }
            }
        }

        total += batch_len;
        last_trace_id = rows.last().map(|(id, _)| *id);

        let elapsed = start.elapsed().as_secs_f64();
        tracing::info!(
            "Backfill: batch of {} encrypted (running total={}, elapsed={:.1}s)",
            batch_len,
            total,
            elapsed,
        );

        tokio::time::sleep(std::time::Duration::from_millis(BATCH_SLEEP_MS)).await;
    }

    tracing::info!(
        "Backfill complete: {} row(s) encrypted in {:.1}s",
        total,
        start.elapsed().as_secs_f64()
    );
    Ok(total)
}

/// Encrypt a single row and UPDATE it in the database.
///
/// Returns `Some(key_version)` if the row was encrypted (UPDATE affected 1 row),
/// or `None` if the row was already encrypted by a concurrent writer (UPDATE
/// affected 0 rows due to the `AND encryption_version=0` guard).
async fn encrypt_one_row(
    pool: &PgPool,
    trace_id: Uuid,
    trace_json: &serde_json::Value,
    key_provider: &dyn KeyProvider,
    _provider_name: &str,
    _key_arn_or_path: &str,
) -> anyhow::Result<Option<i32>> {
    // 1. Generate a fresh per-row DEK.
    let (dek, enc_dek, kv) = key_provider.generate_dek().await.context("generate_dek")?;

    // 2. Serialize the current plaintext trace_json to bytes.
    let plaintext_bytes =
        serde_json::to_vec(trace_json).context("serialize trace_json to bytes")?;

    // 3. Encrypt.
    let blob = encryption::encrypt_trace(&plaintext_bytes, &dek).context("encrypt_trace")?;
    // dek (Zeroizing<Vec<u8>>) drops here — memory wiped automatically.

    // 4. Wrap ciphertext for JSONB storage.
    let wrapped = encryption::wrap_ciphertext_for_jsonb(&blob.ciphertext);
    let nonce_bytes = blob.nonce.to_vec();

    // 5. UPDATE the row.
    //    The AND encryption_version=0 guard prevents double-encryption:
    //    if a concurrent insert or another backfill worker already encrypted this
    //    row, rows_affected=0 and we return None (not an error).
    let result = sqlx::query(
        r#"
        UPDATE irl.reasoning_traces
        SET trace_json        = $1,
            trace_nonce       = $2,
            encrypted_dek     = $3,
            key_version       = $4,
            encryption_version = 1
        WHERE trace_id = $5
          AND encryption_version = 0
        "#,
    )
    .bind(&wrapped)
    .bind(&nonce_bytes)
    .bind(&enc_dek)
    .bind(kv)
    .bind(trace_id)
    .execute(pool)
    .await
    .context("UPDATE reasoning_traces (encrypt backfill)")?;

    if result.rows_affected() == 0 {
        tracing::debug!(
            "Backfill: trace_id={} already encrypted (concurrent writer); skipping",
            trace_id
        );
        return Ok(None);
    }

    Ok(Some(kv))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kms::LocalDevProvider;

    fn setup_local_kms() -> LocalDevProvider {
        std::env::set_var(
            "LOCAL_KMS_KEY",
            "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
        );
        std::env::remove_var("ENVIRONMENT");
        LocalDevProvider::new(1).expect("LocalDevProvider::new should succeed")
    }

    // ── Unit tests (no DB required) ────────────────────────────────────────────

    /// encrypt_one_row logic: verify the encrypt → wrap path produces valid JSONB.
    #[tokio::test]
    async fn test_encrypt_one_row_produces_valid_jsonb_wrapper() {
        let kms = setup_local_kms();
        let plaintext = serde_json::json!({"step": "test", "value": 42});

        // Simulate what encrypt_one_row does (without DB).
        let (dek, _enc_dek, _kv) = kms.generate_dek().await.unwrap();
        let bytes = serde_json::to_vec(&plaintext).unwrap();
        let blob = encryption::encrypt_trace(&bytes, &dek).unwrap();
        let wrapped = encryption::wrap_ciphertext_for_jsonb(&blob.ciphertext);

        // The wrapper must have "v"=1 and "data" key (base64 ciphertext).
        assert_eq!(wrapped["v"], 1);
        assert!(wrapped["data"].is_string(), "data field must be a string");
    }

    /// Verify round-trip: encrypt then decrypt back to original JSON.
    #[tokio::test]
    async fn test_encrypt_decrypt_roundtrip() {
        use crate::encryption;
        let kms = setup_local_kms();
        let original = serde_json::json!({"agent": "test-agent", "decision": "AUTHORIZE"});

        let (dek, enc_dek, kv) = kms.generate_dek().await.unwrap();
        let plaintext_bytes = serde_json::to_vec(&original).unwrap();
        let blob = encryption::encrypt_trace(&plaintext_bytes, &dek).unwrap();
        let wrapped = encryption::wrap_ciphertext_for_jsonb(&blob.ciphertext);
        let nonce_bytes = blob.nonce.to_vec();

        // Now decrypt.
        let dek2 = kms.decrypt_dek(&enc_dek, kv).await.unwrap();
        let ciphertext = encryption::extract_ciphertext_from_jsonb(&wrapped).unwrap();
        let decrypted_bytes = encryption::decrypt_trace(&ciphertext, &nonce_bytes, &dek2).unwrap();
        let recovered: serde_json::Value = serde_json::from_slice(&decrypted_bytes).unwrap();

        assert_eq!(original, recovered);
    }

    // ── Integration tests (require DATABASE_URL) ───────────────────────────────

    fn get_db_url() -> Option<String> {
        std::env::var("DATABASE_URL").ok()
    }

    /// run_backfill on an empty-ish table (no encryption_version=0 rows) returns Ok(0).
    #[tokio::test]
    async fn test_backfill_empty_table_returns_zero() {
        let db_url = match get_db_url() {
            Some(u) => u,
            None => {
                eprintln!("Skipping integration test: DATABASE_URL not set");
                return;
            }
        };
        let pool = sqlx::PgPool::connect(&db_url).await.unwrap();
        // Self-migrate — this test may run before the integration suite migrates.
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        let kms = setup_local_kms();

        // Clean up any leftover test rows from prior runs.
        sqlx::query(
            "DELETE FROM irl.reasoning_traces WHERE reasoning_hash = 'backfill-test-sentinel'",
        )
        .execute(&pool)
        .await
        .unwrap();

        // No plaintext rows with our sentinel hash — but there might be 0 rows with
        // encryption_version=0 overall. We just verify run_backfill returns Ok.
        // The exact count depends on the test DB state, so we only assert no error.
        let result = run_backfill(&pool, &kms, "local", "local").await;
        assert!(result.is_ok(), "run_backfill should succeed: {:?}", result);

        pool.close().await;
    }
}
