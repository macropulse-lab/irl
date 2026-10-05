/// Post-Trade Verifier — async expiry worker (whitepaper v3 §11).
///
/// Runs as a background task alongside the HTTP server.
/// Every 60 seconds, marks PENDING traces older than `expiry_ms` as EXPIRED.
///
/// PENDING → EXPIRED transition:
///   Any trace sealed more than `expiry_ms` milliseconds ago that has not
///   received a bind-execution call is considered orphaned from the exchange
///   confirmation stream and is flagged for operator review.
use sqlx::PgPool;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info};

/// Start the expiry background worker.
/// `expiry_ms`: traces older than this are transitioned PENDING → EXPIRED.
pub async fn run_expiry_worker(pool: Arc<PgPool>, expiry_ms: u64) {
    let expiry_secs = (expiry_ms / 1000) as f64;
    info!(
        "Post-trade verifier started (expiry: {}s)",
        expiry_secs as u64
    );

    loop {
        tokio::time::sleep(Duration::from_secs(60)).await;

        match expire_pending(&pool, expiry_secs).await {
            Ok(n) if n > 0 => info!("Verifier: expired {} stale PENDING trace(s)", n),
            Ok(_) => {}
            Err(e) => error!("Verifier: expiry sweep failed: {}", e),
        }
    }
}

async fn expire_pending(pool: &PgPool, expiry_secs: f64) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        r#"
        UPDATE irl.reasoning_traces
        SET verification_status = 'EXPIRED'
        WHERE verification_status = 'PENDING'
          AND txn_time < now() - make_interval(secs => $1)
        "#,
    )
    .bind(expiry_secs)
    .execute(pool)
    .await?;

    Ok(result.rows_affected())
}
