//! Merkle anchoring — tamper-evident audit log via OpenTimestamps.
//!
//! # What this does
//! A background task runs once per day. It:
//! 1. Collects all `reasoning_hash` values from `irl.reasoning_traces` since the
//!    last anchor cycle's `period_end`.
//! 2. Builds a binary SHA-256 Merkle tree (leaves sorted by `txn_time`).
//! 3. POSTs the 32-byte root to an OpenTimestamps calendar server.
//! 4. Stores the root + raw receipt in `irl.merkle_anchors`.
//!
//! # Tamper-evidence property
//! Even if IRL's own DB is compromised, an attacker cannot silently insert or
//! delete traces without changing the Merkle root — and that root is committed
//! to the Bitcoin blockchain via OTS. Any auditor who holds the leaf hashes can
//! independently recompute the root and verify the OTS proof.
//!
//! # OTS receipt lifecycle
//! OTS calendar receipts are *incomplete* when first issued — they become
//! complete (Bitcoin-anchored) after 1–2 Bitcoin blocks (~10–20 min).
//! The raw bytes are stored as-is; upgrading to a complete proof is a
//! separate out-of-band step using the `ots upgrade` CLI.
//!
//! # OTS failover
//! Three calendar servers are tried in order. If the primary is down the
//! anchor cycle still completes with a receipt from a secondary.
//!
//! # Failure handling
//! If all OTS POSTs fail, the Merkle root is still persisted with
//! `ots_receipt = NULL` and `ots_error` set. The hourly upgrade worker
//! retries failed rows automatically. The root alone is sufficient for
//! an auditor to verify leaf inclusion; the OTS receipt can be obtained
//! retroactively by re-submitting the root hex to any OTS calendar.

use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::time::Duration;

const ANCHOR_INTERVAL_SECS: u64 = 86_400; // 24 hours
const UPGRADE_INTERVAL_SECS: u64 = 3_600; // 1 hour
const OTS_TIMEOUT_SECS: u64 = 30;

/// OTS calendar endpoints tried in order. First success wins.
/// Rotating through all three gives resilience against individual calendar outages.
const OTS_ENDPOINTS: &[&str] = &[
    "https://a.pool.opentimestamps.org/digest",
    "https://b.pool.opentimestamps.org/digest",
    "https://finney.calendar.eternitywall.com/digest",
];

// ── Merkle tree ───────────────────────────────────────────────────────────────

/// Compute a binary SHA-256 Merkle root over a list of hex-encoded leaf hashes.
///
/// - Leaves are used in the order supplied (caller sorts by `txn_time`).
/// - Odd node count at any level: the last node is duplicated (Bitcoin convention).
/// - Empty input: returns `[0u8; 32]`.
/// - If a leaf hex string is not exactly 32 bytes when decoded, the raw UTF-8
///   of the hex string is hashed instead (graceful handling of unexpected formats).
pub fn compute_merkle_root(hashes: &[String]) -> [u8; 32] {
    if hashes.is_empty() {
        return [0u8; 32];
    }

    let mut nodes: Vec<[u8; 32]> = hashes
        .iter()
        .map(|h| {
            match hex::decode(h) {
                Ok(bytes) if bytes.len() == 32 => {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    arr
                }
                _ => {
                    // Unexpected format — hash the hex string bytes as a leaf.
                    let mut hasher = Sha256::new();
                    hasher.update(h.as_bytes());
                    hasher.finalize().into()
                }
            }
        })
        .collect();

    while nodes.len() > 1 {
        // Duplicate last node if count is odd.
        if nodes.len() % 2 == 1 {
            let last = *nodes.last().unwrap();
            nodes.push(last);
        }
        nodes = nodes
            .chunks(2)
            .map(|pair| {
                let mut hasher = Sha256::new();
                hasher.update(pair[0]);
                hasher.update(pair[1]);
                hasher.finalize().into()
            })
            .collect();
    }

    nodes[0]
}

// ── OpenTimestamps ────────────────────────────────────────────────────────────

/// POST the 32-byte hash to OTS calendar servers with failover.
///
/// Tries each endpoint in `OTS_ENDPOINTS` in order, returning the first
/// successful receipt. Logs a warning for each failure before trying the next.
async fn post_to_opentimestamps(root: &[u8; 32]) -> Result<Vec<u8>, String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(OTS_TIMEOUT_SECS))
        .build()
        .map_err(|e| format!("failed to build HTTP client: {e}"))?;

    let mut last_error = String::new();

    for endpoint in OTS_ENDPOINTS {
        match try_ots_endpoint(&client, endpoint, root).await {
            Ok(bytes) => {
                tracing::info!(
                    "OTS receipt received from {endpoint} ({} bytes)",
                    bytes.len()
                );
                return Ok(bytes);
            }
            Err(e) => {
                tracing::warn!("OTS endpoint {endpoint} failed: {e}");
                last_error = e;
            }
        }
    }

    Err(format!(
        "all {} OTS endpoints failed; last error: {last_error}",
        OTS_ENDPOINTS.len()
    ))
}

async fn try_ots_endpoint(
    client: &reqwest::Client,
    endpoint: &str,
    root: &[u8; 32],
) -> Result<Vec<u8>, String> {
    let resp = client
        .post(endpoint)
        .header("Content-Type", "application/octet-stream")
        .body(root.to_vec())
        .send()
        .await
        .map_err(|e| format!("POST failed: {e}"))?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("HTTP {status}: {body}"));
    }

    resp.bytes()
        .await
        .map(|b| b.to_vec())
        .map_err(|e| format!("failed to read response body: {e}"))
}

// ── Anchor cycle ──────────────────────────────────────────────────────────────

/// Run one anchoring cycle.
///
/// Fetches all `reasoning_hash` values recorded since the last `period_end`
/// (or since the Unix epoch if no prior anchor exists), builds the Merkle root,
/// POSTs to OTS with failover, and writes a row to `irl.merkle_anchors`.
async fn run_anchor_cycle(pool: &PgPool, use_v2: bool) -> Result<(), String> {
    // Determine start of new period (= end of previous anchor, or epoch).
    let last_end: Option<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar(
        "SELECT period_end FROM irl.merkle_anchors ORDER BY period_end DESC LIMIT 1",
    )
    .fetch_optional(pool)
    .await
    .map_err(|e| format!("DB error fetching last anchor: {e}"))?;

    let period_start = last_end.unwrap_or_else(|| chrono::DateTime::from_timestamp(0, 0).unwrap());
    let period_end = chrono::Utc::now();

    // Collect reasoning_hash values in (period_start, period_end], ordered by txn_time.
    let hashes: Vec<String> = sqlx::query_scalar(
        "SELECT reasoning_hash \
         FROM irl.reasoning_traces \
         WHERE txn_time > $1 AND txn_time <= $2 \
         ORDER BY txn_time ASC",
    )
    .bind(period_start)
    .bind(period_end)
    .fetch_all(pool)
    .await
    .map_err(|e| format!("DB error fetching hashes: {e}"))?;

    let leaf_count = hashes.len() as i32;

    if leaf_count == 0 {
        tracing::debug!("Merkle anchor: no new traces in ({period_start}, {period_end}], skipping");
        return Ok(());
    }

    // v2 (domain-separated RFC-6962) fixes the v1 second-preimage weakness.
    // Tag stored on the anchor so the offline verifier picks the right
    // reconstruction; NULL = legacy v1.
    let (root, merkle_algo): ([u8; 32], Option<&str>) = if use_v2 {
        (
            crate::merkle_v2::compute_merkle_root_v2(&hashes),
            Some(crate::merkle_v2::MERKLE_ALGO_V2),
        )
    } else {
        (compute_merkle_root(&hashes), None)
    };
    let root_hex = hex::encode(root);

    tracing::info!(
        "Merkle anchor: {leaf_count} traces in ({period_start}, {period_end}], \
         root={root_hex} algo={}",
        merkle_algo.unwrap_or("v1")
    );

    // POST to OpenTimestamps calendar with failover.
    let now = chrono::Utc::now();
    let (ots_receipt, ots_error, ots_upgraded_at): (
        Option<Vec<u8>>,
        Option<String>,
        Option<chrono::DateTime<chrono::Utc>>,
    ) = match post_to_opentimestamps(&root).await {
        Ok(bytes) => {
            tracing::info!("OTS receipt received ({} bytes)", bytes.len());
            (Some(bytes), None, Some(now))
        }
        Err(e) => {
            tracing::warn!("OTS POST failed (root preserved, receipt missing): {e}");
            (None, Some(e), None)
        }
    };

    // Persist anchor row.
    sqlx::query(
        "INSERT INTO irl.merkle_anchors \
         (period_start, period_end, leaf_count, merkle_root, ots_receipt, ots_error, ots_upgraded_at, merkle_algo) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(period_start)
    .bind(period_end)
    .bind(leaf_count)
    .bind(&root_hex)
    .bind(ots_receipt.as_deref())
    .bind(ots_error.as_deref())
    .bind(ots_upgraded_at)
    .bind(merkle_algo)
    .execute(pool)
    .await
    .map_err(|e| format!("DB error storing anchor: {e}"))?;

    tracing::info!(
        "Merkle anchor stored: root={root_hex} leaf_count={leaf_count} \
         ots={}",
        if ots_error.is_none() {
            "ok"
        } else {
            "missing (see ots_error)"
        }
    );

    Ok(())
}

// ── OTS upgrade cycle ─────────────────────────────────────────────────────────

/// Retry OTS submission for anchors whose initial POST failed.
///
/// Finds up to 10 anchors where `ots_receipt IS NULL` (original POST failed),
/// re-submits each merkle_root to OTS with failover, and updates the row if a
/// receipt is obtained.
async fn run_ots_upgrade_cycle(pool: &PgPool) -> Result<(), String> {
    // Find anchors that never received an OTS receipt.
    let failed: Vec<(i64, String)> = sqlx::query_as(
        "SELECT id, merkle_root \
         FROM irl.merkle_anchors \
         WHERE ots_receipt IS NULL \
           AND ots_upgraded_at IS NULL \
         ORDER BY period_end DESC \
         LIMIT 10",
    )
    .fetch_all(pool)
    .await
    .map_err(|e| format!("DB error fetching unanchored rows: {e}"))?;

    if failed.is_empty() {
        return Ok(());
    }

    tracing::info!(
        "OTS upgrade: retrying {} unanchored anchor(s)",
        failed.len()
    );

    for (id, root_hex) in failed {
        let root_bytes = match hex::decode(&root_hex) {
            Ok(b) if b.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&b);
                arr
            }
            _ => {
                tracing::warn!(
                    "OTS upgrade: skipping anchor id={id} — invalid root hex '{root_hex}'"
                );
                continue;
            }
        };

        match post_to_opentimestamps(&root_bytes).await {
            Ok(receipt) => {
                let updated = sqlx::query(
                    "UPDATE irl.merkle_anchors \
                     SET ots_receipt    = $1, \
                         ots_error      = NULL, \
                         ots_upgraded_at = now() \
                     WHERE id = $2",
                )
                .bind(&receipt)
                .bind(id)
                .execute(pool)
                .await
                .map_err(|e| format!("DB error updating anchor id={id}: {e}"))?;

                tracing::info!(
                    "OTS upgrade: anchor id={id} now anchored ({} byte receipt, {} row(s) updated)",
                    receipt.len(),
                    updated.rows_affected()
                );
            }
            Err(e) => {
                tracing::warn!("OTS upgrade: anchor id={id} retry failed: {e}");
            }
        }
    }

    Ok(())
}

// ── Background workers ────────────────────────────────────────────────────────

/// Spawn a background task that runs one anchoring cycle every 24 hours.
///
/// Runs once immediately on startup (after a 60-second delay to let the DB
/// settle), then repeats on the configured interval.
///
/// Call from `main.rs` after the DB pool is ready:
/// ```rust,ignore
/// tokio::spawn(merkle::run_merkle_anchor_worker(pool.clone(), cfg.merkle_v2_enabled));
/// ```
pub async fn run_merkle_anchor_worker(pool: PgPool, use_v2: bool) {
    // Small startup delay so the first cycle doesn't race with migrations.
    tokio::time::sleep(Duration::from_secs(60)).await;

    let mut interval = tokio::time::interval(Duration::from_secs(ANCHOR_INTERVAL_SECS));
    loop {
        interval.tick().await;
        if let Err(e) = run_anchor_cycle(&pool, use_v2).await {
            tracing::error!("Merkle anchor cycle failed: {e}");
        }
    }
}

/// Spawn a background task that retries failed OTS submissions every hour.
///
/// Picks up anchors whose original OTS POST failed and re-submits with
/// failover across all three calendar servers.
///
/// Call from `main.rs` after the DB pool is ready:
/// ```rust,ignore
/// tokio::spawn(merkle::run_ots_upgrade_worker(pool.clone()));
/// ```
pub async fn run_ots_upgrade_worker(pool: PgPool) {
    // Stagger slightly from the anchor worker.
    tokio::time::sleep(Duration::from_secs(90)).await;

    let mut interval = tokio::time::interval(Duration::from_secs(UPGRADE_INTERVAL_SECS));
    loop {
        interval.tick().await;
        if let Err(e) = run_ots_upgrade_cycle(&pool).await {
            tracing::error!("OTS upgrade cycle failed: {e}");
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn hex32(byte: u8) -> String {
        hex::encode([byte; 32])
    }

    #[test]
    fn empty_input_returns_zero_root() {
        assert_eq!(compute_merkle_root(&[]), [0u8; 32]);
    }

    #[test]
    fn single_leaf_returns_itself() {
        let leaf = hex32(0xAB);
        let root = compute_merkle_root(std::slice::from_ref(&leaf));
        assert_eq!(hex::encode(root), leaf);
    }

    #[test]
    fn two_leaves_hash_of_concatenation() {
        let a = hex32(0x01);
        let b = hex32(0x02);
        let root = compute_merkle_root(&[a.clone(), b.clone()]);

        let mut expected = Sha256::new();
        expected.update([0x01u8; 32]);
        expected.update([0x02u8; 32]);
        let expected: [u8; 32] = expected.finalize().into();

        assert_eq!(root, expected);
    }

    #[test]
    fn odd_leaf_count_duplicates_last() {
        // Three leaves: compute_merkle_root should duplicate leaf C.
        // Level 0: [A, B, C, C]
        // Level 1: [hash(A,B), hash(C,C)]
        // Level 2: [hash(hash(A,B), hash(C,C))]
        let a = hex32(0xAA);
        let b = hex32(0xBB);
        let c = hex32(0xCC);

        let root = compute_merkle_root(&[a.clone(), b.clone(), c.clone()]);

        let ab: [u8; 32] = {
            let mut h = Sha256::new();
            h.update([0xAAu8; 32]);
            h.update([0xBBu8; 32]);
            h.finalize().into()
        };
        let cc: [u8; 32] = {
            let mut h = Sha256::new();
            h.update([0xCCu8; 32]);
            h.update([0xCCu8; 32]);
            h.finalize().into()
        };
        let expected: [u8; 32] = {
            let mut h = Sha256::new();
            h.update(ab);
            h.update(cc);
            h.finalize().into()
        };

        assert_eq!(root, expected);
    }

    #[test]
    fn malformed_leaf_hashed_as_bytes() {
        // A non-hex string should not panic; it gets SHA-256'd as UTF-8.
        let bad = "not-a-hex-hash".to_string();
        let root = compute_merkle_root(std::slice::from_ref(&bad));

        let mut expected = Sha256::new();
        expected.update(bad.as_bytes());
        let expected: [u8; 32] = expected.finalize().into();

        assert_eq!(root, expected);
    }

    #[test]
    fn deterministic_for_same_inputs() {
        let leaves: Vec<String> = (0u8..=4).map(hex32).collect();
        let r1 = compute_merkle_root(&leaves);
        let r2 = compute_merkle_root(&leaves);
        assert_eq!(r1, r2);
    }
}
