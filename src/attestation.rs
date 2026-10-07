//! Proof bundle export and offline verification.
//!
//! A proof bundle is a self-contained evidence file covering a time range:
//! every trace (reasoning_hash, final_proof, verdict, bitemporal timestamps),
//! plus every Merkle anchor whose period overlaps the range, including the
//! full ordered leaf list and the raw OpenTimestamps receipt.
//!
//! The bundle is designed to be verified **fully offline** by a party that
//! does not trust the IRL operator:
//!
//! 1. `final_proof = SHA-256(reasoning_hash || "||" || exchange_tx_id)` is
//!    recomputed for every bound trace.
//! 2. Each anchor's Merkle root is recomputed from its leaf list.
//! 3. Each trace's `reasoning_hash` is checked for inclusion in the anchor
//!    covering its `txn_time`.
//! 4. The OTS receipt ties each root to the Bitcoin blockchain — verified
//!    with the standard `ots` client, independent of MacroPulse.
//!
//! Shared between the HTTP endpoint (`GET /irl/attestation`) and the
//! standalone offline verifier binary (`irl-verify`).

use crate::errors::AppError;
use crate::merkle::compute_merkle_root;
use crate::seal::compute_final_proof;
use base64::Engine;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::collections::HashSet;
use uuid::Uuid;

pub const BUNDLE_VERSION: u32 = 1;

/// Hard cap on traces per bundle. Narrow the time range if exceeded.
const MAX_BUNDLE_TRACES: i64 = 100_000;

// ── Bundle types ──────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct ProofBundle {
    pub bundle_version: u32,
    pub generated_at: DateTime<Utc>,
    pub engine_version: String,
    pub period_from: DateTime<Utc>,
    pub period_to: DateTime<Utc>,
    /// Bundle filtered to a single agent when set. Anchors still cover all
    /// traces in their period — leaf lists may include other agents' hashes
    /// (hashes alone reveal nothing).
    pub agent_id: Option<Uuid>,
    pub spec: BundleSpec,
    pub traces: Vec<BundleTrace>,
    pub anchors: Vec<BundleAnchor>,
}

/// Human-readable description of the hash constructions, embedded so a
/// bundle is interpretable years later without access to this codebase.
#[derive(Debug, Serialize, Deserialize)]
pub struct BundleSpec {
    pub reasoning_hash: String,
    pub final_proof: String,
    pub merkle: String,
    pub anchor: String,
}

impl Default for BundleSpec {
    fn default() -> Self {
        Self {
            reasoning_hash: "snapshot_version 1: lower-hex SHA-256 over RFC 8785 canonical \
                             JSON of the CognitiveSnapshot. snapshot_version 2: lower-hex \
                             SHA-256 over RFC 8785 canonical JSON of the public field view \
                             (including private_commitment = SHA-256 of the canonical private \
                             field group); recompute from BundleTrace.public_view"
                .into(),
            final_proof: "lower-hex SHA-256(reasoning_hash_ascii || \"||\" || \
                          exchange_tx_id_ascii)"
                .into(),
            merkle: "v1 (merkle_algo absent): binary SHA-256 Merkle tree, leaves are the \
                     32-byte decoded reasoning_hash values ordered by txn_time ascending, \
                     odd node count duplicates the last node. v2 (merkle_algo \
                     'rfc6962-sha256-v2'): domain-separated leaf=SHA256(0x00||h), \
                     node=SHA256(0x01||l||r); verify BundleTrace.audit_path against merkle_root"
                .into(),
            anchor: "merkle_root committed to Bitcoin via OpenTimestamps; verify \
                     ots_receipt_base64 with the standard `ots` client"
                .into(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BundleTrace {
    pub trace_id: Uuid,
    pub agent_id: Option<Uuid>,
    pub reasoning_hash: String,
    pub exchange_tx_id: Option<String>,
    pub final_proof: Option<String>,
    pub verification_status: String,
    pub valid_time: DateTime<Utc>,
    pub txn_time: DateTime<Utc>,
    /// Seal format: 1 = whole-snapshot v1, 2 = split-commitment v2.
    /// Defaults to 1 so v1 bundles parse unchanged.
    #[serde(default = "default_snapshot_version")]
    pub snapshot_version: i16,
    /// v2 only: the public field view an auditor recomputes `reasoning_hash`
    /// from, offline, without seeing private order detail. Absent for v1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_view: Option<crate::seal_v2::PublicView>,
    /// v2 only: O(log n) Merkle audit path from this trace's leaf to the
    /// covering anchor's root — replaces reliance on the full leaf dump.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_path: Option<Vec<crate::merkle_v2::MerkleStep>>,
}

fn default_snapshot_version() -> i16 {
    1
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BundleAnchor {
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    pub leaf_count: i32,
    pub merkle_root: String,
    /// All reasoning_hash leaves in the anchor period, in txn_time order.
    pub leaves: Vec<String>,
    /// Raw OpenTimestamps receipt, base64. Complete (Bitcoin-upgraded)
    /// receipt when available, otherwise the original calendar receipt.
    pub ots_receipt_base64: Option<String>,
    /// Root construction. `None`/absent = v1 (`SHA256(l||r)`, no domain
    /// separation); `"rfc6962-sha256-v2"` = domain-separated v2. Defaults to
    /// None so v1 bundles parse unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merkle_algo: Option<String>,
}

// ── Bundle construction ───────────────────────────────────────────────────────

/// Build a proof bundle for `(from, to]`, optionally filtered to one agent.
/// `scope` (a client token) limits traces to agents that token owns; anchors
/// stay complete, since their leaves are hashes only.
pub async fn build_bundle(
    pool: &PgPool,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
    agent_id: Option<Uuid>,
    scope: Option<Uuid>,
) -> Result<ProofBundle, AppError> {
    if from >= to {
        return Err(AppError::BadRequest(
            "`from` must be strictly before `to`".into(),
        ));
    }

    let traces = fetch_traces(pool, from, to, agent_id, scope).await?;
    if traces.len() as i64 >= MAX_BUNDLE_TRACES {
        return Err(AppError::BadRequest(format!(
            "bundle would exceed {MAX_BUNDLE_TRACES} traces; narrow the time range"
        )));
    }

    let anchors = fetch_anchors(pool, from, to).await?;

    let mut traces = traces;
    assign_audit_paths(&mut traces, &anchors);

    Ok(ProofBundle {
        bundle_version: BUNDLE_VERSION,
        generated_at: Utc::now(),
        engine_version: env!("CARGO_PKG_VERSION").into(),
        period_from: from,
        period_to: to,
        agent_id,
        spec: BundleSpec::default(),
        traces,
        anchors,
    })
}

/// Trace columns needed to rebuild both the bundle record and (for v2) the
/// public view the auditor recomputes `reasoning_hash` from. Named FromRow
/// rather than a tuple — 17 columns exceeds sqlx's tuple FromRow limit.
#[derive(sqlx::FromRow)]
struct TraceRow {
    trace_id: Uuid,
    agent_id: Option<Uuid>,
    reasoning_hash: String,
    exchange_tx_id: Option<String>,
    final_proof: Option<String>,
    verification_status: String,
    valid_time: DateTime<Utc>,
    txn_time: DateTime<Utc>,
    snapshot_version: i16,
    private_commitment: Option<String>,
    latent_fingerprint: String,
    execution_action: String,
    execution_quantity: f64,
    execution_notional: Option<f64>,
    execution_asset: String,
    mta_hash: String,
    mta_regime_id: i16,
}

async fn fetch_traces(
    pool: &PgPool,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
    agent_id: Option<Uuid>,
    scope: Option<Uuid>,
) -> Result<Vec<BundleTrace>, AppError> {
    let rows: Vec<TraceRow> = sqlx::query_as(
        r#"
        SELECT trace_id, agent_id, reasoning_hash, exchange_tx_id,
               final_proof, verification_status, valid_time, txn_time,
               snapshot_version, private_commitment,
               latent_fingerprint, execution_action,
               execution_quantity::float8 AS execution_quantity,
               execution_notional::float8 AS execution_notional,
               execution_asset, mta_hash, mta_regime_id
        FROM irl.reasoning_traces
        WHERE txn_time > $1 AND txn_time <= $2
          AND ($3::uuid IS NULL OR agent_id = $3)
          AND ($5::uuid IS NULL OR agent_id IN
               (SELECT agent_id FROM irl.agent_registry WHERE owner_token_id = $5))
        ORDER BY txn_time ASC
        LIMIT $4
        "#,
    )
    .bind(from)
    .bind(to)
    .bind(agent_id)
    .bind(MAX_BUNDLE_TRACES)
    .bind(scope)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(bundle_trace_from_row).collect())
}

/// Build a BundleTrace, reconstructing the v2 public view when the row is v2.
///
/// `direction` is derived from the stored `execution_action` display string via
/// the same resolver `TradeAction::direction()` used at seal time, and the
/// bitemporal timestamps are read back as Unix ms — so the auditor's recomputed
/// `reasoning_hash` matches the anchored value byte-for-byte.
fn bundle_trace_from_row(r: TraceRow) -> BundleTrace {
    let public_view = if r.snapshot_version >= crate::seal_v2::SNAPSHOT_VERSION_V2 {
        r.private_commitment
            .as_ref()
            .map(|commitment| crate::seal_v2::PublicView {
                trace_id: r.trace_id,
                latent_fingerprint: r.latent_fingerprint.clone(),
                direction: crate::snapshot::resolve_custom_direction(&r.execution_action)
                    .to_string(),
                quantity: r.execution_quantity,
                notional: r.execution_notional.unwrap_or(0.0),
                asset: r.execution_asset.clone(),
                mta_hash: r.mta_hash.clone(),
                mta_regime_id: r.mta_regime_id as u8,
                valid_time: r.valid_time.timestamp_millis(),
                txn_time: r.txn_time.timestamp_millis(),
                private_commitment: commitment.clone(),
            })
    } else {
        None
    };

    BundleTrace {
        trace_id: r.trace_id,
        agent_id: r.agent_id,
        reasoning_hash: r.reasoning_hash,
        exchange_tx_id: r.exchange_tx_id,
        final_proof: r.final_proof,
        verification_status: r.verification_status,
        valid_time: r.valid_time,
        txn_time: r.txn_time,
        snapshot_version: r.snapshot_version,
        public_view,
        // Assigned in build_bundle once anchors (and their ordered leaves) are known.
        audit_path: None,
    }
}

/// Attach a Merkle audit path to each v2 trace covered by a v2 anchor.
/// No-op while anchors are still v1 (the anchor worker is not yet migrated) —
/// such traces verify by preimage + leaf membership until a v2 anchor covers them.
fn assign_audit_paths(traces: &mut [BundleTrace], anchors: &[BundleAnchor]) {
    for t in traces.iter_mut() {
        if t.snapshot_version < crate::seal_v2::SNAPSHOT_VERSION_V2 {
            continue;
        }
        let covering_v2 = anchors.iter().find(|a| {
            a.merkle_algo.as_deref() == Some(crate::merkle_v2::MERKLE_ALGO_V2)
                && t.txn_time > a.period_start
                && t.txn_time <= a.period_end
        });
        if let Some(anchor) = covering_v2 {
            if let Some(idx) = anchor.leaves.iter().position(|h| h == &t.reasoning_hash) {
                t.audit_path = crate::merkle_v2::audit_path(&anchor.leaves, idx);
            }
        }
    }
}

async fn fetch_anchors(
    pool: &PgPool,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
) -> Result<Vec<BundleAnchor>, AppError> {
    type Row = (
        DateTime<Utc>,
        DateTime<Utc>,
        i32,
        String,
        Option<Vec<u8>>,
        Option<String>,
    );

    let rows: Vec<Row> = sqlx::query_as(
        r#"
        SELECT period_start, period_end, leaf_count, merkle_root,
               COALESCE(ots_complete_receipt, ots_receipt), merkle_algo
        FROM irl.merkle_anchors
        WHERE period_end > $1 AND period_start < $2
        ORDER BY period_end ASC
        "#,
    )
    .bind(from)
    .bind(to)
    .fetch_all(pool)
    .await?;

    let mut anchors = Vec::with_capacity(rows.len());
    for (period_start, period_end, leaf_count, merkle_root, receipt, merkle_algo) in rows {
        // Full leaf list for the anchor period — required for offline root
        // recomputation. Matches run_anchor_cycle's query exactly.
        let leaves: Vec<String> = sqlx::query_scalar(
            r#"
            SELECT reasoning_hash
            FROM irl.reasoning_traces
            WHERE txn_time > $1 AND txn_time <= $2
            ORDER BY txn_time ASC
            "#,
        )
        .bind(period_start)
        .bind(period_end)
        .fetch_all(pool)
        .await?;

        anchors.push(BundleAnchor {
            period_start,
            period_end,
            leaf_count,
            merkle_root,
            leaves,
            ots_receipt_base64: receipt
                .map(|b| base64::engine::general_purpose::STANDARD.encode(b)),
            // NULL for legacy v1 anchors; Some("rfc6962-sha256-v2") once the
            // worker runs with MERKLE_V2_ENABLED. The verifier selects the root
            // construction from this tag.
            merkle_algo,
        });
    }

    Ok(anchors)
}

// ── Offline verification ──────────────────────────────────────────────────────

/// Result of verifying a bundle. Pure computation — no network, no DB.
#[derive(Debug, Default, Serialize)]
pub struct VerificationReport {
    pub final_proofs_checked: usize,
    pub final_proof_failures: Vec<String>,
    pub anchors_checked: usize,
    pub anchor_root_failures: Vec<String>,
    pub anchors_with_ots_receipt: usize,
    pub traces_anchored: usize,
    /// Trace appears inside an anchor period but its hash is missing from
    /// the leaf list — evidence of tampering. Hard failure.
    pub inclusion_failures: Vec<String>,
    /// Trace not covered by any anchor in the bundle (e.g. sealed after the
    /// most recent anchor cycle). Warning, not failure.
    pub traces_unanchored: Vec<String>,
    /// v2: number of traces whose `reasoning_hash` was recomputed from the
    /// public view (the check the v1 verifier could not perform).
    pub preimage_checked: usize,
    /// v2: recomputing `reasoning_hash` from the public view did not match the
    /// anchored value — the disclosed decision does not hash to its proof.
    /// Hard failure.
    pub preimage_failures: Vec<String>,
    /// v2: number of traces whose Merkle audit path was folded to the root.
    pub audit_paths_checked: usize,
    /// v2: an audit path did not fold to the covering anchor's root. Hard failure.
    pub audit_path_failures: Vec<String>,
}

impl VerificationReport {
    pub fn passed(&self) -> bool {
        self.final_proof_failures.is_empty()
            && self.anchor_root_failures.is_empty()
            && self.inclusion_failures.is_empty()
            && self.preimage_failures.is_empty()
            && self.audit_path_failures.is_empty()
    }
}

/// Decode a hex Merkle root to 32 bytes for audit-path folding.
fn decode_root_hex(root_hex: &str) -> Option<[u8; 32]> {
    hex::decode(root_hex).ok()?.try_into().ok()
}

/// Returns true when an anchor's root uses the v2 domain-separated construction.
fn anchor_is_v2(anchor: &BundleAnchor) -> bool {
    anchor.merkle_algo.as_deref() == Some(crate::merkle_v2::MERKLE_ALGO_V2)
}

/// Verify a proof bundle offline.
pub fn verify_bundle(bundle: &ProofBundle) -> VerificationReport {
    let mut report = VerificationReport::default();

    // 1. Recompute final_proof for every bound trace.
    for trace in &bundle.traces {
        if let (Some(tx_id), Some(claimed)) = (&trace.exchange_tx_id, &trace.final_proof) {
            report.final_proofs_checked += 1;
            let recomputed = compute_final_proof(&trace.reasoning_hash, tx_id);
            if &recomputed != claimed {
                report.final_proof_failures.push(format!(
                    "trace {}: claimed final_proof {} != recomputed {}",
                    trace.trace_id, claimed, recomputed
                ));
            }
        }
    }

    // 1b. PREIMAGE (v2): recompute reasoning_hash from the disclosed public
    // view. This is the check the v1 verifier could not perform — it proves the
    // anchored hash is a faithful hash of the decision, not just internally
    // consistent arithmetic. A v2 trace without a public_view is reported as a
    // preimage failure: it claims v2 but supplies nothing to recompute from.
    for trace in &bundle.traces {
        if trace.snapshot_version >= crate::seal_v2::SNAPSHOT_VERSION_V2 {
            report.preimage_checked += 1;
            match &trace.public_view {
                Some(view) => {
                    let recomputed = view.recompute_reasoning_hash();
                    if recomputed != trace.reasoning_hash {
                        report.preimage_failures.push(format!(
                            "trace {}: reasoning_hash {} != recomputed-from-public-view {}",
                            trace.trace_id, trace.reasoning_hash, recomputed
                        ));
                    }
                }
                None => report.preimage_failures.push(format!(
                    "trace {}: snapshot_version {} but no public_view to recompute from",
                    trace.trace_id, trace.snapshot_version
                )),
            }
        }
    }

    // 2. Recompute every anchor's Merkle root from its leaves, using the anchor's
    //    declared algorithm (v1 SHA256(l||r) or v2 domain-separated RFC-6962).
    let mut anchor_leaf_sets: Vec<HashSet<&str>> = Vec::with_capacity(bundle.anchors.len());
    for anchor in &bundle.anchors {
        report.anchors_checked += 1;
        if anchor.ots_receipt_base64.is_some() {
            report.anchors_with_ots_receipt += 1;
        }
        if anchor.leaves.len() != anchor.leaf_count as usize {
            report.anchor_root_failures.push(format!(
                "anchor {}..{}: leaf_count {} != {} leaves supplied",
                anchor.period_start,
                anchor.period_end,
                anchor.leaf_count,
                anchor.leaves.len()
            ));
        }
        let recomputed = if anchor_is_v2(anchor) {
            hex::encode(crate::merkle_v2::compute_merkle_root_v2(&anchor.leaves))
        } else {
            hex::encode(compute_merkle_root(&anchor.leaves))
        };
        if recomputed != anchor.merkle_root {
            report.anchor_root_failures.push(format!(
                "anchor {}..{}: claimed root {} != recomputed {}",
                anchor.period_start, anchor.period_end, anchor.merkle_root, recomputed
            ));
        }
        anchor_leaf_sets.push(anchor.leaves.iter().map(String::as_str).collect());
    }

    // 3. Check each trace's inclusion in the anchor covering its txn_time.
    //    Leaf-set membership works for any algorithm; when the anchor is v2 and
    //    the trace carries an audit path, additionally fold the path to the root
    //    — the cryptographic inclusion proof that does not depend on the full
    //    leaf dump.
    for trace in &bundle.traces {
        let covering = bundle
            .anchors
            .iter()
            .position(|a| trace.txn_time > a.period_start && trace.txn_time <= a.period_end);
        match covering {
            Some(idx) => {
                let anchor = &bundle.anchors[idx];
                if anchor_leaf_sets[idx].contains(trace.reasoning_hash.as_str()) {
                    report.traces_anchored += 1;
                } else {
                    report.inclusion_failures.push(format!(
                        "trace {}: txn_time {} falls in anchor {}..{} but reasoning_hash \
                         is absent from its leaf list",
                        trace.trace_id, trace.txn_time, anchor.period_start, anchor.period_end
                    ));
                }

                if let Some(path) = &trace.audit_path {
                    if anchor_is_v2(anchor) {
                        report.audit_paths_checked += 1;
                        match decode_root_hex(&anchor.merkle_root) {
                            Some(root) => {
                                if !crate::merkle_v2::verify_audit_path(
                                    &trace.reasoning_hash,
                                    path,
                                    &root,
                                ) {
                                    report.audit_path_failures.push(format!(
                                        "trace {}: audit path does not fold to anchor root {}",
                                        trace.trace_id, anchor.merkle_root
                                    ));
                                }
                            }
                            None => report.audit_path_failures.push(format!(
                                "trace {}: anchor root {} is not 32-byte hex",
                                trace.trace_id, anchor.merkle_root
                            )),
                        }
                    }
                }
            }
            None => report.traces_unanchored.push(trace.trace_id.to_string()),
        }
    }

    report
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use sha2::{Digest, Sha256};

    fn hash_hex(data: &[u8]) -> String {
        hex::encode(Sha256::digest(data))
    }

    fn ts(hour: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 6, 1, hour, 0, 0).unwrap()
    }

    fn make_trace(hour: u32, tx: Option<&str>) -> BundleTrace {
        let reasoning_hash = hash_hex(format!("snapshot-{hour}").as_bytes());
        let final_proof = tx.map(|t| compute_final_proof(&reasoning_hash, t));
        BundleTrace {
            trace_id: Uuid::new_v4(),
            agent_id: None,
            reasoning_hash,
            exchange_tx_id: tx.map(String::from),
            final_proof,
            verification_status: if tx.is_some() { "MATCHED" } else { "PENDING" }.into(),
            valid_time: ts(hour) - chrono::Duration::seconds(5),
            txn_time: ts(hour),
            snapshot_version: 1,
            public_view: None,
            audit_path: None,
        }
    }

    fn make_bundle(traces: Vec<BundleTrace>) -> ProofBundle {
        let leaves: Vec<String> = traces.iter().map(|t| t.reasoning_hash.clone()).collect();
        let root = hex::encode(compute_merkle_root(&leaves));
        let anchor = BundleAnchor {
            period_start: ts(0),
            period_end: ts(23),
            leaf_count: leaves.len() as i32,
            merkle_root: root,
            leaves,
            ots_receipt_base64: None,
            merkle_algo: None,
        };
        ProofBundle {
            bundle_version: BUNDLE_VERSION,
            generated_at: Utc::now(),
            engine_version: "test".into(),
            period_from: ts(0),
            period_to: ts(23),
            agent_id: None,
            spec: BundleSpec::default(),
            traces,
            anchors: vec![anchor],
        }
    }

    #[test]
    fn valid_bundle_passes() {
        let bundle = make_bundle(vec![
            make_trace(1, Some("exch-1")),
            make_trace(2, Some("exch-2")),
            make_trace(3, None),
        ]);
        let report = verify_bundle(&bundle);
        assert!(report.passed(), "{report:?}");
        assert_eq!(report.final_proofs_checked, 2);
        assert_eq!(report.traces_anchored, 3);
        assert!(report.traces_unanchored.is_empty());
    }

    #[test]
    fn tampered_final_proof_fails() {
        let mut bundle = make_bundle(vec![make_trace(1, Some("exch-1"))]);
        bundle.traces[0].final_proof = Some(hash_hex(b"forged"));
        let report = verify_bundle(&bundle);
        assert!(!report.passed());
        assert_eq!(report.final_proof_failures.len(), 1);
    }

    #[test]
    fn tampered_merkle_root_fails() {
        let mut bundle = make_bundle(vec![make_trace(1, Some("exch-1"))]);
        bundle.anchors[0].merkle_root = hash_hex(b"forged-root");
        let report = verify_bundle(&bundle);
        assert!(!report.passed());
        assert_eq!(report.anchor_root_failures.len(), 1);
    }

    #[test]
    fn deleted_leaf_breaks_inclusion_and_root() {
        let mut bundle = make_bundle(vec![
            make_trace(1, Some("exch-1")),
            make_trace(2, Some("exch-2")),
        ]);
        // Simulate a silently deleted trace: leaf removed but root left as-is.
        bundle.anchors[0].leaves.remove(0);
        let report = verify_bundle(&bundle);
        assert!(!report.passed());
        assert_eq!(report.inclusion_failures.len(), 1);
        assert!(!report.anchor_root_failures.is_empty());
    }

    #[test]
    fn trace_outside_anchor_period_is_warning_not_failure() {
        let mut bundle = make_bundle(vec![make_trace(1, Some("exch-1"))]);
        // Sealed after the last anchor cycle.
        let late = make_trace(2, Some("exch-2"));
        bundle.anchors[0].period_end = ts(1); // anchor only covers hour 1
        bundle.traces.push(late);
        // Rebuild root for the single covered leaf.
        bundle.anchors[0].leaves = vec![bundle.traces[0].reasoning_hash.clone()];
        bundle.anchors[0].leaf_count = 1;
        bundle.anchors[0].merkle_root = hex::encode(compute_merkle_root(&bundle.anchors[0].leaves));

        let report = verify_bundle(&bundle);
        assert!(report.passed(), "{report:?}");
        assert_eq!(report.traces_unanchored.len(), 1);
        assert_eq!(report.traces_anchored, 1);
    }

    #[test]
    fn round_trips_through_json() {
        let bundle = make_bundle(vec![make_trace(1, Some("exch-1"))]);
        let json = serde_json::to_string(&bundle).unwrap();
        let parsed: ProofBundle = serde_json::from_str(&json).unwrap();
        assert!(verify_bundle(&parsed).passed());
    }

    // ── v2 (2b): preimage + audit-path verification ─────────────────────────

    /// An honest v2 trace: `reasoning_hash` is exactly what the public view
    /// hashes to. `audit_path` is filled in by `make_v2_bundle`.
    fn make_v2_trace(hour: u32) -> BundleTrace {
        let view = crate::seal_v2::PublicView {
            trace_id: Uuid::new_v4(),
            latent_fingerprint: "a".repeat(64),
            direction: "short".into(),
            quantity: 1.5,
            notional: 100_000.0,
            asset: "BTC-PERP".into(),
            mta_hash: "b".repeat(64),
            mta_regime_id: 2,
            valid_time: 1_700_000_000_000 + hour as i64,
            txn_time: 1_700_000_000_100 + hour as i64,
            private_commitment: "c".repeat(64),
        };
        let reasoning_hash = view.recompute_reasoning_hash();
        BundleTrace {
            trace_id: view.trace_id,
            agent_id: None,
            reasoning_hash,
            exchange_tx_id: None,
            final_proof: None,
            verification_status: "PENDING".into(),
            valid_time: ts(hour) - chrono::Duration::seconds(5),
            txn_time: ts(hour),
            snapshot_version: 2,
            public_view: Some(view),
            audit_path: None,
        }
    }

    fn make_v2_bundle(mut traces: Vec<BundleTrace>) -> ProofBundle {
        let leaves: Vec<String> = traces.iter().map(|t| t.reasoning_hash.clone()).collect();
        let root = hex::encode(crate::merkle_v2::compute_merkle_root_v2(&leaves));
        for (i, t) in traces.iter_mut().enumerate() {
            t.audit_path = Some(crate::merkle_v2::audit_path(&leaves, i).unwrap());
        }
        let anchor = BundleAnchor {
            period_start: ts(0),
            period_end: ts(23),
            leaf_count: leaves.len() as i32,
            merkle_root: root,
            leaves,
            ots_receipt_base64: None,
            merkle_algo: Some(crate::merkle_v2::MERKLE_ALGO_V2.into()),
        };
        ProofBundle {
            bundle_version: BUNDLE_VERSION,
            generated_at: Utc::now(),
            engine_version: "test".into(),
            period_from: ts(0),
            period_to: ts(23),
            agent_id: None,
            spec: BundleSpec::default(),
            traces,
            anchors: vec![anchor],
        }
    }

    #[test]
    fn honest_v2_bundle_passes_preimage_and_audit_path() {
        let bundle = make_v2_bundle(vec![make_v2_trace(1), make_v2_trace(2), make_v2_trace(3)]);
        let report = verify_bundle(&bundle);
        assert!(report.passed(), "{report:?}");
        assert_eq!(report.preimage_checked, 3);
        assert!(report.preimage_failures.is_empty());
        assert_eq!(report.audit_paths_checked, 3);
        assert_eq!(report.traces_anchored, 3);
    }

    #[test]
    fn tampered_public_view_fails_preimage() {
        // Operator rewrites a disclosed public field but keeps the anchored hash.
        let mut bundle = make_v2_bundle(vec![make_v2_trace(1)]);
        if let Some(view) = bundle.traces[0].public_view.as_mut() {
            view.notional = 999_999.0;
        }
        let report = verify_bundle(&bundle);
        assert!(!report.passed());
        assert_eq!(report.preimage_failures.len(), 1);
    }

    #[test]
    fn v2_trace_without_public_view_fails() {
        // Claims v2 but supplies nothing to recompute from.
        let mut bundle = make_v2_bundle(vec![make_v2_trace(1)]);
        bundle.traces[0].public_view = None;
        let report = verify_bundle(&bundle);
        assert!(!report.passed());
        assert_eq!(report.preimage_failures.len(), 1);
    }

    #[test]
    fn forged_v2_audit_path_fails() {
        let mut bundle = make_v2_bundle(vec![make_v2_trace(1), make_v2_trace(2)]);
        if let Some(path) = bundle.traces[0].audit_path.as_mut() {
            path[0].sibling[0] ^= 0xFF;
        }
        let report = verify_bundle(&bundle);
        assert!(!report.passed());
        assert_eq!(report.audit_path_failures.len(), 1);
    }

    #[test]
    fn v2_bundle_round_trips_through_json() {
        let bundle = make_v2_bundle(vec![make_v2_trace(1), make_v2_trace(2)]);
        let json = serde_json::to_string(&bundle).unwrap();
        let parsed: ProofBundle = serde_json::from_str(&json).unwrap();
        assert!(verify_bundle(&parsed).passed());
    }

    #[test]
    fn mixed_v1_and_v2_anchors_each_verify_under_their_own_algo() {
        // v1 trace under a v1 anchor (hour 1), v2 trace under a v2 anchor (hour 2).
        let v1 = make_trace(1, Some("exch-1"));
        let mut v2 = make_v2_trace(2);

        let v1_leaves = vec![v1.reasoning_hash.clone()];
        let v1_anchor = BundleAnchor {
            period_start: ts(0),
            period_end: ts(1),
            leaf_count: 1,
            merkle_root: hex::encode(compute_merkle_root(&v1_leaves)),
            leaves: v1_leaves,
            ots_receipt_base64: None,
            merkle_algo: None,
        };

        let v2_leaves = vec![v2.reasoning_hash.clone()];
        v2.audit_path = Some(crate::merkle_v2::audit_path(&v2_leaves, 0).unwrap());
        let v2_anchor = BundleAnchor {
            period_start: ts(1),
            period_end: ts(3),
            leaf_count: 1,
            merkle_root: hex::encode(crate::merkle_v2::compute_merkle_root_v2(&v2_leaves)),
            leaves: v2_leaves,
            ots_receipt_base64: None,
            merkle_algo: Some(crate::merkle_v2::MERKLE_ALGO_V2.into()),
        };

        let bundle = ProofBundle {
            bundle_version: BUNDLE_VERSION,
            generated_at: Utc::now(),
            engine_version: "test".into(),
            period_from: ts(0),
            period_to: ts(3),
            agent_id: None,
            spec: BundleSpec::default(),
            traces: vec![v1, v2],
            anchors: vec![v1_anchor, v2_anchor],
        };

        let report = verify_bundle(&bundle);
        assert!(report.passed(), "{report:?}");
        assert_eq!(report.preimage_checked, 1); // only the v2 trace
        assert_eq!(report.audit_paths_checked, 1);
        assert_eq!(report.traces_anchored, 2);
    }
}
