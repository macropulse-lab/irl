//! T-1.0 / T-1.1 — split public/private commitment sealing over the real
//! [`CognitiveSnapshot`].
//!
//! This is an **additive** module. It does not modify [`crate::seal`]; existing
//! traces keep sealing via `seal::seal` (recorded as `snapshot_version = 1`).
//! New traces that opt into v2 seal via [`seal_v2`] (recorded as
//! `snapshot_version = 2`). The verifier handles both.
//!
//! # Why the two-level commitment
//! Sealing over a *public-only* field set would leave the private fields
//! (`venue_id`, `client_order_id`, prices, heartbeat, …) unbound by the hash —
//! an operator could rewrite them post-hoc without breaking verification. That
//! is the exact tamper gap the audit chain exists to close.
//!
//! Fix — bind everything, disclose nothing:
//! ```text
//! private_commitment = SHA256( canonical(private_fields) )
//! reasoning_hash     = SHA256( canonical(public_fields ∪ {private_commitment}) )
//! ```
//! An auditor recomputes `reasoning_hash` from the public fields plus the opaque
//! `private_commitment` — no access to the raw private values required. Full
//! disclosure (litigation / regulator) reveals the private fields so the
//! auditor can recompute the commitment; the seal never has to change.
//!
//! The public field set carries NO order size/venue/id detail that would leak
//! trading intent beyond what the agent already discloses at bind time: it is
//! `latent_fingerprint`, `direction`, `quantity`, `notional`, `asset`,
//! `mta_hash`, `mta_regime_id`, and the bitemporal timestamps.

use crate::errors::AppError;
use crate::snapshot::CognitiveSnapshot;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// Snapshot format version recorded on every trace so the verifier knows which
/// seal construction to reproduce. v1 = whole-snapshot seal ([`crate::seal`]).
pub const SNAPSHOT_VERSION_V2: i16 = 2;

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// RFC 8785 canonical JSON — identical construction to
/// [`crate::seal`]'s canonicalizer (sorted keys, no whitespace), duplicated
/// here so this module stays fully decoupled from `seal.rs`.
fn canonicalize(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let mut sorted: Vec<(&String, &Value)> = map.iter().collect();
            sorted.sort_by_key(|(k, _)| *k);
            let inner = sorted
                .into_iter()
                .map(|(k, v)| {
                    let key = serde_json::to_string(k).expect("string key serializes");
                    format!("{key}:{}", canonicalize(v))
                })
                .collect::<Vec<_>>()
                .join(",");
            format!("{{{inner}}}")
        }
        Value::Array(arr) => {
            let inner = arr.iter().map(canonicalize).collect::<Vec<_>>().join(",");
            format!("[{inner}]")
        }
        other => serde_json::to_string(other).expect("scalar serializes"),
    }
}

/// The private field group — only its SHA-256 commitment is published.
fn private_value(s: &CognitiveSnapshot) -> Value {
    json!({
        "client_order_id": s.execution.client_order_id,
        "venue_id": s.execution.venue_id,
        "order_type": s.execution.order_type.to_string(),
        "notional_currency": s.execution.notional_currency,
        "multiplier": s.execution.multiplier,
        "limit_price": s.execution.limit_price,
        "stop_price": s.execution.stop_price,
        "feature_schema_id": s.feature_schema_id,
        "mta_version": s.mta_version,
        "heartbeat_seq": s.heartbeat.sequence_id,
        "heartbeat_ts_ms": s.heartbeat.timestamp_ms,
        "heartbeat_regime_id": s.heartbeat.regime_id,
        "heartbeat_mta_ref": s.heartbeat.mta_ref,
        "heartbeat_sig_hex": hex::encode(&s.heartbeat.signature),
    })
}

/// The public field group, with the private commitment folded in. This is the
/// exact preimage of `reasoning_hash`.
fn public_value(s: &CognitiveSnapshot, private_commitment: &str) -> Value {
    json!({
        "trace_id": s.trace_id,
        "latent_fingerprint": s.latent_fingerprint,
        "direction": s.execution.action.direction(),
        "quantity": s.execution.quantity,
        "notional": s.execution.notional,
        "asset": s.execution.asset,
        "mta_hash": s.mta_hash,
        "mta_regime_id": s.mta_regime_id,
        "valid_time": s.valid_time,
        "txn_time": s.txn_time,
        "private_commitment": private_commitment,
    })
}

/// SHA-256 over the canonical private field group.
pub fn private_commitment(s: &CognitiveSnapshot) -> String {
    sha256_hex(canonicalize(&private_value(s)).as_bytes())
}

/// v2 seal: `reasoning_hash = SHA256(canonical(public ∪ private_commitment))`.
pub fn seal_v2(s: &CognitiveSnapshot) -> Result<String, AppError> {
    let commitment = private_commitment(s);
    Ok(sha256_hex(
        canonicalize(&public_value(s, &commitment)).as_bytes(),
    ))
}

/// The public view shipped in a proof bundle: every public field plus the
/// opaque commitment — never the raw private values. Recomputing
/// `reasoning_hash` from this alone must reproduce the anchored value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicView {
    pub trace_id: uuid::Uuid,
    pub latent_fingerprint: String,
    pub direction: String,
    pub quantity: f64,
    pub notional: f64,
    pub asset: String,
    pub mta_hash: String,
    pub mta_regime_id: u8,
    pub valid_time: i64,
    pub txn_time: i64,
    pub private_commitment: String,
}

impl PublicView {
    /// Derive the public view from a full snapshot (operator side, at export).
    pub fn from_snapshot(s: &CognitiveSnapshot) -> Self {
        Self {
            trace_id: s.trace_id,
            latent_fingerprint: s.latent_fingerprint.clone(),
            direction: s.execution.action.direction().to_string(),
            quantity: s.execution.quantity,
            notional: s.execution.notional,
            asset: s.execution.asset.clone(),
            mta_hash: s.mta_hash.clone(),
            mta_regime_id: s.mta_regime_id,
            valid_time: s.valid_time,
            txn_time: s.txn_time,
            private_commitment: private_commitment(s),
        }
    }

    /// Recompute `reasoning_hash` from the disclosed public view alone
    /// (auditor side, offline). No raw private values required.
    pub fn recompute_reasoning_hash(&self) -> String {
        let v = json!({
            "trace_id": self.trace_id,
            "latent_fingerprint": self.latent_fingerprint,
            "direction": self.direction,
            "quantity": self.quantity,
            "notional": self.notional,
            "asset": self.asset,
            "mta_hash": self.mta_hash,
            "mta_regime_id": self.mta_regime_id,
            "valid_time": self.valid_time,
            "txn_time": self.txn_time,
            "private_commitment": self.private_commitment,
        });
        sha256_hex(canonicalize(&v).as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heartbeat::SignedHeartbeat;
    use crate::snapshot::{CognitiveSnapshot, ExecutionIntent, OrderType, TradeAction};
    use uuid::Uuid;

    fn snapshot() -> CognitiveSnapshot {
        CognitiveSnapshot {
            trace_id: Uuid::from_u128(0x1234),
            mta_regime_id: 2,
            mta_version: "hmm-v3.1".into(),
            mta_hash: "b".repeat(64),
            latent_fingerprint: "a".repeat(64),
            feature_schema_id: "schema-7".into(),
            execution: ExecutionIntent {
                action: TradeAction::Short(1.5),
                asset: "BTC-PERP".into(),
                order_type: OrderType::Market,
                venue_id: "XNAS".into(),
                quantity: 1.5,
                notional: 100_000.0,
                notional_currency: "USD".into(),
                multiplier: 1.0,
                limit_price: None,
                stop_price: None,
                client_order_id: "order-1".into(),
            },
            valid_time: 1_700_000_000_000,
            txn_time: 1_700_000_000_100,
            heartbeat: SignedHeartbeat {
                sequence_id: 42,
                timestamp_ms: 1_700_000_000_000,
                regime_id: 2,
                mta_ref: "0xref".into(),
                signature: vec![0u8; 64],
            },
        }
    }

    #[test]
    fn seal_is_deterministic() {
        let s = snapshot();
        assert_eq!(seal_v2(&s).unwrap(), seal_v2(&s).unwrap());
    }

    #[test]
    fn public_field_change_breaks_seal() {
        let s = snapshot();
        let mut t = snapshot();
        t.execution.notional = 250_000.0;
        assert_ne!(seal_v2(&s).unwrap(), seal_v2(&t).unwrap());
    }

    #[test]
    fn private_field_change_breaks_seal_via_commitment() {
        // The crux of T-1.0: a PRIVATE-only change must still move reasoning_hash.
        let s = snapshot();
        let mut t = snapshot();
        t.execution.venue_id = "DARKPOOL-X".into();
        assert_ne!(private_commitment(&s), private_commitment(&t));
        assert_ne!(seal_v2(&s).unwrap(), seal_v2(&t).unwrap());
    }

    #[test]
    fn auditor_recomputes_from_public_view_only() {
        let s = snapshot();
        assert_eq!(
            PublicView::from_snapshot(&s).recompute_reasoning_hash(),
            seal_v2(&s).unwrap()
        );
    }

    #[test]
    fn tampered_public_view_fails_to_reproduce_hash() {
        // Operator rewrites a disclosed public field but keeps the anchored hash.
        let s = snapshot();
        let anchored = seal_v2(&s).unwrap();
        let mut view = PublicView::from_snapshot(&s);
        view.notional = 999_999.0;
        assert_ne!(view.recompute_reasoning_hash(), anchored);
    }
}
