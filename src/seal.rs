use crate::errors::AppError;
use crate::snapshot::CognitiveSnapshot;
use sha2::{Digest, Sha256};

/// Enforce the bitemporal invariant: valid_time must be strictly before txn_time.
///
/// This kills:
/// - Hindsight bias (agent couldn't have reasoned about a future regime)
/// - Data revision attacks ("we logged it after we knew the outcome")
pub fn verify_bitemporal(snapshot: &CognitiveSnapshot) -> Result<(), AppError> {
    if snapshot.valid_time >= snapshot.txn_time {
        return Err(AppError::BiTemporalViolation);
    }
    Ok(())
}

/// Produce a deterministic, canonical SHA-256 hash of the CognitiveSnapshot.
///
/// Uses RFC 8785 JSON Canonicalization Scheme (sorted keys, no whitespace)
/// instead of standard `serde_json::to_string()` which does NOT guarantee
/// field order across crate versions or struct changes.
///
/// This is critical for long-term audit integrity: the same snapshot must
/// produce the same hash regardless of when or where it is recomputed.
pub fn seal(snapshot: &CognitiveSnapshot) -> Result<String, AppError> {
    let value =
        serde_json::to_value(snapshot).map_err(|e| AppError::Serialization(e.to_string()))?;

    let canonical = canonicalize_json(&value)?;

    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    Ok(hex::encode(hasher.finalize()))
}

/// Compute the final proof that binds reasoning to a specific exchange execution.
///
/// final_proof = SHA-256(reasoning_hash || "||" || exchange_tx_id)
///
/// Once this is computed, the chain is complete:
///   Agent Reasoning → IRL Snapshot → Exchange Order
pub fn compute_final_proof(reasoning_hash: &str, exchange_tx_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(reasoning_hash.as_bytes());
    hasher.update(b"||");
    hasher.update(exchange_tx_id.as_bytes());
    hex::encode(hasher.finalize())
}

/// RFC 8785 JSON Canonicalization: sort object keys recursively, no whitespace.
/// This is deterministic across all serde_json versions and struct field orderings.
fn canonicalize_json(value: &serde_json::Value) -> Result<String, AppError> {
    use serde_json::Value;
    match value {
        Value::Object(map) => {
            let mut sorted: Vec<(&String, &Value)> = map.iter().collect();
            sorted.sort_by_key(|(k, _)| *k);
            let inner = sorted
                .into_iter()
                .map(|(k, v)| {
                    let key = serde_json::to_string(k)
                        .map_err(|e| AppError::Serialization(e.to_string()))?;
                    let val = canonicalize_json(v)?;
                    Ok(format!("{key}:{val}"))
                })
                .collect::<Result<Vec<_>, AppError>>()?
                .join(",");
            Ok(format!("{{{inner}}}"))
        }
        Value::Array(arr) => {
            let inner = arr
                .iter()
                .map(canonicalize_json)
                .collect::<Result<Vec<_>, AppError>>()?
                .join(",");
            Ok(format!("[{inner}]"))
        }
        other => serde_json::to_string(other).map_err(|e| AppError::Serialization(e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heartbeat::SignedHeartbeat;
    use crate::snapshot::{CognitiveSnapshot, ExecutionIntent, TradeAction};
    use uuid::Uuid;

    fn make_snapshot(valid_time: i64, txn_time: i64) -> CognitiveSnapshot {
        CognitiveSnapshot {
            trace_id: Uuid::new_v4(),
            mta_regime_id: 2,
            mta_version: "hmm-v3.1".into(),
            mta_hash: "0xabc".into(),
            latent_fingerprint: "0xdef".into(),
            feature_schema_id: "schema-test".into(),
            execution: ExecutionIntent {
                action: TradeAction::Short(1.5),
                asset: "BTC-PERP".into(),
                order_type: crate::snapshot::OrderType::Market,
                venue_id: "XNAS".into(),
                quantity: 1.5,
                notional: 100_000.0,
                notional_currency: "USD".into(),
                multiplier: 1.0,
                limit_price: None,
                stop_price: None,
                client_order_id: "order-1".into(),
            },
            valid_time,
            txn_time,
            heartbeat: SignedHeartbeat {
                sequence_id: 1,
                timestamp_ms: valid_time as u64,
                regime_id: 2,
                mta_ref: "0xmockref".to_string(),
                signature: vec![],
            },
        }
    }

    #[test]
    fn bitemporal_valid() {
        let snap = make_snapshot(1000, 1001);
        assert!(verify_bitemporal(&snap).is_ok());
    }

    #[test]
    fn bitemporal_rejects_equal_timestamps() {
        let snap = make_snapshot(1000, 1000);
        assert!(matches!(
            verify_bitemporal(&snap),
            Err(AppError::BiTemporalViolation)
        ));
    }

    #[test]
    fn bitemporal_rejects_future_valid_time() {
        let snap = make_snapshot(2000, 1000);
        assert!(matches!(
            verify_bitemporal(&snap),
            Err(AppError::BiTemporalViolation)
        ));
    }

    #[test]
    fn seal_is_deterministic() {
        let snap = make_snapshot(1000, 1001);
        let h1 = seal(&snap).unwrap();
        let h2 = seal(&snap).unwrap();
        assert_eq!(h1, h2, "Same snapshot must produce same hash");
    }

    #[test]
    fn seal_changes_on_mutation() {
        let mut snap = make_snapshot(1000, 1001);
        let h1 = seal(&snap).unwrap();
        snap.mta_regime_id = 3;
        let h2 = seal(&snap).unwrap();
        assert_ne!(h1, h2, "Different data must produce different hash");
    }

    #[test]
    fn final_proof_is_deterministic() {
        let p1 = compute_final_proof("0xabc", "exch-123");
        let p2 = compute_final_proof("0xabc", "exch-123");
        assert_eq!(p1, p2);
    }

    #[test]
    fn final_proof_is_unique() {
        let p1 = compute_final_proof("0xabc", "exch-123");
        let p2 = compute_final_proof("0xabc", "exch-456");
        assert_ne!(p1, p2);
    }
}
