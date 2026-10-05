use crate::asset;
use crate::seal::compute_final_proof;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// Full lifecycle of a reasoning trace — whitepaper v3 §11.2.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub enum VerificationStatus {
    /// Intent sealed, pre-auth token issued, awaiting exchange confirmation.
    Pending,
    /// Exchange confirmed; asset/side/size within tolerance.
    Matched,
    /// Exchange confirmed; one or more parameters differ from authorized intent.
    Divergent,
    /// Exchange report received with no corresponding IRL intent.
    Orphan,
    /// No exchange confirmation received within the timeout window.
    Expired,
    /// Legacy alias for Divergent (kept for backward compatibility).
    Mismatch,
}

impl std::fmt::Display for VerificationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerificationStatus::Pending => write!(f, "PENDING"),
            VerificationStatus::Matched => write!(f, "MATCHED"),
            VerificationStatus::Divergent => write!(f, "DIVERGENT"),
            VerificationStatus::Orphan => write!(f, "ORPHAN"),
            VerificationStatus::Expired => write!(f, "EXPIRED"),
            VerificationStatus::Mismatch => write!(f, "MISMATCH"),
        }
    }
}

/// What actually happened at the exchange after the trade was sent.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub enum ExecutionStatus {
    Filled,
    Rejected,
    Partial,
}

impl std::fmt::Display for ExecutionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExecutionStatus::Filled => write!(f, "FILLED"),
            ExecutionStatus::Rejected => write!(f, "REJECTED"),
            ExecutionStatus::Partial => write!(f, "PARTIAL"),
        }
    }
}

/// Request body for POST /irl/bind-execution.
/// Called by the agent after receiving the exchange confirmation.
#[derive(Debug, Deserialize, ToSchema)]
pub struct BindExecutionRequest {
    pub trace_id: Uuid,
    pub exchange_tx_id: String,
    pub execution_status: ExecutionStatus,
    /// Asset actually traded (for mismatch detection).
    pub asset: Option<String>,
    /// Quantity actually executed (for tolerance check).
    pub executed_quantity: Option<f64>,
    /// Execution price at the exchange (for forensic PnL correlation).
    pub execution_price: Option<f64>,
    /// Trade direction as reported by the exchange: "Long" or "Short".
    /// Optional — if provided, verified against the authorized intent to detect
    /// side mismatches (e.g. Long authorized but Short executed). Omit if the
    /// exchange does not return direction in the fill report.
    #[serde(default)]
    pub executed_side: Option<String>,
    /// Unix milliseconds of the actual exchange fill.
    /// Optional — if provided, stored as execution_time for accurate PnL timestamps.
    /// Defaults to IRL wall clock at bind time if not supplied.
    #[serde(default)]
    pub execution_time_ms: Option<i64>,
}

/// The result of binding a reasoning trace to an exchange execution.
#[derive(Debug, Serialize, ToSchema)]
pub struct BindExecutionResult {
    pub trace_id: Uuid,
    /// SHA-256(reasoning_hash || "||" || exchange_tx_id).
    /// This is the terminal proof that closes the chain:
    ///   Agent Reasoning → IRL Snapshot → Exchange Order
    pub final_proof: String,
    pub verification_status: VerificationStatus,
    pub execution_status: String,
    pub execution_time: DateTime<Utc>,
    /// Non-None when verification_status is Divergent — explains what differed.
    pub divergence_reason: Option<String>,
}

/// Default size tolerance: 0.01% — configurable via BIND_SIZE_TOLERANCE env var.
pub const DEFAULT_SIZE_TOLERANCE: f64 = 0.0001;

/// Resolve a stored action string to a canonical direction for side-check comparison.
/// Mirrors TradeAction::direction() for strings retrieved from the DB.
fn resolve_direction(action: &str) -> &'static str {
    let lower = action.to_ascii_lowercase();
    let lower = lower.trim();
    if lower.starts_with("long")
        || lower.starts_with("buy")
        || lower.contains("open_long")
        || lower == "open"
    {
        return "long";
    }
    if lower.starts_with("short")
        || lower.starts_with("sell")
        || lower.contains("close_short")
        || lower == "close"
        || lower == "exit"
        || lower == "reverse"
    {
        return "short";
    }
    "neutral"
}

/// Reconcile an exchange execution report against the authorized intent.
///
/// §11.3 reconciliation logic:
/// 1. Asset check         — any mismatch                   → Divergent
/// 2. Side check          — Long↔Short direction mismatch  → Divergent
/// 3. Quantity tolerance  — delta > tolerance              → Divergent
/// 4. All checks pass                                      → Matched
///
/// Check 2 is only applied when `req.executed_side` is provided. Agents should
/// populate this field from the exchange fill report where available. Omitting
/// it is safe (no check performed) but reduces forensic coverage.
pub fn reconcile(
    trace_id: Uuid,
    reasoning_hash: &str,
    req: &BindExecutionRequest,
    intent_asset: &str,
    intent_action: &str,
    intent_quantity: f64,
    size_tolerance: f64,
) -> BindExecutionResult {
    let final_proof = compute_final_proof(reasoning_hash, &req.exchange_tx_id);

    // Use exchange-reported fill time if supplied; fall back to IRL wall clock.
    let execution_time = req
        .execution_time_ms
        .and_then(|ms| chrono::TimeZone::timestamp_millis_opt(&Utc, ms).single())
        .unwrap_or_else(Utc::now);

    // 1. Asset mismatch check — uses alias map so "AAPL" matches "AAPL.USD" etc.
    if let Some(ref exec_asset) = req.asset {
        if !asset::assets_match(exec_asset, intent_asset) {
            return BindExecutionResult {
                trace_id,
                final_proof,
                verification_status: VerificationStatus::Divergent,
                execution_status: req.execution_status.to_string(),
                execution_time,
                divergence_reason: Some(format!(
                    "Asset mismatch: authorized {intent_asset}, executed {exec_asset}"
                )),
            };
        }
    }

    // 2. Side mismatch check — only applied when the agent reports executed_side.
    //
    //    Resolves canonical direction using the same keyword logic as
    //    TradeAction::direction() so Custom actions ("Buy", "Open Long", etc.)
    //    are handled consistently.
    if let Some(ref exec_side) = req.executed_side {
        let intent_side = resolve_direction(intent_action);
        if !exec_side.eq_ignore_ascii_case(intent_side) {
            return BindExecutionResult {
                trace_id,
                final_proof,
                verification_status: VerificationStatus::Divergent,
                execution_status: req.execution_status.to_string(),
                execution_time,
                divergence_reason: Some(format!(
                    "Side mismatch: authorized {intent_side}, executed {exec_side}"
                )),
            };
        }
    }

    // 3. Quantity tolerance check.
    if let Some(executed_qty) = req.executed_quantity {
        if intent_quantity > 0.0 {
            let delta = (intent_quantity - executed_qty).abs();
            if delta > intent_quantity * size_tolerance {
                return BindExecutionResult {
                    trace_id,
                    final_proof,
                    verification_status: VerificationStatus::Divergent,
                    execution_status: req.execution_status.to_string(),
                    execution_time,
                    divergence_reason: Some(format!(
                        "Quantity outside tolerance: authorized {intent_quantity:.4}, \
                         executed {executed_qty:.4}, delta {delta:.4}"
                    )),
                };
            }
        }
    }

    BindExecutionResult {
        trace_id,
        final_proof,
        verification_status: VerificationStatus::Matched,
        execution_status: req.execution_status.to_string(),
        execution_time,
        divergence_reason: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_req(exchange_tx_id: &str) -> BindExecutionRequest {
        BindExecutionRequest {
            trace_id: Uuid::new_v4(),
            exchange_tx_id: exchange_tx_id.to_string(),
            execution_status: ExecutionStatus::Filled,
            asset: Some("BTC-PERP".to_string()),
            executed_quantity: Some(1.5),
            execution_price: Some(67450.25),
            executed_side: None,
            execution_time_ms: None,
        }
    }

    #[test]
    fn matched_when_asset_and_quantity_match() {
        let id = Uuid::new_v4();
        let req = make_req("exch-0x123");
        let result = reconcile(
            id,
            "0xhash",
            &req,
            "BTC-PERP",
            "Short(1.5)",
            1.5,
            DEFAULT_SIZE_TOLERANCE,
        );
        assert_eq!(result.verification_status, VerificationStatus::Matched);
        assert!(result.divergence_reason.is_none());
    }

    #[test]
    fn divergent_on_asset_mismatch() {
        let id = Uuid::new_v4();
        let req = make_req("exch-0x456");
        let result = reconcile(
            id,
            "0xhash",
            &req,
            "ETH-PERP",
            "Short(1.5)",
            1.5,
            DEFAULT_SIZE_TOLERANCE,
        );
        assert_eq!(result.verification_status, VerificationStatus::Divergent);
        assert!(result.divergence_reason.unwrap().contains("Asset mismatch"));
    }

    #[test]
    fn divergent_on_quantity_outside_tolerance() {
        let id = Uuid::new_v4();
        let mut req = make_req("exch-0x789");
        req.executed_quantity = Some(2.0); // 33% diff vs 1.5
        let result = reconcile(
            id,
            "0xhash",
            &req,
            "BTC-PERP",
            "Short(1.5)",
            1.5,
            DEFAULT_SIZE_TOLERANCE,
        );
        assert_eq!(result.verification_status, VerificationStatus::Divergent);
    }

    #[test]
    fn final_proof_changes_with_different_tx() {
        let id = Uuid::new_v4();
        let r1 = reconcile(
            id,
            "0xhash",
            &make_req("tx-1"),
            "BTC-PERP",
            "Short",
            1.5,
            DEFAULT_SIZE_TOLERANCE,
        );
        let r2 = reconcile(
            id,
            "0xhash",
            &make_req("tx-2"),
            "BTC-PERP",
            "Short",
            1.5,
            DEFAULT_SIZE_TOLERANCE,
        );
        assert_ne!(r1.final_proof, r2.final_proof);
    }

    #[test]
    fn divergent_on_side_mismatch() {
        let id = Uuid::new_v4();
        let mut req = make_req("exch-0xside");
        req.executed_side = Some("short".to_string());
        // Authorized as Long; exchange reports Short → DIVERGENT
        let result = reconcile(
            id,
            "0xhash",
            &req,
            "BTC-PERP",
            "Long(1.5)",
            1.5,
            DEFAULT_SIZE_TOLERANCE,
        );
        assert_eq!(result.verification_status, VerificationStatus::Divergent);
        assert!(result.divergence_reason.unwrap().contains("Side mismatch"));
    }

    #[test]
    fn matched_when_side_matches() {
        let id = Uuid::new_v4();
        let mut req = make_req("exch-0xmatch");
        req.executed_side = Some("Long".to_string()); // case-insensitive
        let result = reconcile(
            id,
            "0xhash",
            &req,
            "BTC-PERP",
            "Long(1.5)",
            1.5,
            DEFAULT_SIZE_TOLERANCE,
        );
        assert_eq!(result.verification_status, VerificationStatus::Matched);
    }

    #[test]
    fn side_check_skipped_when_not_provided() {
        // Without executed_side, no side check is performed (backward compatible).
        let id = Uuid::new_v4();
        let req = make_req("exch-0xnoside"); // executed_side defaults to None
        let result = reconcile(
            id,
            "0xhash",
            &req,
            "BTC-PERP",
            "Long(1.5)",
            1.5,
            DEFAULT_SIZE_TOLERANCE,
        );
        assert_eq!(result.verification_status, VerificationStatus::Matched);
    }

    #[test]
    fn final_proof_is_deterministic() {
        let id = Uuid::new_v4();
        let r1 = reconcile(
            id,
            "0xhash",
            &make_req("tx-1"),
            "BTC-PERP",
            "Short",
            1.5,
            DEFAULT_SIZE_TOLERANCE,
        );
        let r2 = reconcile(
            id,
            "0xhash",
            &make_req("tx-1"),
            "BTC-PERP",
            "Short",
            1.5,
            DEFAULT_SIZE_TOLERANCE,
        );
        assert_eq!(r1.final_proof, r2.final_proof);
    }
}
