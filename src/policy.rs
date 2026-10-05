use crate::errors::{AppError, PolicyError};
use crate::mta::MtaState;
use crate::snapshot::TradeAction;
use sha2::{Digest, Sha256};

/// Decision produced by a policy evaluation.
#[derive(Debug, Clone)]
pub struct PolicyDecision {
    pub result: PolicyResult,
    pub policy_id: String,
    pub policy_version: String,
    /// SHA-256 of the MTA constraint fields that produced this decision.
    /// Proves exactly which limits were in effect at the time of evaluation.
    pub policy_hash: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PolicyResult {
    Allowed,
    Halted,
    /// Shadow mode: policy would have halted this trade, but enforcement is
    /// suspended. The violation is logged for compliance review without
    /// blocking the agent. Only active when `SHADOW_MODE=true`.
    ShadowHalted,
}

impl std::fmt::Display for PolicyResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyResult::Allowed => write!(f, "ALLOWED"),
            PolicyResult::Halted => write!(f, "HALTED"),
            PolicyResult::ShadowHalted => write!(f, "SHADOW_HALTED"),
        }
    }
}

// ---------------------------------------------------------------------------
// Constraint-based policy engine
//
// IRL does not hardcode per-regime rules.  The MTA operator provides three
// normalized constraint fields with every broadcast:
//
//   allowed_sides       — which trade directions are open ("long"/"short"/"neutral")
//   max_notional_scale  — regime-level multiplier on the agent's configured cap
//   risk_level          — informational (0.0–1.0), stored in the audit trace
//
// The policy engine enforces exactly those two hard limits.  MacroPulse's
// HMM/PCA regime taxonomy is one operator's choice; a firm running a 2-state
// VIX model, a credit-spread classifier, or a GPT-based sentiment regime all
// plug in the same way.
// ---------------------------------------------------------------------------

const POLICY_ID: &str = "IrlConstraintPolicy";
const POLICY_VERSION: &str = "1.0.0";

/// Map a TradeAction to its direction string for allowed_sides comparison.
fn action_side(action: &TradeAction) -> &'static str {
    action.direction()
}

/// Compute a deterministic hash of the active MTA constraints.
/// Stored in PolicyBlock.hash so auditors can reconstruct exactly which
/// constraints governed a given decision.
fn constraint_hash(mta: &MtaState) -> String {
    let mut hasher = Sha256::new();
    hasher.update(mta.regime_id.to_le_bytes());
    hasher.update(b"|");
    hasher.update(mta.version.as_bytes());
    hasher.update(b"|");
    hasher.update(mta.risk_level.to_bits().to_le_bytes());
    hasher.update(b"|");
    hasher.update(mta.max_notional_scale.to_bits().to_le_bytes());
    hasher.update(b"|");
    for side in &mta.allowed_sides {
        hasher.update(side.as_bytes());
        hasher.update(b",");
    }
    hex::encode(hasher.finalize())
}

/// Evaluate whether the action is permitted under the current MTA constraints.
/// Returns a `PolicyDecision` regardless of outcome — both ALLOWED and HALTED
/// are recorded in the audit log.
///
/// `agent_notional_cap` is the agent's per-profile hard ceiling from MAR.
/// The effective limit is `agent_notional_cap × mta.max_notional_scale`.
pub fn evaluate(
    mta: &MtaState,
    action: &TradeAction,
    notional: f64,
    agent_notional_cap: f64,
    reduce_only: bool,
) -> PolicyDecision {
    let hash = constraint_hash(mta);
    let base = PolicyDecision {
        result: PolicyResult::Allowed,
        policy_id: POLICY_ID.to_string(),
        policy_version: POLICY_VERSION.to_string(),
        policy_hash: hash.clone(),
    };
    match check_constraints(mta, action, notional, agent_notional_cap, reduce_only) {
        Ok(()) => base,
        Err(_) => PolicyDecision {
            result: PolicyResult::Halted,
            ..base
        },
    }
}

/// Same as `evaluate` but returns `AppError` when the action is halted.
/// Use this in the authorization flow where a halt must abort the request.
///
/// `reduce_only` bypasses the `allowed_sides` direction check — a trader must
/// always be able to exit an existing position regardless of the current regime.
/// The notional cap is still enforced: a reduce-only order cannot exceed the
/// agent's effective cap (closing a 10 BTC position requires notional ≤ cap).
pub fn enforce(
    mta: &MtaState,
    action: &TradeAction,
    notional: f64,
    agent_notional_cap: f64,
    reduce_only: bool,
) -> Result<PolicyDecision, AppError> {
    check_constraints(mta, action, notional, agent_notional_cap, reduce_only)?;
    Ok(PolicyDecision {
        result: PolicyResult::Allowed,
        policy_id: POLICY_ID.to_string(),
        policy_version: POLICY_VERSION.to_string(),
        policy_hash: constraint_hash(mta),
    })
}

fn check_constraints(
    mta: &MtaState,
    action: &TradeAction,
    notional: f64,
    agent_notional_cap: f64,
    reduce_only: bool,
) -> Result<(), AppError> {
    // 1. Direction check — bypassed for reduce_only orders.
    //    Traders must always be able to close positions even during kill-switch.
    if !reduce_only {
        let side = action_side(action);
        let side_allowed = mta
            .allowed_sides
            .iter()
            .any(|s| s.eq_ignore_ascii_case(side));

        if !side_allowed {
            return Err(AppError::Policy(PolicyError::RegimeViolation {
                action: action.to_string(),
                regime: mta.regime_label.clone(),
                policy: POLICY_ID.to_string(),
                version: POLICY_VERSION.to_string(),
            }));
        }
    }

    // 2. Notional check — always enforced, including for reduce_only.
    //    If max_notional_scale == 0.0 the effective cap is zero.
    let effective_cap = agent_notional_cap * mta.max_notional_scale;
    if notional > effective_cap {
        return Err(AppError::Policy(PolicyError::NotionalExceedsLimit {
            notional,
            limit: effective_cap,
            regime: mta.regime_label.clone(),
            policy: POLICY_ID.to_string(),
        }));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mta::mock_mta;
    use crate::snapshot::TradeAction;

    fn fully_open() -> MtaState {
        mock_mta(0, "expansion", 1.0, 1.0, vec!["long", "short", "neutral"])
    }

    fn short_only() -> MtaState {
        mock_mta(2, "tightening", 0.3, 0.25, vec!["short", "neutral"])
    }

    fn locked() -> MtaState {
        mock_mta(3, "risk_off", 0.0, 0.0, vec!["neutral"])
    }

    const CAP: f64 = 1_000_000.0;

    #[test]
    fn allowed_side_passes() {
        let mta = fully_open();
        assert!(enforce(&mta, &TradeAction::Long(1.0), 100_000.0, CAP, false).is_ok());
        assert!(enforce(&mta, &TradeAction::Short(1.0), 100_000.0, CAP, false).is_ok());
        assert!(enforce(&mta, &TradeAction::Neutral, 0.0, CAP, false).is_ok());
    }

    #[test]
    fn blocked_side_returns_error() {
        let mta = short_only();
        assert!(enforce(&mta, &TradeAction::Long(1.0), 50_000.0, CAP, false).is_err());
        assert!(enforce(&mta, &TradeAction::Short(1.0), 50_000.0, CAP, false).is_ok());
        assert!(enforce(&mta, &TradeAction::Neutral, 0.0, CAP, false).is_ok());
    }

    #[test]
    fn notional_within_scaled_cap_passes() {
        // scale = 0.25, cap = 1_000_000 → effective = 250_000
        let mta = short_only();
        assert!(enforce(&mta, &TradeAction::Short(1.0), 250_000.0, CAP, false).is_ok());
    }

    #[test]
    fn notional_exceeds_scaled_cap_returns_error() {
        let mta = short_only();
        assert!(enforce(&mta, &TradeAction::Short(1.0), 250_001.0, CAP, false).is_err());
    }

    #[test]
    fn zero_scale_blocks_all_nonzero_notional() {
        let mta = locked();
        assert!(enforce(&mta, &TradeAction::Neutral, 1.0, CAP, false).is_err());
        assert!(enforce(&mta, &TradeAction::Neutral, 0.0, CAP, false).is_ok());
    }

    #[test]
    fn empty_allowed_sides_blocks_all() {
        let mta = mock_mta(99, "blackout", 0.0, 0.0, vec![]);
        assert!(enforce(&mta, &TradeAction::Long(1.0), 0.0, CAP, false).is_err());
        assert!(enforce(&mta, &TradeAction::Short(1.0), 0.0, CAP, false).is_err());
        assert!(enforce(&mta, &TradeAction::Neutral, 0.0, CAP, false).is_err());
    }

    #[test]
    fn evaluate_returns_halted_without_error() {
        let mta = short_only();
        let decision = evaluate(&mta, &TradeAction::Long(1.0), 50_000.0, CAP, false);
        assert_eq!(decision.result, PolicyResult::Halted);
        assert_eq!(decision.policy_id, POLICY_ID);
    }

    #[test]
    fn enforce_returns_error_on_halt() {
        let mta = short_only();
        let result = enforce(&mta, &TradeAction::Long(1.0), 50_000.0, CAP, false);
        assert!(matches!(result, Err(AppError::Policy(_))));
    }

    #[test]
    fn constraint_hash_is_deterministic() {
        let mta = fully_open();
        assert_eq!(constraint_hash(&mta), constraint_hash(&mta));
    }

    #[test]
    fn constraint_hash_differs_across_regimes() {
        let a = fully_open();
        let b = locked();
        assert_ne!(constraint_hash(&a), constraint_hash(&b));
    }

    #[test]
    fn reduce_only_bypasses_direction_check() {
        // risk_off regime: only "neutral" allowed.
        // A long reduce_only order must still be permitted (closing a position).
        let mta = locked();
        assert!(enforce(&mta, &TradeAction::Long(1.0), 0.0, CAP, true).is_ok());
        assert!(enforce(&mta, &TradeAction::Short(1.0), 0.0, CAP, true).is_ok());
        // Notional cap is still enforced even for reduce_only.
        // locked() has max_notional_scale = 0.0, so effective_cap = 0.0 — any notional > 0 is blocked.
        assert!(enforce(&mta, &TradeAction::Long(1.0), 1.0, CAP, true).is_err());
    }

    #[test]
    fn reduce_only_with_nonzero_cap_passes_notional() {
        // fully_open has max_notional_scale = 1.0, so cap is unchanged.
        let mta = fully_open();
        assert!(enforce(&mta, &TradeAction::Long(1.0), CAP, CAP, true).is_ok());
        assert!(enforce(&mta, &TradeAction::Long(1.0), CAP + 1.0, CAP, true).is_err());
    }

    #[test]
    fn case_insensitive_side_matching() {
        let mta = mock_mta(0, "custom", 1.0, 1.0, vec!["Long", "SHORT", "Neutral"]);
        assert!(enforce(&mta, &TradeAction::Long(1.0), 0.0, CAP, false).is_ok());
        assert!(enforce(&mta, &TradeAction::Short(1.0), 0.0, CAP, false).is_ok());
    }
}
