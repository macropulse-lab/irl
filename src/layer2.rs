//! Layer 2 regime binding (design: `docs/design/layer2-v2.md`).
//!
//! - `Legacy`: every authorize carries an MTA-signed heartbeat that must be
//!   younger than `MAX_HEARTBEAT_DRIFT_MS` (a cross-service wall-clock window).
//! - `V2`: the agent sends `mta_ref`, the regime reference returned by
//!   `GET /irl/regime`. IRL checks it against its own verified MTA state,
//!   accepting the previous reference for a grace window after a regime
//!   change. Replay protection is the unique `(agent_id, client_order_id)`
//!   intent key instead of heartbeat sequence numbers.
//! - `Both` (migration default): a request with `mta_ref` takes the v2 path,
//!   otherwise a heartbeat takes the legacy path.

use crate::errors::HeartbeatError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layer2Mode {
    Legacy,
    V2,
    Both,
}

impl Layer2Mode {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "legacy" => Some(Self::Legacy),
            "v2" => Some(Self::V2),
            "both" => Some(Self::Both),
            _ => None,
        }
    }
}

/// How a single authorize request is bound to the regime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum L2Path {
    /// Layer 2 disabled (development only).
    Off,
    /// Legacy signed heartbeat.
    Heartbeat,
    /// v2 regime reference, as supplied by the agent.
    RegimeRef(String),
}

/// Pure: choose the Layer 2 path from configuration and what the request carries.
pub fn select_path(
    enabled: bool,
    mode: Layer2Mode,
    mta_ref: Option<&str>,
    has_heartbeat: bool,
) -> Result<L2Path, HeartbeatError> {
    if !enabled {
        return Ok(L2Path::Off);
    }
    let mta_ref = mta_ref.map(str::trim).filter(|r| !r.is_empty());
    match (mode, mta_ref, has_heartbeat) {
        (Layer2Mode::Legacy, _, true) => Ok(L2Path::Heartbeat),
        (Layer2Mode::V2 | Layer2Mode::Both, Some(r), _) => Ok(L2Path::RegimeRef(r.to_string())),
        (Layer2Mode::Both, None, true) => Ok(L2Path::Heartbeat),
        _ => Err(HeartbeatError::Missing),
    }
}

/// Pure: is `given` an acceptable regime reference right now?
///
/// The current verified reference is always accepted. The reference it
/// replaced is accepted for `grace_secs` after the change, so an agent that
/// fetched `GET /irl/regime` just before a regime update is not rejected.
pub fn ref_accepted(
    given: &str,
    current: &str,
    previous: Option<(&str, u64)>,
    now_ms: u64,
    grace_secs: u64,
) -> bool {
    if given == current {
        return true;
    }
    match previous {
        Some((prev, replaced_at_ms)) => {
            given == prev && now_ms.saturating_sub(replaced_at_ms) <= grace_secs * 1000
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_modes_case_insensitively() {
        assert_eq!(Layer2Mode::parse("V2"), Some(Layer2Mode::V2));
        assert_eq!(Layer2Mode::parse(" both "), Some(Layer2Mode::Both));
        assert_eq!(Layer2Mode::parse("legacy"), Some(Layer2Mode::Legacy));
        assert_eq!(Layer2Mode::parse("nope"), None);
    }

    #[test]
    fn disabled_is_always_off() {
        assert_eq!(
            select_path(false, Layer2Mode::V2, None, false),
            Ok(L2Path::Off)
        );
    }

    #[test]
    fn both_prefers_regime_ref_then_heartbeat() {
        assert_eq!(
            select_path(true, Layer2Mode::Both, Some("abc"), true),
            Ok(L2Path::RegimeRef("abc".into()))
        );
        assert_eq!(
            select_path(true, Layer2Mode::Both, None, true),
            Ok(L2Path::Heartbeat)
        );
        assert_eq!(
            select_path(true, Layer2Mode::Both, Some("  "), true),
            Ok(L2Path::Heartbeat)
        );
        assert!(select_path(true, Layer2Mode::Both, None, false).is_err());
    }

    #[test]
    fn v2_requires_a_ref_and_legacy_requires_a_heartbeat() {
        assert!(select_path(true, Layer2Mode::V2, None, true).is_err());
        assert_eq!(
            select_path(true, Layer2Mode::V2, Some("r"), false),
            Ok(L2Path::RegimeRef("r".into()))
        );
        assert!(select_path(true, Layer2Mode::Legacy, Some("r"), false).is_err());
        assert_eq!(
            select_path(true, Layer2Mode::Legacy, Some("r"), true),
            Ok(L2Path::Heartbeat)
        );
    }

    #[test]
    fn current_ref_always_accepted() {
        assert!(ref_accepted("cur", "cur", None, 1_000, 300));
    }

    #[test]
    fn previous_ref_accepted_only_within_grace() {
        let prev = Some(("old", 1_000_000));
        assert!(ref_accepted("old", "cur", prev, 1_000_000 + 300_000, 300));
        assert!(!ref_accepted("old", "cur", prev, 1_000_000 + 300_001, 300));
        assert!(!ref_accepted("other", "cur", prev, 1_000_001, 300));
        assert!(!ref_accepted("old", "cur", None, 1_000_001, 300));
    }
}
