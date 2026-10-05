/// Asset alias normalization.
///
/// Converts exchange-specific or legacy symbol formats to a canonical form
/// before the asset string is stored in the audit trace. This prevents false
/// DIVERGENT outcomes when the agent sends "AAPL" but the exchange confirms
/// "AAPL.USD", or the agent sends "BTC" but Binance returns "BTCUSDT".
///
/// ## Configuration
///
/// Alias maps are loaded from `ASSET_ALIAS_MAP` env var at startup.
/// Format: comma-separated pairs, pipe-separated within each pair.
///
/// Example:
///   ASSET_ALIAS_MAP=AAPL.USD|AAPL,BTCUSDT|BTC-PERP,ETHUSDT|ETH-PERP
///
/// This maps "AAPL.USD" → "AAPL", "BTCUSDT" → "BTC-PERP", etc.
/// Both the alias and the canonical form are accepted in authorize/bind.
///
/// ## Bind reconciliation
///
/// When comparing an authorized asset against a bind execution report,
/// both values are canonicalized before comparison. If either maps to the
/// same canonical form, the check passes (no DIVERGENT).
use std::collections::HashMap;
use std::sync::OnceLock;

/// Global alias map — loaded once at startup.
static ALIAS_MAP: OnceLock<HashMap<String, String>> = OnceLock::new();

/// Initialize the alias map from a semicolon-separated environment string.
/// Should be called once during startup (after config is loaded).
pub fn init(raw: &str) {
    let mut map = HashMap::new();
    for pair in raw.split(',') {
        let parts: Vec<&str> = pair.splitn(2, '|').collect();
        if parts.len() == 2 {
            let alias = parts[0].trim().to_string();
            let canonical = parts[1].trim().to_string();
            map.insert(alias, canonical);
        }
    }
    let _ = ALIAS_MAP.set(map);
}

/// Resolve an asset string to its canonical form.
///
/// If the asset is in the alias map, returns the canonical form.
/// Otherwise returns the input unchanged.
///
/// Case-sensitive — symbols are case-sensitive on most exchanges.
pub fn canonicalize(asset: &str) -> String {
    ALIAS_MAP
        .get()
        .and_then(|m| m.get(asset))
        .map(|s| s.to_owned())
        .unwrap_or_else(|| asset.to_string())
}

/// Returns true if two asset strings refer to the same canonical asset.
///
/// Used during bind reconciliation: if the authorized asset and the
/// execution report asset canonicalize to the same value, they match.
pub fn assets_match(a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }
    canonicalize(a) == canonicalize(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(dead_code)]
    fn with_map(raw: &str, f: impl FnOnce()) {
        // Since OnceLock can't be reset, we test canonicalize directly
        // by building a local map inline for unit tests.
        let _ = raw; // suppress unused warning
        f();
    }

    #[test]
    fn exact_match_passes() {
        assert!(assets_match("BTC-PERP", "BTC-PERP"));
    }

    #[test]
    fn different_symbols_fail() {
        assert!(!assets_match("BTC-PERP", "ETH-PERP"));
    }

    #[test]
    fn canonicalize_unknown_returns_input() {
        assert_eq!(canonicalize("UNKNOWN-XYZ"), "UNKNOWN-XYZ");
    }
}
