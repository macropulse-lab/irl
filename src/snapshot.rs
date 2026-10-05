use crate::heartbeat::SignedHeartbeat;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// The direction and size of a proposed trade.
///
/// Standard variants (Long/Short/Neutral) cover crypto and generic use.
/// Use `Custom(String)` for exchange-specific semantics:
///   - Equities: `Custom("Buy")`, `Custom("Sell")`
///   - Futures:  `Custom("Open Long")`, `Custom("Close Short")`, `Custom("Reverse")`
///   - Options:  `Custom("Buy Call")`, `Custom("Sell Put")`
///
/// `direction()` maps any variant to a canonical "long"/"short"/"neutral"/"unknown"
/// string for policy enforcement. Custom values are matched by prefix/keyword.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, ToSchema)]
pub enum TradeAction {
    Long(f64),
    Short(f64),
    Neutral,
    /// Open-ended action string for exchange-specific or multi-market semantics.
    /// The string is stored verbatim in the audit trace.
    Custom(String),
}

impl TradeAction {
    /// Canonical direction for policy enforcement: "long", "short", "neutral", or "unknown".
    ///
    /// Custom values are resolved by keyword matching (case-insensitive):
    ///   "buy", "long", "open long", "open_long"       → "long"
    ///   "sell", "short", "close short", "close_short" → "short"
    ///   "close", "exit", "reverse"                    → "short" (net-reducing)
    ///   "flat", "neutral", "cancel"                   → "neutral"
    pub fn direction(&self) -> &'static str {
        match self {
            TradeAction::Long(_) => "long",
            TradeAction::Short(_) => "short",
            TradeAction::Neutral => "neutral",
            TradeAction::Custom(s) => resolve_custom_direction(s),
        }
    }
}

/// Canonical direction resolver, also used by the proof-bundle exporter to
/// reconstruct the sealed `direction` public field from the stored
/// `execution_action` display string. It yields the same value `direction()`
/// produced at seal time: `"Long(x)"`→"long", `"Short(x)"`→"short",
/// `"Neutral"`→"neutral", and any Custom string by keyword — so the auditor's
/// recomputed `reasoning_hash` matches byte-for-byte.
pub(crate) fn resolve_custom_direction(s: &str) -> &'static str {
    let lower = s.to_ascii_lowercase();
    let lower = lower.trim();
    // Long-direction keywords
    if lower.contains("long")
        || lower.starts_with("buy")
        || lower == "open"
        || lower.contains("open_long")
    {
        return "long";
    }
    // Short-direction keywords
    if lower.contains("short")
        || lower.starts_with("sell")
        || lower == "close"
        || lower == "exit"
        || lower == "reverse"
        || lower.contains("close_short")
    {
        return "short";
    }
    // Neutral keywords
    if lower == "neutral" || lower == "flat" || lower == "cancel" || lower == "hold" {
        return "neutral";
    }
    "unknown"
}

impl std::fmt::Display for TradeAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TradeAction::Long(s) => write!(f, "Long({s})"),
            TradeAction::Short(s) => write!(f, "Short({s})"),
            TradeAction::Neutral => write!(f, "Neutral"),
            TradeAction::Custom(s) => write!(f, "{s}"),
        }
    }
}

/// Order execution type — maps to exchange order semantics.
///
/// Standard types cover most use cases. Use `Custom(String)` for
/// venue-specific order types not listed here.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, ToSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OrderType {
    /// Execute at current market price (taker).
    Market,
    /// Execute at limit price or better.
    Limit,
    /// Trigger order that converts to a market order at stop price.
    Stop,
    /// Trigger order that converts to a limit order at stop price.
    StopLimit,
    /// Time-weighted average price execution.
    Twap,
    /// Volume-weighted average price execution.
    Vwap,
    /// Immediate-or-Cancel: fill immediately, cancel any unfilled remainder.
    Ioc,
    /// Fill-or-Kill: fill the entire order immediately or cancel entirely.
    Fok,
    /// Post-Only: cancel if the order would immediately cross the spread (maker-only).
    PostOnly,
    /// Pegged: price tracks a reference (e.g. mid-price peg for passive market making).
    Pegged,
    /// Trailing Stop: stop price trails market price by a fixed offset.
    TrailingStop,
    /// Iceberg: only a disclosed quantity is visible on the order book.
    Iceberg,
    /// Venue-specific order type not covered by the above.
    Custom(String),
}

impl std::fmt::Display for OrderType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            OrderType::Market => "MARKET",
            OrderType::Limit => "LIMIT",
            OrderType::Stop => "STOP",
            OrderType::StopLimit => "STOP_LIMIT",
            OrderType::Twap => "TWAP",
            OrderType::Vwap => "VWAP",
            OrderType::Ioc => "IOC",
            OrderType::Fok => "FOK",
            OrderType::PostOnly => "POST_ONLY",
            OrderType::Pegged => "PEGGED",
            OrderType::TrailingStop => "TRAILING_STOP",
            OrderType::Iceberg => "ICEBERG",
            OrderType::Custom(s) => s.as_str(),
        };
        write!(f, "{s}")
    }
}

/// Full execution intent — §5.2 E_t specification.
///
/// Every field that is required for policy evaluation is mandatory.
/// `limit_price` is required when `order_type == Limit` or `StopLimit`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ExecutionIntent {
    pub action: TradeAction,
    /// Asset identifier. Free-form — use canonical form for your venue
    /// (e.g. "AAPL" for US equities, "BTC-PERP" for crypto perps, "ES" for CME futures).
    /// IRL stores exactly what the agent provides; asset normalization is applied upstream
    /// via the alias map if configured.
    pub asset: String,
    pub order_type: OrderType,
    /// MIC code or internal route ID (e.g. "XNAS", "XLON", "INTERNAL-DARK").
    pub venue_id: String,
    /// Number of units to trade (contracts, shares, or base currency units).
    pub quantity: f64,
    /// Notional value in `notional_currency` — evaluated against per-regime notional caps.
    /// For futures: notional = quantity × price × multiplier (caller is responsible for this).
    pub notional: f64,
    /// ISO 4217 currency code for the notional (default: "USD").
    /// Used for multi-currency position tracking and cross-asset cap enforcement.
    pub notional_currency: String,
    /// Contract multiplier for futures and options.
    /// Examples: CME ES = 50, Euronext CAC40 futures = 10, equity options = 100.
    /// Default 1.0 (no multiplier — spot/equities/crypto perps).
    pub multiplier: f64,
    /// Required for Limit and StopLimit orders; None for Market/Stop/TWAP/VWAP/IOC/FOK.
    pub limit_price: Option<f64>,
    /// For StopLimit orders: the stop trigger price.
    pub stop_price: Option<f64>,
    pub client_order_id: String,
}

/// A point-in-time snapshot of everything an agent knew and intended
/// at the moment of decision. This is the atomic unit of proof.
///
/// Fields:
/// - `valid_time`: when the MTA regime was broadcast (MTA-attested).
/// - `txn_time`:   when IRL sealed this snapshot (secured via `time.rs`).
///
/// Invariant: `valid_time < txn_time` — enforced by `seal::verify_bitemporal`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CognitiveSnapshot {
    pub trace_id: Uuid,
    /// Opaque regime identifier from the MTA operator.
    pub mta_regime_id: u8,
    /// Semantic version of the MTA model that produced `mta_regime_id`.
    pub mta_version: String,
    /// SHA-256 of the raw MTA response body (proves which exact data was used).
    pub mta_hash: String,
    /// SHA-256(model_id || prompt_version || feature_schema_id || hyperparameter_checksum).
    /// A fingerprint of the agent's "brain" — lightweight, deterministic, no IP exposed.
    pub latent_fingerprint: String,
    /// Identifies the feature schema (input structure) the agent was running.
    pub feature_schema_id: String,
    /// What the agent wants to do.
    pub execution: ExecutionIntent,
    /// Unix ms — when the MTA regime was valid in the market.
    pub valid_time: i64,
    /// Unix ms — when IRL sealed this snapshot.
    pub txn_time: i64,
    /// Layer 2: monotonic heartbeat required when LAYER2_ENABLED=true.
    pub heartbeat: SignedHeartbeat,
}

/// The request body sent by an agent to POST /irl/authorize.
#[derive(Debug, Deserialize, ToSchema)]
pub struct AuthorizeRequest {
    /// Registered agent identity (UUID from POST /irl/agents).
    pub agent_id: uuid::Uuid,
    /// Hex-encoded SHA-256 of the running model version + config — verified against MAR.
    pub model_hash_hex: String,
    pub model_id: String,
    pub prompt_version: String,
    pub feature_schema_id: String,
    /// Checksum of hyperparameters — 4th component of L_t fingerprint.
    pub hyperparameter_checksum: String,
    pub action: TradeAction,
    pub asset: String,
    pub order_type: OrderType,
    pub venue_id: String,
    pub quantity: f64,
    pub notional: f64,
    /// ISO 4217 currency of the notional. Defaults to "USD" if not provided.
    #[serde(default = "default_usd")]
    pub notional_currency: String,
    /// Contract multiplier. Defaults to 1.0 if not provided.
    #[serde(default = "default_multiplier")]
    pub multiplier: f64,
    pub limit_price: Option<f64>,
    pub stop_price: Option<f64>,
    pub client_order_id: String,
    /// Unix ms: the timestamp of the MTA regime the agent used.
    pub agent_valid_time: i64,
    pub heartbeat: Option<SignedHeartbeat>,
    /// When true, this order is reducing an existing position (not opening a new one).
    /// The `allowed_sides` regime constraint is bypassed — a trader must be able to
    /// exit positions even during a kill-switch regime. Notional cap still applies.
    /// The agent asserts reduce-only intent; IRL seals and audits the claim.
    #[serde(default)]
    pub reduce_only: bool,
    /// Optional regulatory metadata. Omit if not subject to a specific reporting regime.
    /// See `RegulatoryBlock` for supported fields.
    #[serde(default)]
    pub regulatory: Option<RegulatoryBlock>,
    /// Multi-agent linking: the trace_id of the orchestrator decision that triggered
    /// this sub-agent call. Forms a causal DAG for full lineage audits.
    #[serde(default)]
    pub parent_trace_id: Option<Uuid>,
    /// Layer 2 v2: regime reference from `GET /irl/regime` (replaces the
    /// client-carried heartbeat when LAYER2_MODE is v2 or both).
    #[serde(default)]
    pub mta_ref: Option<String>,
}

fn default_usd() -> String {
    "USD".to_string()
}

fn default_multiplier() -> f64 {
    1.0
}

/// Compute the latent fingerprint from agent identity fields.
/// §5.2: L_t = SHA-256(model_version_hash || prompt_template_hash || feature_schema_id || hyperparameter_checksum)
pub fn compute_latent_fingerprint(
    model_id: &str,
    prompt_version: &str,
    feature_schema_id: &str,
    hyperparameter_checksum: &str,
) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(model_id.as_bytes());
    hasher.update(b"||");
    hasher.update(prompt_version.as_bytes());
    hasher.update(b"||");
    hasher.update(feature_schema_id.as_bytes());
    hasher.update(b"||");
    hasher.update(hyperparameter_checksum.as_bytes());
    hex::encode(hasher.finalize())
}

/// The full Reasoning_Trace_v1 object returned to callers and stored in DB.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ReasoningTrace {
    pub trace_id: Uuid,
    pub version: &'static str,
    pub bitemporal: BiTemporalBlock,
    pub mta: MtaBlock,
    pub agent: AgentBlock,
    pub execution: ExecutionBlock,
    pub heartbeat: HeartbeatBlock,
    pub policy: PolicyBlock,
    pub integrity: IntegrityBlock,
    /// Optional regulatory metadata (MiFID II, CFTC, SEC CAT).
    /// Absent when the agent does not operate under a specific reporting regime.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub regulatory: Option<RegulatoryBlock>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct BiTemporalBlock {
    pub valid_time: DateTime<Utc>,
    pub txn_time: DateTime<Utc>,
    pub time_source: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct MtaBlock {
    pub regime_id: u8,
    pub regime_label: String,
    /// Normalized risk level at time of decision (0.0–1.0).
    pub risk_level: f64,
    /// Regime-level notional multiplier that was in effect.
    pub max_notional_scale: f64,
    /// Trade directions that were permitted.
    pub allowed_sides: Vec<String>,
    pub version: String,
    pub hash: String,
    pub signature_valid: bool,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct AgentBlock {
    pub agent_id: Uuid,
    pub latent_fingerprint: String,
    pub feature_schema_id: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ExecutionBlock {
    pub action: String,
    pub asset: String,
    pub order_type: String,
    pub venue_id: String,
    pub quantity: f64,
    pub notional: f64,
    pub notional_currency: String,
    pub multiplier: f64,
    pub limit_price: Option<f64>,
    pub stop_price: Option<f64>,
    pub client_order_id: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct HeartbeatBlock {
    pub sequence_id: u64,
    pub signature_valid: bool,
    pub drift_ms: i64,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct PolicyBlock {
    pub id: String,
    pub version: String,
    pub hash: String,
    pub result: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct IntegrityBlock {
    pub reasoning_hash: String,
    pub final_proof: Option<String>,
    pub verification_status: String,
    pub execution_status: Option<String>,
}

/// Optional regulatory metadata — included when the agent operates under a
/// reporting regime that requires structured fields in the audit trace.
///
/// All fields are optional. The block itself is absent (`None`) when no
/// regulatory context is provided by the agent.
///
/// MiFID II (EU): algorithmic trading identifier + decision-maker identity.
/// CFTC (US): Commodity Trading Advisor Code + special account code.
/// SEC/FINRA: optional order-tracking reference number (CAT NMS).
///
/// IRL seals and persists whatever the agent supplies — it does not validate
/// against any external regulatory schema. Compliance teams are responsible
/// for verifying that the values satisfy their specific reporting obligations.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RegulatoryBlock {
    /// MiFID II Annex I Table 2: algorithm identifier assigned by the firm.
    /// Required for algorithmic orders under Art. 17 of MiFID II.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mifid_algo_id: Option<String>,
    /// MiFID II: identifier of the person or system that made the investment decision.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mifid_decision_maker: Option<String>,
    /// CFTC: Commodity Trading Advisor (CTA) code for the account.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cftc_cti_code: Option<String>,
    /// CFTC: special account type designator (e.g. "H" = hedge, "S" = speculator).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cftc_account_type: Option<String>,
    /// SEC CAT NMS: Consolidated Audit Trail order-tracking reference number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cat_order_id: Option<String>,
    /// Free-form jurisdiction tag (e.g. "EU", "US", "UK", "APAC").
    /// Allows downstream compliance tooling to route the trace for the right rulebook.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jurisdiction: Option<String>,
}
