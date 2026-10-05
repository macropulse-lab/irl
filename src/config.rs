use anyhow::{Context, Result};
use ed25519_dalek::VerifyingKey;
use std::env;

#[derive(Debug, Clone, PartialEq)]
pub enum TimeSource {
    /// Dev only — system clock, NOT audit-safe.
    System,
    /// Phase 2: Roughtime / NTP attestation stub.
    NtpSynced,
}

/// Which KMS backend to use for envelope encryption of trace_json.
#[derive(Debug, Clone, PartialEq)]
pub enum KmsProvider {
    /// KMS_PROVIDER unset — no encryption; plaintext mode (dev/legacy).
    None,
    /// KMS_PROVIDER=local — LocalDevProvider using a fixed 32-byte key (CI / local dev only).
    Local,
    /// KMS_PROVIDER=aws — AwsKmsProvider using AWS KMS CMK.
    Aws,
    /// KMS_PROVIDER=vault — VaultTransitProvider using HashiCorp Vault Transit secrets engine.
    Vault,
}

/// Which MTA client to instantiate at startup.
#[derive(Debug, Clone, PartialEq)]
pub enum MtaMode {
    /// Production: connect to an external signed-regime operator (MacroPulse
    /// or any service speaking the same signed MTA format). Requires MTA_URL
    /// and MTA_PUBKEY_HEX. `MTA_MODE=external` (legacy aliases: `macropulse`, `custom`).
    External,
    /// Evaluation / CI: built-in mock that returns a static Expansion regime.
    /// No external endpoint required. Do NOT use in production.
    Mock,
    /// No external signal — IRL seals and audits every decision but applies
    /// no regime-level direction or notional constraints. Agent-level caps
    /// from the MAR are still enforced. All traces record signal_mode="none".
    ///
    /// Valid for production. Use when the firm manages risk externally (OMS,
    /// pre-trade risk checks) and wants IRL purely as a cryptographic audit rail.
    None,
}

#[derive(Clone)]
pub struct Config {
    pub database_url: String,
    pub mta_mode: MtaMode,
    /// Only used when mta_mode = External.
    pub mta_url: String,
    /// Only used when mta_mode = External.
    pub mta_pubkey: VerifyingKey,
    /// Valid bearer tokens, one per client/fund.
    pub irl_api_tokens: Vec<String>,
    pub time_source: TimeSource,
    /// Maximum age of a heartbeat before it is rejected (milliseconds).
    pub max_heartbeat_drift_ms: u64,
    /// When true, every /authorize request must carry a valid SignedHeartbeat.
    pub layer2_enabled: bool,
    /// Layer 2 binding mode: legacy heartbeats, v2 regime refs, or both (LAYER2_MODE).
    pub layer2_mode: crate::layer2::Layer2Mode,
    /// v2: how long the previous regime ref stays valid after a change (MTA_REF_GRACE_SECS).
    pub mta_ref_grace_secs: u64,
    /// Tolerance for quantity divergence in bind-execution (0.0001 = 0.01%).
    pub bind_size_tolerance: f64,
    /// How long before a PENDING trace is expired by the verifier worker (ms).
    pub trace_expiry_ms: u64,
    pub port: u16,
    /// When true, policy violations are logged but not blocked.
    /// Traces are persisted with policy_result = 'SHADOW_HALTED'.
    /// Safe for first-run instrumentation; set to false in production enforcement.
    pub shadow_mode: bool,
    /// When true, expose GET /metrics in Prometheus exposition format.
    pub metrics_enabled: bool,
    /// Optional bearer token required to access GET /metrics.
    /// When set, unauthenticated scrape requests receive 401.
    /// When unset, the endpoint is open (suitable when restricted at the network layer).
    pub metrics_token: Option<String>,
    /// Maximum authorized requests per token per second (0 = disabled).
    /// Applies to all protected routes. Default: 100.
    pub rate_limit_per_second: u32,
    /// Maximum allowed request body size in bytes (0 = unlimited).
    /// Default: 1 MB (1_048_576 bytes). Protects against memory exhaustion.
    pub max_body_bytes: usize,
    /// KMS backend selection. None = plaintext mode.
    pub kms_provider: KmsProvider,
    /// CMK identifier: AWS key ARN/alias or Vault transit key name.
    /// Required when kms_provider is Aws or Vault.
    pub kms_key_id: Option<String>,
    /// Active key version used when generating new DEKs. Default: 1.
    pub kms_key_version: i32,
    /// When true, bind TLS listener via axum_server::bind_rustls.
    pub mtls_enabled: bool,
    /// When true, client certificate is required (not just accepted).
    pub mtls_required: bool,
    /// Path to server TLS certificate PEM file.
    pub tls_cert_path: Option<String>,
    /// Path to server TLS private key PEM file.
    pub tls_key_path: Option<String>,
    /// Path to CA certificate PEM used to verify client certs.
    pub tls_ca_cert_path: Option<String>,
    /// When true, generate ephemeral dev certs via rcgen (dev/CI only).
    pub mtls_dev_certs: bool,
    /// POST target for regime-change webhooks (e.g. "https://ops.example.com/hooks/irl").
    /// When set, IRL fires a signed POST within 5 s of detecting a regime change.
    pub webhook_url: Option<String>,
    /// HMAC-SHA256 signing secret for webhook payloads.
    /// Signature is sent in `X-IRL-Signature: sha256=<hex>`. Required when webhook_url is set.
    pub webhook_secret: Option<String>,
    /// T-1.1: when true, new traces seal via the v2 split public/private
    /// commitment (`snapshot_version = 2`) instead of the v1 whole-snapshot
    /// seal. Default false. Do NOT enable until the v2-aware offline verifier
    /// ships — v2 hashes are not reproducible by the current `verify_bundle`.
    pub snapshot_v2_enabled: bool,
    /// T-1.2: when true, the Merkle anchor worker builds domain-separated
    /// (RFC-6962) roots and tags anchors `merkle_algo = "rfc6962-sha256-v2"`,
    /// fixing the v1 second-preimage weakness. Independent of snapshot_v2 — a v2
    /// tree over v1 hashes is valid and fixes the flaw for all traces. Default
    /// false; enable only after the v2-aware verifier is deployed (it selects
    /// the root construction per anchor).
    pub merkle_v2_enabled: bool,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        dotenvy::dotenv().ok();

        let database_url = env::var("DATABASE_URL").context("DATABASE_URL missing")?;

        let mta_mode = parse_mta_mode(
            env::var("MTA_MODE").ok().as_deref(),
            env::var("MTA_URL").is_ok_and(|u| !u.trim().is_empty()),
        )?;

        // MTA credentials are only required when using an external MTA operator.
        let (mta_url, mta_pubkey) = if mta_mode != MtaMode::External {
            (String::new(), VerifyingKey::from_bytes(&[0u8; 32]).unwrap())
        } else {
            let url = env::var("MTA_URL").context("MTA_URL missing")?;
            let pubkey_hex = env::var("MTA_PUBKEY_HEX").context("MTA_PUBKEY_HEX missing")?;
            let pubkey_bytes =
                hex::decode(&pubkey_hex).context("MTA_PUBKEY_HEX is not valid hex")?;
            let pubkey_array: [u8; 32] = pubkey_bytes.try_into().map_err(|_| {
                anyhow::anyhow!("MTA_PUBKEY_HEX must be exactly 32 bytes (64 hex chars)")
            })?;
            let pubkey =
                VerifyingKey::from_bytes(&pubkey_array).context("Invalid Ed25519 public key")?;
            (url, pubkey)
        };

        let tokens_raw = env::var("IRL_API_TOKENS").context("IRL_API_TOKENS missing")?;
        let irl_api_tokens: Vec<String> = tokens_raw
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        anyhow::ensure!(
            !irl_api_tokens.is_empty(),
            "IRL_API_TOKENS must contain at least one token"
        );

        let time_source = match env::var("TIME_SOURCE").as_deref() {
            Ok("NtpSynced") => TimeSource::NtpSynced,
            _ => TimeSource::System,
        };

        let max_heartbeat_drift_ms = env::var("MAX_HEARTBEAT_DRIFT_MS")
            .unwrap_or_else(|_| "200".to_string())
            .parse::<u64>()
            .context("MAX_HEARTBEAT_DRIFT_MS must be a number")?;

        // Layer 2 binds each authorize to the regime operator's current state;
        // with no operator (MTA_MODE=none) there is nothing to bind, so it
        // defaults off there. An explicit LAYER2_ENABLED always wins.
        let layer2_enabled = match env::var("LAYER2_ENABLED") {
            Ok(v) => v.trim().eq_ignore_ascii_case("true"),
            Err(_) => mta_mode != MtaMode::None,
        };

        let layer2_mode_raw = env::var("LAYER2_MODE").unwrap_or_else(|_| "both".to_string());
        let layer2_mode =
            crate::layer2::Layer2Mode::parse(&layer2_mode_raw).with_context(|| {
                format!("LAYER2_MODE must be legacy, v2 or both (got {layer2_mode_raw:?})")
            })?;
        let mta_ref_grace_secs = env::var("MTA_REF_GRACE_SECS")
            .unwrap_or_else(|_| "300".to_string())
            .parse::<u64>()
            .context("MTA_REF_GRACE_SECS must be a number")?;

        let bind_size_tolerance = env::var("BIND_SIZE_TOLERANCE")
            .unwrap_or_else(|_| "0.0001".to_string())
            .parse::<f64>()
            .context("BIND_SIZE_TOLERANCE must be a float")?;

        let trace_expiry_ms = env::var("TRACE_EXPIRY_MS")
            .unwrap_or_else(|_| "3600000".to_string())
            .parse::<u64>()
            .context("TRACE_EXPIRY_MS must be a number")?;

        let port = env::var("PORT")
            .unwrap_or_else(|_| "4000".to_string())
            .parse::<u16>()
            .context("PORT must be a valid port number")?;

        let shadow_mode = env::var("SHADOW_MODE")
            .unwrap_or_else(|_| "false".to_string())
            .to_lowercase()
            == "true";

        let metrics_enabled = env::var("METRICS_ENABLED")
            .unwrap_or_else(|_| "true".to_string())
            .to_lowercase()
            == "true";

        let metrics_token = env::var("METRICS_TOKEN").ok();

        let rate_limit_per_second = env::var("RATE_LIMIT_PER_SECOND")
            .unwrap_or_else(|_| "100".to_string())
            .parse::<u32>()
            .context("RATE_LIMIT_PER_SECOND must be a non-negative integer")?;

        let max_body_bytes = env::var("MAX_BODY_BYTES")
            .unwrap_or_else(|_| "1048576".to_string())
            .parse::<usize>()
            .context("MAX_BODY_BYTES must be a non-negative integer")?;

        let kms_provider = match env::var("KMS_PROVIDER").as_deref() {
            Ok("local") => KmsProvider::Local,
            Ok("aws") => KmsProvider::Aws,
            Ok("vault") => KmsProvider::Vault,
            _ => KmsProvider::None,
        };
        let kms_key_id = env::var("KMS_KEY_ID").ok();
        let kms_key_version = env::var("KMS_KEY_VERSION")
            .unwrap_or_else(|_| "1".to_string())
            .parse::<i32>()
            .context("KMS_KEY_VERSION must be an integer")?;

        let mtls_enabled = env::var("MTLS_ENABLED")
            .unwrap_or_else(|_| "false".to_string())
            .to_lowercase()
            == "true";
        let mtls_required = env::var("MTLS_REQUIRED")
            .unwrap_or_else(|_| "false".to_string())
            .to_lowercase()
            == "true";
        let tls_cert_path = env::var("TLS_CERT_PATH").ok();
        let tls_key_path = env::var("TLS_KEY_PATH").ok();
        let tls_ca_cert_path = env::var("TLS_CA_CERT_PATH").ok();
        let mtls_dev_certs = env::var("MTLS_DEV_CERTS")
            .unwrap_or_else(|_| "false".to_string())
            .to_lowercase()
            == "true";

        let webhook_url = env::var("WEBHOOK_URL").ok();
        let webhook_secret = env::var("WEBHOOK_SECRET").ok();

        let snapshot_v2_enabled = env::var("SNAPSHOT_V2_ENABLED")
            .unwrap_or_else(|_| "false".to_string())
            .to_lowercase()
            == "true";

        let merkle_v2_enabled = env::var("MERKLE_V2_ENABLED")
            .unwrap_or_else(|_| "false".to_string())
            .to_lowercase()
            == "true";

        Ok(Config {
            database_url,
            mta_mode,
            mta_url,
            mta_pubkey,
            irl_api_tokens,
            time_source,
            max_heartbeat_drift_ms,
            layer2_enabled,
            layer2_mode,
            mta_ref_grace_secs,
            bind_size_tolerance,
            trace_expiry_ms,
            port,
            shadow_mode,
            metrics_enabled,
            metrics_token,
            rate_limit_per_second,
            max_body_bytes,
            kms_provider,
            kms_key_id,
            kms_key_version,
            mtls_enabled,
            mtls_required,
            tls_cert_path,
            tls_key_path,
            tls_ca_cert_path,
            mtls_dev_certs,
            webhook_url,
            webhook_secret,
            snapshot_v2_enabled,
            merkle_v2_enabled,
        })
    }
}

/// Resolve `MTA_MODE`. Unset means "external if an `MTA_URL` is configured,
/// otherwise none", so IRL runs without any regime operator by default while
/// existing deployments that point at one keep working unchanged.
pub fn parse_mta_mode(raw: Option<&str>, has_mta_url: bool) -> anyhow::Result<MtaMode> {
    match raw.map(|v| v.trim().to_ascii_lowercase()).as_deref() {
        None | Some("") => Ok(if has_mta_url {
            MtaMode::External
        } else {
            MtaMode::None
        }),
        // `macropulse` and `custom` are earlier names for the same mode.
        Some("external") | Some("macropulse") | Some("custom") => Ok(MtaMode::External),
        Some("none") => Ok(MtaMode::None),
        Some("mock") => Ok(MtaMode::Mock),
        Some(other) => anyhow::bail!("MTA_MODE must be external, none or mock (got {other:?})"),
    }
}

#[cfg(test)]
mod mta_mode_tests {
    use super::*;

    #[test]
    fn unset_mode_follows_whether_an_operator_url_is_configured() {
        assert_eq!(parse_mta_mode(None, true).unwrap(), MtaMode::External);
        assert_eq!(parse_mta_mode(None, false).unwrap(), MtaMode::None);
        assert_eq!(parse_mta_mode(Some("  "), false).unwrap(), MtaMode::None);
    }

    #[test]
    fn explicit_modes_and_legacy_alias_are_case_insensitive() {
        assert_eq!(
            parse_mta_mode(Some("External"), false).unwrap(),
            MtaMode::External
        );
        assert_eq!(
            parse_mta_mode(Some("macropulse"), false).unwrap(),
            MtaMode::External
        );
        assert_eq!(
            parse_mta_mode(Some("custom"), false).unwrap(),
            MtaMode::External
        );
        assert_eq!(parse_mta_mode(Some("NONE"), true).unwrap(), MtaMode::None);
        assert_eq!(parse_mta_mode(Some("Mock"), true).unwrap(), MtaMode::Mock);
    }

    #[test]
    fn unknown_mode_is_a_startup_error_not_a_silent_default() {
        assert!(parse_mta_mode(Some("macro-pulse"), true).is_err());
    }
}
