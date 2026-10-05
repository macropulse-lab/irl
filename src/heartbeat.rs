use crate::config::Config;
use crate::errors::{AppError, HeartbeatError};
use crate::time::now_ms;
use dashmap::DashMap;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;
use utoipa::ToSchema;
use uuid::Uuid;

/// A signed pulse from MacroPulse, broadcast every ~100ms.
/// Acts as an anti-replay anchor: proves the agent used a fresh, authentic regime.
///
/// §9.2: signature is Ed25519 over (seq_id || timestamp || regime_id || mta_ref)
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SignedHeartbeat {
    /// Monotonically increasing counter. Ensures no replay.
    pub sequence_id: u64,
    /// Unix ms when MacroPulse broadcast this heartbeat.
    pub timestamp_ms: u64,
    /// The regime ID active at broadcast time (must match MTA response).
    pub regime_id: u8,
    /// Hex-encoded SHA-256 of the current MTA broadcast — binds heartbeat to a specific MTA state.
    /// Must match `MtaState.hash` for the regime the agent is acting on.
    #[serde(default)]
    pub mta_ref: String,
    /// Ed25519 signature over: seq_id_be || timestamp_ms_be || regime_id || mta_ref_bytes
    /// Signed by the MTA operator's private key. Verified against Config.mta_pubkey.
    #[serde(with = "base64_bytes")]
    pub signature: Vec<u8>,
}

impl SignedHeartbeat {
    /// Returns the canonical byte payload that was signed.
    /// Layout: seq_id (8 bytes BE) || timestamp_ms (8 bytes BE) || regime_id (1 byte) || mta_ref UTF-8
    pub fn signed_payload(&self) -> Vec<u8> {
        let mta_ref_bytes = self.mta_ref.as_bytes();
        let mut payload = Vec::with_capacity(17 + mta_ref_bytes.len());
        payload.extend_from_slice(&self.sequence_id.to_be_bytes());
        payload.extend_from_slice(&self.timestamp_ms.to_be_bytes());
        payload.push(self.regime_id);
        payload.extend_from_slice(mta_ref_bytes);
        payload
    }
}

/// Validates incoming heartbeats.
///
/// Per-agent sequence tracking via an in-memory `DashMap<Uuid, u64>`.
/// On startup the map is hydrated from `irl.heartbeat_sequences` so anti-replay
/// state survives server restarts. After each successful validation the accepted
/// sequence is upserted back to the DB.
///
/// Thread-safe: DashMap uses fine-grained bucket locking internally.
pub struct HeartbeatValidator {
    /// Last accepted sequence number, keyed by agent_id. Crash-recovered from DB on startup.
    sequences: DashMap<Uuid, u64>,
    max_drift_ms: u64,
    pubkey: VerifyingKey,
}

impl HeartbeatValidator {
    /// Create and hydrate the validator from the database.
    ///
    /// Loads all rows from `irl.heartbeat_sequences` into the in-memory map so
    /// that sequence anti-replay state is not lost across restarts.
    pub async fn new(cfg: &Config, pool: &PgPool) -> anyhow::Result<Arc<Self>> {
        let sequences: DashMap<Uuid, u64> = DashMap::new();

        match sqlx::query_as::<_, (Uuid, i64)>(
            "SELECT agent_id, last_sequence FROM irl.heartbeat_sequences",
        )
        .fetch_all(pool)
        .await
        {
            Ok(rows) => {
                let count = rows.len();
                for (agent_id, seq) in rows {
                    sequences.insert(agent_id, seq as u64);
                }
                tracing::info!(
                    "HeartbeatValidator: loaded {} agent sequence(s) from DB",
                    count
                );
            }
            Err(e) => {
                // FAIL CLOSED (trust-layer integrity). Anti-replay state is a
                // security guarantee, not a cache. Silently starting with an
                // empty map opens a replay window — an attacker could re-present
                // old signed heartbeats up to each agent's last accepted
                // sequence — with no operator signal. When Layer 2 is enforced,
                // refuse to start rather than serve with replay protection
                // silently disabled. When Layer 2 is off, heartbeats are never
                // validated, so an empty map is harmless.
                if cfg.layer2_enabled {
                    anyhow::bail!(
                        "HeartbeatValidator: failed to hydrate anti-replay state from \
                         irl.heartbeat_sequences ({e}). Refusing to start with \
                         LAYER2_ENABLED=true and replay protection disabled — fix DB \
                         access, or set LAYER2_ENABLED=false to run without heartbeat \
                         validation."
                    );
                }
                tracing::warn!(
                    "HeartbeatValidator: hydration failed but LAYER2_ENABLED=false, so \
                     heartbeat anti-replay is not enforced anyway: {e}"
                );
            }
        }

        Ok(Arc::new(Self {
            sequences,
            max_drift_ms: cfg.max_heartbeat_drift_ms,
            pubkey: cfg.mta_pubkey,
        }))
    }

    /// Create a validator with an empty in-memory map (no DB — for tests only).
    #[cfg(test)]
    pub fn new_for_test(cfg: &Config) -> Arc<Self> {
        Arc::new(Self {
            sequences: DashMap::new(),
            max_drift_ms: cfg.max_heartbeat_drift_ms,
            pubkey: cfg.mta_pubkey,
        })
    }

    /// Validate a heartbeat for a given agent. Returns `Ok(drift_ms)` on success.
    ///
    /// Checks (in order):
    /// 1. Ed25519 signature valid
    /// 2. sequence_id > last accepted sequence for this agent (no replay)
    /// 3. age of heartbeat < max_drift_ms (no stale truth)
    ///
    /// On success: updates the in-memory sequence map and upserts to the DB.
    /// DB upsert failure is non-fatal — the in-memory map is the enforced state.
    pub async fn validate(
        &self,
        hb: &SignedHeartbeat,
        agent_id: Uuid,
        cfg: &Config,
        pool: Option<&PgPool>,
    ) -> Result<i64, AppError> {
        // 1. Signature check — must come first to prevent oracle attacks.
        self.verify_signature(hb)?;

        // 2. Per-agent sequence check — strict monotonicity, no replay.
        let last = self.sequences.get(&agent_id).map(|r| *r).unwrap_or(0);
        if hb.sequence_id <= last {
            return Err(AppError::Heartbeat(HeartbeatError::StaleSequence {
                received: hb.sequence_id,
                last,
            }));
        }

        // 3. Drift check — heartbeat must be fresh.
        let current_ms = now_ms(cfg);
        let drift_ms = current_ms - hb.timestamp_ms as i64;
        if drift_ms < 0 || drift_ms as u64 > self.max_drift_ms {
            return Err(AppError::Heartbeat(
                HeartbeatError::LatencyThresholdExceeded {
                    drift_ms: drift_ms.unsigned_abs(),
                    max_ms: self.max_drift_ms,
                },
            ));
        }

        // All checks passed — commit sequence in-memory first (fast path).
        self.sequences.insert(agent_id, hb.sequence_id);

        // Persist to DB for crash recovery. Non-fatal if unavailable.
        if let Some(pool) = pool {
            let seq = hb.sequence_id as i64;
            if let Err(e) = sqlx::query(
                "INSERT INTO irl.heartbeat_sequences (agent_id, last_sequence, updated_at) \
                 VALUES ($1, $2, now()) \
                 ON CONFLICT (agent_id) DO UPDATE \
                   SET last_sequence = EXCLUDED.last_sequence, \
                       updated_at    = EXCLUDED.updated_at \
                 WHERE irl.heartbeat_sequences.last_sequence < EXCLUDED.last_sequence",
            )
            .bind(agent_id)
            .bind(seq)
            .execute(pool)
            .await
            {
                tracing::warn!(
                    agent_id = %agent_id,
                    sequence_id = hb.sequence_id,
                    "Failed to persist heartbeat sequence to DB (in-memory state is authoritative): {e}"
                );
            }
        }

        Ok(drift_ms)
    }

    fn verify_signature(&self, hb: &SignedHeartbeat) -> Result<(), AppError> {
        let sig_bytes: [u8; 64] = hb
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| AppError::Heartbeat(HeartbeatError::InvalidSignature))?;

        let sig = Signature::from_bytes(&sig_bytes);
        let payload = hb.signed_payload();

        self.pubkey
            .verify(&payload, &sig)
            .map_err(|_| AppError::Heartbeat(HeartbeatError::InvalidSignature))
    }
}

/// serde helper: serialize/deserialize Vec<u8> as base64.
mod base64_bytes {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        s.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D>(d: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(d)?;
        STANDARD.decode(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, TimeSource};
    use ed25519_dalek::{SigningKey, VerifyingKey};
    use rand::rngs::OsRng;

    fn make_cfg(pubkey: VerifyingKey) -> Config {
        Config {
            database_url: String::new(),
            mta_mode: crate::config::MtaMode::Mock,
            mta_url: String::new(),
            mta_pubkey: pubkey,
            irl_api_tokens: vec!["tok".into()],
            time_source: TimeSource::System,
            max_heartbeat_drift_ms: 200,
            layer2_enabled: true,
            layer2_mode: crate::layer2::Layer2Mode::Both,
            mta_ref_grace_secs: 300,
            bind_size_tolerance: 0.0001,
            trace_expiry_ms: 3_600_000,
            port: 4000,
            shadow_mode: false,
            metrics_enabled: true,
            metrics_token: None,
            webhook_url: None,
            webhook_secret: None,
            rate_limit_per_second: 100,
            max_body_bytes: 1_048_576,
            kms_provider: crate::config::KmsProvider::None,
            kms_key_id: None,
            kms_key_version: 1,
            mtls_enabled: false,
            mtls_required: false,
            tls_cert_path: None,
            tls_key_path: None,
            tls_ca_cert_path: None,
            mtls_dev_certs: false,
            snapshot_v2_enabled: false,
            merkle_v2_enabled: false,
        }
    }

    fn make_heartbeat(signing_key: &SigningKey, seq: u64, timestamp_ms: u64) -> SignedHeartbeat {
        use ed25519_dalek::Signer;
        let mut hb = SignedHeartbeat {
            sequence_id: seq,
            timestamp_ms,
            regime_id: 2,
            mta_ref: "0xmockref".to_string(),
            signature: vec![],
        };
        let payload = hb.signed_payload();
        let sig = signing_key.sign(&payload);
        hb.signature = sig.to_bytes().to_vec();
        hb
    }

    #[tokio::test]
    async fn valid_heartbeat_accepted() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let cfg = make_cfg(signing_key.verifying_key());
        let validator = HeartbeatValidator::new_for_test(&cfg);

        let now = chrono::Utc::now().timestamp_millis() as u64;
        let hb = make_heartbeat(&signing_key, 1, now);
        assert!(validator
            .validate(&hb, Uuid::nil(), &cfg, None)
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn stale_sequence_rejected() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let cfg = make_cfg(signing_key.verifying_key());
        let validator = HeartbeatValidator::new_for_test(&cfg);

        let now = chrono::Utc::now().timestamp_millis() as u64;
        let hb1 = make_heartbeat(&signing_key, 5, now);
        validator
            .validate(&hb1, Uuid::nil(), &cfg, None)
            .await
            .unwrap();

        let hb2 = make_heartbeat(&signing_key, 3, now); // seq 3 < 5
        assert!(matches!(
            validator.validate(&hb2, Uuid::nil(), &cfg, None).await,
            Err(AppError::Heartbeat(HeartbeatError::StaleSequence { .. }))
        ));
    }

    #[tokio::test]
    async fn drift_exceeded_rejected() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let cfg = make_cfg(signing_key.verifying_key());
        let validator = HeartbeatValidator::new_for_test(&cfg);

        // Timestamp 5 seconds in the past — beyond 200ms drift limit
        let old = (chrono::Utc::now().timestamp_millis() - 5000) as u64;
        let hb = make_heartbeat(&signing_key, 1, old);
        assert!(matches!(
            validator.validate(&hb, Uuid::nil(), &cfg, None).await,
            Err(AppError::Heartbeat(
                HeartbeatError::LatencyThresholdExceeded { .. }
            ))
        ));
    }

    #[tokio::test]
    async fn invalid_signature_rejected() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let wrong_key = SigningKey::generate(&mut OsRng);
        // Config has wrong_key's pubkey, but heartbeat is signed by signing_key
        let cfg = make_cfg(wrong_key.verifying_key());
        let validator = HeartbeatValidator::new_for_test(&cfg);

        let now = chrono::Utc::now().timestamp_millis() as u64;
        let hb = make_heartbeat(&signing_key, 1, now);
        assert!(matches!(
            validator.validate(&hb, Uuid::nil(), &cfg, None).await,
            Err(AppError::Heartbeat(HeartbeatError::InvalidSignature))
        ));
    }

    #[tokio::test]
    async fn per_agent_sequences_are_independent() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let cfg = make_cfg(signing_key.verifying_key());
        let validator = HeartbeatValidator::new_for_test(&cfg);

        let now = chrono::Utc::now().timestamp_millis() as u64;
        let agent_a = Uuid::new_v4();
        let agent_b = Uuid::new_v4();

        // Agent A accepts seq 10.
        let hb_a = make_heartbeat(&signing_key, 10, now);
        validator
            .validate(&hb_a, agent_a, &cfg, None)
            .await
            .unwrap();

        // Agent B starts fresh — seq 5 is valid (independent counter).
        let hb_b = make_heartbeat(&signing_key, 5, now);
        assert!(
            validator.validate(&hb_b, agent_b, &cfg, None).await.is_ok(),
            "agent B seq 5 should be accepted independently of agent A seq 10"
        );

        // Agent A seq 5 is now stale (< 10).
        let hb_a_stale = make_heartbeat(&signing_key, 5, now);
        assert!(matches!(
            validator.validate(&hb_a_stale, agent_a, &cfg, None).await,
            Err(AppError::Heartbeat(HeartbeatError::StaleSequence { .. }))
        ));
    }
}
