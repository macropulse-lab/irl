use crate::config::{Config, TimeSource};
use chrono::Utc;

/// Returns the current time as Unix milliseconds.
///
/// In dev (`TimeSource::System`): uses the system clock directly.
/// In production (`TimeSource::NtpSynced`): stub for Roughtime / NTP attestation.
/// Phase 2 will replace `ntp_attested_ms()` with a real signed time source.
pub fn now_ms(cfg: &Config) -> i64 {
    match cfg.time_source {
        TimeSource::System => Utc::now().timestamp_millis(),
        TimeSource::NtpSynced => ntp_attested_ms(),
    }
}

/// Returns the current time as Unix **microseconds**.
///
/// Use for sub-millisecond ordering when multiple authorizations arrive within
/// the same millisecond (e.g. HFT burst, batch submission). The `txn_time` field
/// in `CognitiveSnapshot` may be upgraded to microseconds in a future migration;
/// for now this is available for new fields or custom integrations.
pub fn now_us(cfg: &Config) -> i64 {
    match cfg.time_source {
        TimeSource::System => Utc::now().timestamp_micros(),
        TimeSource::NtpSynced => ntp_attested_us(),
    }
}

/// Phase 2 stub — replace with Roughtime client or NTP attestation service.
/// When implemented, this must return a monotonic, externally-signed timestamp.
fn ntp_attested_ms() -> i64 {
    // TODO(phase2): integrate Roughtime (https://roughtime.googlesource.com/roughtime)
    // For now, falls back to system clock to allow compilation.
    Utc::now().timestamp_millis()
}

fn ntp_attested_us() -> i64 {
    Utc::now().timestamp_micros()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TimeSource;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn make_cfg(source: TimeSource) -> Config {
        use ed25519_dalek::VerifyingKey;
        Config {
            database_url: String::new(),
            mta_mode: crate::config::MtaMode::Mock,
            mta_url: String::new(),
            mta_pubkey: VerifyingKey::from_bytes(&[0u8; 32]).unwrap(),
            irl_api_tokens: vec![],
            time_source: source,
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

    #[test]
    fn system_time_is_recent() {
        let cfg = make_cfg(TimeSource::System);
        let t = now_ms(&cfg);
        let sys = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        // Within 1 second of system time
        assert!((t - sys).abs() < 1000, "time drift too large: {}", t - sys);
    }

    #[test]
    fn time_is_monotonically_increasing() {
        let cfg = make_cfg(TimeSource::System);
        let t1 = now_ms(&cfg);
        let t2 = now_ms(&cfg);
        assert!(t2 >= t1, "time went backwards: t1={t1} t2={t2}");
    }
}
