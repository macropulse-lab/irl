/// Integration tests for Phase 4 mTLS requirements (MTLS-01 through MTLS-05).
///
/// These tests verify TLS configuration, client cert parsing, expiry logic,
/// and CN extraction without requiring a live HTTP server or DB connection.
use irl_engine::middleware::client_cert::parse_client_cert;
use irl_engine::tls::{
    build_server_config, check_cert_expiry, generate_dev_certs, spawn_expiry_warn_task,
    CertExpiryStatus,
};
use rustls_pemfile::{certs, private_key};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::time::{Duration, SystemTime};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn pem_to_cert_chain(pem: &str) -> Vec<CertificateDer<'static>> {
    let collected: Vec<_> = {
        let mut rd = std::io::Cursor::new(pem.as_bytes());
        certs(&mut rd).collect()
    };
    collected.into_iter().map(|r| r.unwrap()).collect()
}

fn pem_to_key(pem: &str) -> PrivateKeyDer<'static> {
    let mut rd = std::io::Cursor::new(pem.as_bytes());
    private_key(&mut rd).unwrap().unwrap()
}

fn pem_to_ca_der(pem: &str) -> Vec<u8> {
    pem_to_cert_chain(pem)[0].as_ref().to_vec()
}

// ── MTLS-01: Server config with required client cert ─────────────────────────

/// MTLS-01: build_server_config with mtls_required=true compiles and succeeds.
#[test]
fn test_client_cert_required_config() {
    let dev = generate_dev_certs().unwrap();
    let ca_der = pem_to_ca_der(&dev.ca_cert_pem);
    let chain = pem_to_cert_chain(&dev.server_cert_pem);
    let key = pem_to_key(&dev.server_key_pem);

    let cfg = build_server_config(&ca_der, chain, key, true, true);
    assert!(
        cfg.is_ok(),
        "build_server_config(required=true) should succeed"
    );
    let server_config = cfg.unwrap();
    assert_eq!(
        server_config.alpn_protocols,
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    );
}

/// MTLS-01: A cert signed by the dev CA parses without error via parse_client_cert.
#[test]
fn test_valid_client_cert_accepted() {
    let dev = generate_dev_certs().unwrap();
    let client_chain = pem_to_cert_chain(&dev.client_cert_pem);
    let der = client_chain[0].as_ref();

    let result = parse_client_cert(der);
    assert!(
        result.is_ok(),
        "CA-signed dev client cert should parse: {:?}",
        result.err()
    );
    let info = result.unwrap();
    assert_eq!(info.cn, "dev-agent-01");
}

// ── MTLS-02: CN extraction ────────────────────────────────────────────────────

/// MTLS-02: parse_client_cert correctly extracts CN from a self-signed cert.
#[test]
fn test_extract_cn() {
    use rcgen::{CertificateParams, DnType, KeyPair};
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, "agent-42");
    let cert = params.self_signed(&key).unwrap();

    let info = parse_client_cert(cert.der().as_ref()).unwrap();
    assert_eq!(info.cn, "agent-42");
}

/// MTLS-02: CN mismatch can be detected by comparing CN to agent_id.
#[test]
fn test_cn_mismatch_detection() {
    use rcgen::{CertificateParams, DnType, KeyPair};
    let agent_id = uuid::Uuid::new_v4();

    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, "not-the-agent-id");
    let cert = params.self_signed(&key).unwrap();

    let info = parse_client_cert(cert.der().as_ref()).unwrap();
    assert_ne!(
        info.cn,
        agent_id.to_string(),
        "CN should not match a random agent_id"
    );
}

// ── MTLS-03: Hot-reload infra smoke test ──────────────────────────────────────

/// MTLS-03: spawn_expiry_warn_task does not panic (smoke test).
#[tokio::test]
async fn test_cert_watcher_smoke() {
    let soon = SystemTime::now() + Duration::from_secs(5 * 86400);
    spawn_expiry_warn_task(soon);
    tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;
}

// ── MTLS-04: Expiry monitoring ────────────────────────────────────────────────

/// MTLS-04: check_cert_expiry returns ExpiringSoon within 14 days.
#[test]
fn test_cert_expiry_warning() {
    let not_after = SystemTime::now() + Duration::from_secs(5 * 86400);
    assert!(
        matches!(
            check_cert_expiry(not_after),
            CertExpiryStatus::ExpiringSoon { days_remaining: d } if d <= 5
        ),
        "cert within 5 days should be ExpiringSoon"
    );
}

/// MTLS-04: check_cert_expiry returns Ok beyond 14 days.
#[test]
fn test_cert_expiry_ok() {
    let not_after = SystemTime::now() + Duration::from_secs(20 * 86400);
    assert_eq!(check_cert_expiry(not_after), CertExpiryStatus::Ok);
}

/// MTLS-04: check_cert_expiry returns Expired for past certs.
#[test]
fn test_cert_expiry_expired() {
    let not_after = SystemTime::now() - Duration::from_secs(1);
    assert_eq!(check_cert_expiry(not_after), CertExpiryStatus::Expired);
}

// ── MTLS-05: mTLS is optional ────────────────────────────────────────────────

/// MTLS-05: build_server_config with mtls_enabled=false succeeds without client verifier.
#[test]
fn test_mtls_disabled_config() {
    let dev = generate_dev_certs().unwrap();
    let ca_der = pem_to_ca_der(&dev.ca_cert_pem);
    let chain = pem_to_cert_chain(&dev.server_cert_pem);
    let key = pem_to_key(&dev.server_key_pem);

    let cfg = build_server_config(&ca_der, chain, key, false, false);
    assert!(
        cfg.is_ok(),
        "build_server_config(mtls_enabled=false) should succeed"
    );
    let server_config = cfg.unwrap();
    assert_eq!(
        server_config.alpn_protocols,
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    );
}

/// MTLS-05: build_server_config with mtls_enabled=true, mtls_required=false (optional mode).
#[test]
fn test_mtls_optional_config() {
    let dev = generate_dev_certs().unwrap();
    let ca_der = pem_to_ca_der(&dev.ca_cert_pem);
    let chain = pem_to_cert_chain(&dev.server_cert_pem);
    let key = pem_to_key(&dev.server_key_pem);

    let cfg = build_server_config(&ca_der, chain, key, true, false);
    assert!(
        cfg.is_ok(),
        "optional mTLS (mtls_required=false) should succeed"
    );
}
