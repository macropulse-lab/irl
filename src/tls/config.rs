use anyhow::Result;
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::sync::Arc;

/// Build a rustls `ServerConfig` with the appropriate client certificate
/// verification policy based on `mtls_enabled` and `mtls_required`.
///
/// - `mtls_enabled=false`: no client certificate requested or verified
/// - `mtls_enabled=true, mtls_required=false`: client cert accepted if presented, optional
/// - `mtls_enabled=true, mtls_required=true`: client cert is mandatory
///
/// Always sets ALPN to `["h2", "http/1.1"]`.
pub fn build_server_config(
    ca_cert_der: &[u8],
    server_cert_chain: Vec<CertificateDer<'static>>,
    server_key: PrivateKeyDer<'static>,
    mtls_enabled: bool,
    mtls_required: bool,
) -> Result<Arc<ServerConfig>> {
    let mut config = if mtls_enabled {
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(ca_cert_der.to_vec()))
            .map_err(|e| anyhow::anyhow!("Failed to add CA cert to root store: {e}"))?;
        let roots = Arc::new(roots);

        let client_verifier = if mtls_required {
            WebPkiClientVerifier::builder(roots).build()?
        } else {
            WebPkiClientVerifier::builder(roots)
                .allow_unauthenticated()
                .build()?
        };

        ServerConfig::builder()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(server_cert_chain, server_key)?
    } else {
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(server_cert_chain, server_key)?
    };

    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::dev_certs::generate_dev_certs;
    use rustls_pemfile::{certs, private_key};

    fn load_dev_certs() -> (
        Vec<u8>,
        Vec<CertificateDer<'static>>,
        PrivateKeyDer<'static>,
    ) {
        let dev = generate_dev_certs().expect("dev certs");
        let ca_bytes = dev.ca_cert_pem.as_bytes().to_vec();
        let ca_certs: Vec<CertificateDer<'static>> = certs(&mut ca_bytes.as_slice())
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        let srv_bytes = dev.server_cert_pem.as_bytes().to_vec();
        let server_certs: Vec<CertificateDer<'static>> = certs(&mut srv_bytes.as_slice())
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        let key_bytes = dev.server_key_pem.as_bytes().to_vec();
        let key = private_key(&mut key_bytes.as_slice())
            .unwrap()
            .expect("private key");
        (ca_certs[0].as_ref().to_vec(), server_certs, key)
    }

    #[test]
    fn build_server_config_tls_disabled() {
        let (ca_der, cert_chain, key) = load_dev_certs();
        let cfg = build_server_config(&ca_der, cert_chain, key, false, false)
            .expect("build_server_config failed");
        assert_eq!(
            cfg.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
    }

    #[test]
    fn build_server_config_mtls_optional() {
        let (ca_der, cert_chain, key) = load_dev_certs();
        let cfg = build_server_config(&ca_der, cert_chain, key, true, false)
            .expect("build_server_config failed");
        assert_eq!(
            cfg.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
    }

    #[test]
    fn build_server_config_mtls_required() {
        let (ca_der, cert_chain, key) = load_dev_certs();
        let cfg = build_server_config(&ca_der, cert_chain, key, true, true)
            .expect("build_server_config failed");
        assert_eq!(
            cfg.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
    }
}
