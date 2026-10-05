use anyhow::anyhow;
use axum::{
    extract::{Extension, Request},
    middleware::Next,
    response::Response,
};
use std::time::SystemTime;
use x509_parser::prelude::*;

/// Raw DER bytes of the peer's TLS client certificate.
/// Injected into request extensions by the TLS acceptor layer.
/// Empty Vec means no certificate was presented (plain HTTP or mTLS optional).
#[derive(Clone, Debug, Default)]
pub struct PeerCertDer(pub Vec<u8>);

/// Parsed client certificate info. Available as `axum::Extension<ClientCertInfo>`
/// in route handlers when the client presented a valid TLS certificate.
#[derive(Clone, Debug)]
pub struct ClientCertInfo {
    pub cn: String,
    pub not_after: SystemTime,
}

/// Parse a DER-encoded client certificate, extracting the CommonName and expiry.
pub fn parse_client_cert(der: &[u8]) -> anyhow::Result<ClientCertInfo> {
    let (_, cert) = X509Certificate::from_der(der)
        .map_err(|e| anyhow!("Failed to parse client cert: {e:?}"))?;
    let cn = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|attr| attr.as_str().ok())
        .ok_or_else(|| anyhow!("Client cert has no CommonName"))?
        .to_string();
    let not_after: SystemTime = cert.validity().not_after.to_datetime().into();
    Ok(ClientCertInfo { cn, not_after })
}

/// Tower middleware that reads the raw DER peer cert extension (PeerCertDer),
/// parses it, and injects ClientCertInfo into request extensions.
///
/// When no cert is present (plain HTTP or mTLS-optional with no cert offered),
/// the request proceeds unchanged — no ClientCertInfo extension is added.
pub async fn client_cert_middleware(
    Extension(peer_cert): Extension<PeerCertDer>,
    mut req: Request,
    next: Next,
) -> Response {
    if !peer_cert.0.is_empty() {
        match parse_client_cert(&peer_cert.0) {
            Ok(info) => {
                req.extensions_mut().insert(info);
            }
            Err(e) => {
                tracing::warn!("Failed to parse client cert DER: {e}");
            }
        }
    }
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, DnType, KeyPair};

    fn make_test_cert_der(cn: &str) -> Vec<u8> {
        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, cn);
        let key = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        cert.der().to_vec()
    }

    #[test]
    fn test_parse_valid_cert() {
        let der = make_test_cert_der("agent-01");
        let info = parse_client_cert(&der).unwrap();
        assert_eq!(info.cn, "agent-01");
    }

    #[test]
    fn test_parse_empty_returns_err() {
        assert!(parse_client_cert(&[]).is_err());
    }
}
