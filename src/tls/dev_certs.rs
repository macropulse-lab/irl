use anyhow::Result;
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};

/// PEM-encoded certificates and keys for local development / CI.
/// Never use in production.
pub struct DevCerts {
    pub ca_cert_pem: String,
    pub ca_key_pem: String,
    pub server_cert_pem: String,
    pub server_key_pem: String,
    pub client_cert_pem: String,
    pub client_key_pem: String,
}

/// Generate an ephemeral CA, server certificate, and client certificate for
/// local dev/CI mTLS testing. Uses rcgen 0.13 API (self_signed / signed_by).
pub fn generate_dev_certs() -> Result<DevCerts> {
    // ── CA ────────────────────────────────────────────────────────────────────
    let ca_key = KeyPair::generate()?;
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "IRL-Engine Dev CA");
    let ca_cert = ca_params.self_signed(&ca_key)?;

    // ── Server certificate ────────────────────────────────────────────────────
    let server_key = KeyPair::generate()?;
    let mut server_params = CertificateParams::new(vec!["localhost".to_string()])?;
    server_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "irl-engine-server");
    let server_cert = server_params.signed_by(&server_key, &ca_cert, &ca_key)?;

    // ── Client certificate ────────────────────────────────────────────────────
    let client_key = KeyPair::generate()?;
    let mut client_params = CertificateParams::default();
    client_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "dev-agent-01");
    let client_cert = client_params.signed_by(&client_key, &ca_cert, &ca_key)?;

    Ok(DevCerts {
        ca_cert_pem: ca_cert.pem(),
        ca_key_pem: ca_key.serialize_pem(),
        server_cert_pem: server_cert.pem(),
        server_key_pem: server_key.serialize_pem(),
        client_cert_pem: client_cert.pem(),
        client_key_pem: client_key.serialize_pem(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_dev_certs_returns_ok() {
        let certs = generate_dev_certs().expect("dev cert generation failed");
        assert!(certs.ca_cert_pem.contains("CERTIFICATE"));
        assert!(certs.server_cert_pem.contains("CERTIFICATE"));
        assert!(certs.client_cert_pem.contains("CERTIFICATE"));
        assert!(certs.ca_key_pem.contains("PRIVATE KEY"));
        assert!(certs.server_key_pem.contains("PRIVATE KEY"));
        assert!(certs.client_key_pem.contains("PRIVATE KEY"));
    }
}
