# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.2.x   | Yes       |
| < 1.2   | No        |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Email **security@macropulse.live** with:

1. A clear description of the vulnerability
2. Steps to reproduce (proof-of-concept if available)
3. Affected versions
4. Potential impact

You will receive an acknowledgement within **48 hours** and a resolution timeline within **7 days**.

## Scope

In scope:
- IRL Engine API endpoints (`/irl/authorize`, `/irl/bind-execution`, `/irl/agents`, `/irl/heartbeat`)
- Bearer token authentication and authorization bypass
- Cryptographic integrity (Ed25519 verification, heartbeat mta_ref, SHA-256 reasoning_hash)
- Policy engine bypass (notional caps, regime restrictions, side filters)
- Audit trail tampering or gap injection
- GDPR purge endpoint misuse
- KMS integration (AWS KMS, HashiCorp Vault key exposure)

Out of scope:
- Issues in third-party Rust crates (report upstream)
- Social engineering
- Denial of service without a reproducible code path

## Disclosure Policy

We follow coordinated disclosure. Once a fix is shipped, we will:

1. Publish a security advisory on GitHub
2. Credit the reporter (unless anonymity is requested)
3. Tag the patched release in the changelog

Thank you for helping keep IRL Engine secure.
