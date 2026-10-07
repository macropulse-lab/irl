# Changelog

All notable changes to IRL Engine are documented here.
Follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

### Added
- **Agent trading scope** — `allowed_assets` (new, migration 027) and `allowed_venues` (previously
  stored but never checked) are now enforced at `/irl/authorize`: an out-of-scope request is rejected
  with 403 `ASSET_UNAUTHORIZED` / `VENUE_UNAUTHORIZED`. Case-insensitive; null = unrestricted.
  Settable at `POST /irl/agents` and in the Python SDK's `register_agent`.
- **Public source** at [norve-labs/irl](https://github.com/norve-labs/irl): a history-free
  export made by `scripts/publish-public.sh` (private planning, business and operations material
  excluded; gitleaks-gated with `.gitleaks.toml`). Replaces the retired `IRL-engine-AX`.
- **One IRL site.** irl.macropulse.live leads with the MCP gateway and merges the strongest parts of
  the former macropulse.live/irl page (ownership gap, tamper demo, trust model, adoption path,
  regulation table) with live stats from `/irl/anchors`. macropulse.live/irl now redirects here.
- **Whitepaper v5.0** and updated public docs: free and source-available, standalone mode, agent
  mandates, Layer 2 v2, and a new section on the IRL Gateway (MCP).

### Changed
- **License: FSL-1.1-ALv2** (`LICENSE.md`). Free for any use except offering IRL to others as a
  competing product or service; each release becomes Apache 2.0 two years after publication. The
  gateway, SDKs and verifier stay MIT. Paid per-agent tiers are withdrawn; IRL is free to use.
- **Dependencies:** all 16 Dependabot alerts resolved (openssl 0.10.81, quinn-proto 0.11.19,
  rustls-webpki 0.103.15, rand 0.8.8, AWS SDK crates; `aws-sdk-kms` without the legacy rustls 0.21
  stack; prometheus 0.14 / protobuf 3.7.2).
- **IRL runs without a regime operator.** `MTA_MODE=none` no longer requires `MTA_URL` /
  `MTA_PUBKEY_HEX`, and Layer 2 defaults off in that mode (nothing to bind to). With `MTA_MODE`
  unset, IRL uses `external` when `MTA_URL` is set and `none` otherwise, so existing deployments
  are unchanged. `external` is the new name for the operator mode (`macropulse` and `custom`
  remain aliases).
- An unrecognised `MTA_MODE` value now fails startup instead of silently selecting the operator mode.

---

## [1.3.0] — 2026-06-10

### Added
- **Proof bundle export** — `GET /irl/attestation?from=&to=[&agent_id=]` returns a self-contained
  evidence file: every trace in the period plus every overlapping Merkle anchor with its full
  ordered leaf list and raw OpenTimestamps receipt (base64). Designed for handoff to auditors,
  allocators, and regulators.
- **`irl-verify` offline verifier CLI** — verifies a proof bundle with no network, no database,
  and no trust in the IRL operator: recomputes every `final_proof`, recomputes every Merkle root
  from leaves, and checks every trace's inclusion in its covering anchor. `--dump-ots` extracts
  receipts for independent Bitcoin verification with the standard `ots` client. Exit code 0 = PASS.
- **Public anchor transparency feed** — `GET /irl/anchors` (no auth) returns the last 100 daily
  Merkle anchors: period bounds, leaf count, root hex, OTS status. Roots reveal nothing about
  trace contents; publishing them is what makes the chain publicly auditable.

---

## [1.2.0] — 2026-04-14

### Added
- **TypeScript SDK** (`irl-sdk` on npm) — full L2 support including `bindExecution()` and auto-heartbeat fetch
- **KMS integration** — AWS KMS, HashiCorp Vault, and local key backends via `token_manager.rs`
- **`MTA_MODE=none`** — pure audit rail with no external signal; all sides permitted, notional caps still enforced; traces record `signal_mode="none"`. Valid for production when the firm manages risk externally.
- **Shadow mode hardening** — `SHADOW_MODE=true` no longer affects heartbeat sequence counters; shadow traces are clearly flagged in the audit log
- **Evidence export binary** — `irl-engine-evidence-export` for generating CFTC/SEC-ready audit packages
- **OpenAPI schema** — `openapi.rs` generates spec at `/openapi.json`; Swagger UI at `/swagger-ui/`

### Fixed
- **Pipeline restart race** — heartbeat sequence counter now persisted across restarts; no more sequence gaps after container redeploy
- **Bitemporal clock drift** — `time.rs` uses monotonic clock for `valid_time` and wall clock for `transaction_time`; no more out-of-order records on NTP corrections

### Changed
- `POST /irl/authorize` response now includes `shadow_blocked: bool` field indicating whether the request would have been blocked if not in shadow mode
- Prometheus histogram buckets tuned for 1ms–500ms range (p99 under 8ms in production)

---

## [1.1.0] — 2026-03-15

### Added
- **Layer 2 — Cryptographic regime binding**
  - `GET /irl/heartbeat` endpoint proxied through MacroPulse MTA
  - `heartbeat.rs` — Ed25519 signature verification, mta_ref computation, anti-replay sequence enforcement
  - `mta.rs` — MTA client trait with MacroPulse, Custom, None, and Mock implementations
  - `verifier.rs` — heartbeat drift window enforcement (`MAX_HEARTBEAT_DRIFT_MS`)
- **Python SDK** (`irl-sdk` on PyPI) — async client with L2 heartbeat auto-fetch, full API coverage
- **Merkle anchoring** — `merkle.rs` — daily OpenTimestamps anchoring of the regime hash to Bitcoin
  - `irl.merkle_anchors` table (bitemporal)
  - Background worker runs at 02:00 UTC daily
- **Backfill** — `backfill.rs` — re-seals historical traces with MTA data for pre-L2 records
- **GDPR** — `DELETE /irl/gdpr/purge/{agent_id}` — irreversible anonymisation, compliant with GDPR Art. 17
- **Encryption** — `encryption.rs` — field-level encryption for agent PII at rest (AES-256-GCM)

### Fixed
- Agent registry lookup was O(n) on every authorize request — now indexed by `agent_id` with prepared statements

---

## [1.0.0] — 2026-02-01

### Added
- **Core authorize→bind audit chain**
  - `POST /irl/authorize` — CognitiveSnapshot sealing, SHA-256(RFC 8785), policy checks, reasoning_hash generation
  - `POST /irl/bind-execution` — exchange confirmation binding, final_proof computation, MATCHED/DIVERGENT/EXPIRED record
- **Multi-Agent Registry (MAR)**
  - `POST /irl/agents` — agent registration with model hash, notional cap, allowed regimes
  - `GET /irl/agents/{agent_id}` — agent metadata
  - `PATCH /irl/agents/{agent_id}` — update caps or status
  - `DELETE /irl/agents/{agent_id}` — deactivate (soft delete, bitemporal)
- **Policy engine** — `policy.rs` — regime permission enforcement, notional cap × regime scale, side restrictions
- **Audit trail** — `audit.rs` — bitemporal `irl.traces` table; no deletes ever; valid_time + transaction_time
- **Shadow mode** — `SHADOW_MODE=true` — audit-only mode; all authorizations pass, violations logged
- **Asset registry** — `asset.rs` — per-asset notional and quantity limits
- **Authentication** — `IRL_API_TOKENS` env var; Bearer token middleware
- **Rate limiting** — per-token sliding window via `rate_limit.rs`
- **Prometheus metrics** — `metrics.rs` — authorize latency histogram, policy violation counter, active agent gauge
- **Docker Compose** — standalone stack (IRL Engine + PostgreSQL 16)
- **Database migrations** — 10 SQL migration files under `migrations/`

[1.2.0]: https://github.com/norve-labs/irl/releases/tag/v1.2.0
[1.1.0]: https://github.com/norve-labs/irl/releases/tag/v1.1.0
[1.0.0]: https://github.com/norve-labs/irl/releases/tag/v1.0.0
