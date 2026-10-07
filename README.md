![version](https://img.shields.io/badge/version-v1.3.0-0a0a0a?style=flat-square)
![rust edition](https://img.shields.io/badge/rust-2021_edition-b7410e?style=flat-square&logo=rust)
![license](https://img.shields.io/badge/license-FSL--1.1--ALv2-2d6a4f?style=flat-square)
![sandbox](https://img.shields.io/badge/sandbox-live-1a7f37?style=flat-square)

# IRL Engine

**Immutable Reasoning Log** — a pre-execution compliance gateway that cryptographically seals every autonomous trading decision before it reaches an exchange.

Autonomous AI agents make trading decisions faster than any human oversight mechanism can follow. IRL does not slow them down. It inserts a cryptographic checkpoint between intent and execution: the agent's complete reasoning state is hashed, the decision is evaluated against verified market regime data, and the result is recorded in a tamper-evident audit chain before a single order is submitted. When regulators, risk officers, or counterparties need to reconstruct what the agent knew and why it acted, the proof is already there.

---

## How It Works

The authorize → bind chain ties agent reasoning to exchange execution through a seven-step sequence. Steps 1–4 happen before any order is placed; steps 5–7 close the chain after the exchange confirms.

1. **Register** — Agent submits model hash, notional cap, and permitted regime set to `POST /irl/agents`. IRL creates an entry in the Multi-Agent Registry (MAR).

2. **Authorize** — Before placing any order, the agent calls `POST /irl/authorize` with a complete `CognitiveSnapshot`: model identity, hyperparameter checksum, prompt version, feature schema, action intent, asset, venue, quantity, and notional.

3. **Verify identity** — IRL checks the model hash and agent status against the MAR. Unknown or suspended agents are rejected immediately.

4. **Evaluate policy** — The policy engine checks the requested action against the agent's permitted regime set and notional cap, scaled by the current regime's `max_notional_scale` from the MTA. If any constraint is violated, the request is denied.

5. **Seal the snapshot** — IRL computes `reasoning_hash = SHA-256(RFC 8785 canonical JSON of the full snapshot)` and returns it to the agent. The agent embeds this hash in the exchange order metadata before submission.

6. **Place the order** — The agent places the order through its normal exchange pathway. IRL is not in the execution path.

7. **Bind execution** — The agent calls `POST /irl/bind-execution` with the exchange `tx_id`. IRL computes `final_proof = SHA-256(reasoning_hash ‖ exchange_tx_id)`, reconciles executed parameters against sealed intent, and records a permanent `MATCHED`, `DIVERGENT`, or `EXPIRED` verdict. The audit chain is closed.

Traces are written with bitemporal timestamps (`valid_time` + `transaction_time`) and are never deleted. Every record is final.

---

## Independent Verification (v1.3)

The audit chain is verifiable by parties who do not trust the IRL operator.

**Export a proof bundle** — a self-contained evidence file covering a time range: every trace (reasoning_hash, final_proof, verdict, bitemporal timestamps) plus every overlapping daily Merkle anchor with its full ordered leaf list and raw OpenTimestamps receipt.

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "https://your-irl-host/irl/attestation?from=2026-05-01T00:00:00Z&to=2026-06-01T00:00:00Z" \
  > may-2026.bundle.json
```

**Verify it offline** — no network, no database, no MacroPulse:

```bash
irl-verify may-2026.bundle.json
# 1. recomputes final_proof = SHA-256(reasoning_hash || "||" || exchange_tx_id) for every bound trace
# 2. recomputes every anchor's Merkle root from its leaf list
# 3. checks every trace's inclusion in the anchor covering its txn_time
# exit 0 = PASS, non-zero = the bundle is inconsistent

irl-verify may-2026.bundle.json --dump-ots ./ots
ots verify ./ots/anchor-0.ots
# ties each Merkle root to a Bitcoin block via the standard OpenTimestamps client
```

The bundle embeds its own spec block, so it remains interpretable without access to this codebase. Hand it to an auditor, an allocator, or a regulator — they can verify the chain end-to-end against Bitcoin headers with zero trust in the operator.

---

## Free and Open

IRL is free to use, self-host and modify, and its source is open to read. Every capability in this repository (registry, pre-execution policy, seal and bind, the bitemporal trace log, Bitcoin anchoring, proof bundles, the public anchor feed, signed regime binding and anti-replay) is available to everyone, self-hosted or on the public sandbox. Verification is free for everyone, forever.

| Component | What it is |
|---|---|
| [IRL Engine](https://github.com/norve-labs/irl) (this repo) | The server: policy, seal, bind, anchor |
| [irl-gateway](https://github.com/norve-labs/irl-gateway) | MCP server that puts any AI agent's trades through IRL |
| [irl-verify](https://github.com/norve-labs/irl-verify) | Offline proof-bundle verifier |
| [irl-sdk-python](https://github.com/norve-labs/irl-sdk-python), [irl-sdk-ts](https://github.com/norve-labs/irl-sdk-ts) | Client SDKs |

The engine is licensed under the [Functional Source License](LICENSE.md) (FSL-1.1-ALv2): any use is permitted, including commercial use inside your own firm, except offering IRL to others as a competing product or service. Every release automatically becomes Apache 2.0 two years after it is published. The gateway, SDKs and verifier are MIT.

A hosted offering for teams may come later, shaped by what early users need. Tell us in the [gateway issues](https://github.com/norve-labs/irl-gateway/issues).

Roadmap: TEE execution attestation, Wasm policy modules, ZK compliance proofs.

---

## Market Truth Anchor (MTA) Interface

IRL is signal-agnostic. It does not hardcode any regime taxonomy, signal provider, or market classification scheme. The MTA is an abstraction over any cryptographically signed source of regime state.

| `MTA_MODE` | Description |
|---|---|
| `none` | No regime operator. IRL seals and audits every decision and enforces the agent's own controls (status, model hash, notional cap, venue and asset allowlists); all sides are permitted. Traces record `signal_mode = "none"`. No external service or credentials needed. **The default when no `MTA_URL` is set.** |
| `external` | Connects to a signed-regime operator at `MTA_URL` (for example MacroPulse at `https://api.macropulse.live`, or your own service speaking the same format) and verifies its Ed25519 signature (`MTA_PUBKEY_HEX`). IRL reads three normalized fields: `risk_level`, `max_notional_scale` (multiplier on the agent's notional cap) and `allowed_sides`. Regime labels and model logic stay private to the operator. **The default when `MTA_URL` is set.** Legacy names `macropulse` and `custom` still work. |
| `mock` | Evaluation and CI only. Fixed permissive regime state. |

To plug in a regime source in-process instead, implement the `MtaClient` trait in Rust.

Agent-level controls apply in every mode. They are set at `POST /irl/agents` and checked on every authorize: `status` (suspend an agent to stop it immediately), `model_hash_hex`, `max_notional`, `allowed_regimes`, `allowed_venues` and `allowed_assets`. The allowlists are case-insensitive, and null means unrestricted. `max_leverage` is stored but not enforced, because the authorize request carries no leverage figure.

In `external` mode with `LAYER2_ENABLED=true`, each authorize call must include an `mta_ref` — a sequence ID from a recent signed heartbeat. IRL verifies that the heartbeat is current and has not been replayed. Staleness and replay are rejected before the policy evaluation runs.

---

## Get a free token (hosted at norve.dev)

```bash
uvx irl-gateway init            # signup + agent registration + MCP config, in one step
# or by hand:
curl -X POST https://norve.dev/irl/signup -H "Content-Type: application/json"   -d '{"client_name": "my-agent", "contact": "optional@example.com"}'
```

Self-serve tokens are **paper tier**: they authorize only on paper venues
(`venue_id` starting with `paper`), own up to 3 agents and up to 500
authorizations a day. Ask the operator for a full token to trade live.
Every token sees only the agents it registered.

---

## Quick Start

### Docker Standalone (no external dependencies)

The standalone compose file bundles PostgreSQL and a mock MTA. No MacroPulse account or external service is required.

```bash
git clone https://github.com/norve-labs/irl.git
cd irl-engine

docker compose -f docker-compose.standalone.yml up -d
```

IRL is available at `http://localhost:4000`. Interactive API docs (Swagger UI) are served at `http://localhost:4000/swagger-ui/` **only when `EXPOSE_DOCS=true`** — they are disabled by default so the API surface is not published on untrusted deployments.

### Cargo Build

```bash
cp .env.example .env
# Minimum required: DATABASE_URL and IRL_API_TOKENS
# For evaluation: MTA_MODE=mock and LAYER2_ENABLED=false

cargo build --release
./target/release/irl-engine
```

PostgreSQL 14+ is required. Run `sqlx migrate run` against the target database before first start, or set `AUTO_MIGRATE=true`.

---

## Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `DATABASE_URL` | yes | — | PostgreSQL connection string |
| `IRL_API_TOKENS` | yes | — | Comma-separated bearer tokens for API authentication |
| `MTA_MODE` | no | `external` if `MTA_URL` is set, else `none` | `external`, `none` or `mock` (`macropulse`/`custom` = `external`); an unknown value fails startup |
| `MTA_URL` | if `external` | — | MTA operator endpoint (e.g. `https://api.macropulse.live`) |
| `MTA_PUBKEY_HEX` | if `external` | — | Ed25519 public key, 64 hex characters |
| `LAYER2_MODE` | no | `both` | `legacy` (signed heartbeats only), `v2` (regime ref from `GET /irl/regime` + unique `(agent_id, client_order_id)`), or `both`. See docs/design/layer2-v2.md |
| `MTA_REF_GRACE_SECS` | no | `300` | v2: how long the previous regime ref is still accepted after a regime change |
| `LAYER2_ENABLED` | no | `true` (`false` when `MTA_MODE=none`) | Require signed MTA heartbeat reference on every authorize call. When enabled the engine fails closed at startup: if it cannot hydrate anti-replay state from the database it refuses to start rather than serve with replay protection silently disabled |
| `SHADOW_MODE` | no | `false` | Audit only — log and seal every request but never block. Safe for dry-run evaluation against production traffic |
| `BIND_SIZE_TOLERANCE` | no | `0.0001` | Quantity divergence tolerance before recording `DIVERGENT` (default: 0.01%) |
| `TRACE_EXPIRY_MS` | no | `3600000` | Time before an unbound `PENDING` trace is marked `EXPIRED` (default: 1 hour) |
| `KMS_PROVIDER` | no | `none` | `local` (AES-256 DEK envelope encryption) or `none` |
| `LOCAL_KMS_KEY` | if `local` | — | 32-byte hex key for local KMS |
| `KMS_KEY_VERSION` | if `local` | — | Key version label |
| `AUTO_MIGRATE` | no | `false` | Run database migrations on startup |
| `PORT` | no | `4000` | HTTP listen port |
| `WEBHOOK_URL` | no | — | POST target for regime-change events (e.g. `https://ops.example.com/hooks/irl`) |
| `WEBHOOK_SECRET` | if `WEBHOOK_URL` | — | HMAC-SHA256 secret for `X-IRL-Signature` header on webhook payloads |
| `METRICS_ENABLED` | no | `true` | Expose Prometheus `/metrics` endpoint |
| `METRICS_TOKEN` | no | — | Bearer token required for `/metrics` scrape (open when unset) |
| `EXPOSE_DOCS` | no | `false` | Serve Swagger UI at `/swagger-ui` and the OpenAPI schema at `/openapi.json`. Off by default so the API surface is not published on untrusted deployments; enable on sandboxes and local dev |
| `MERKLE_V2_ENABLED` | no | `false` | Anchor period roots with RFC-6962 domain-separated hashing (leaf `0x00` / node `0x01`). Enabling this closes the second-preimage weakness in the legacy `SHA256(l‖r)` construction |
| `SIGNUP_ENABLED` | no | `false` | Serve `POST /irl/signup` (self-serve paper-tier tokens). Off by default so a self-hosted engine never exposes it by surprise |
| `SIGNUP_PER_IP_PER_DAY` / `SIGNUP_DAILY_CAP` | no | `3` / `100` | Signups per requester IP (IPv6: per /64) and in total, per rolling 24 h |
| `SIGNUP_MAX_AGENTS` / `SIGNUP_MAX_TRACES_PER_DAY` | no | `3` / `500` | Agents and authorizations per paper-tier token (per rolling 24 h) |
| `SNAPSHOT_V2_ENABLED` | no | `false` | Seal traces with the split public/private commitment format. Leave OFF until a staging round-trip verification has been run — enabling it changes sealed-hash inputs |

---

## SDK Examples

### Python

```bash
pip install irl-sdk
```

```python
import asyncio
from irl_sdk import IRLClient, AuthorizeRequest, TradeAction, OrderType

async def run():
    async with IRLClient(
        irl_url="https://norve.dev",
        api_token="your-token",
    ) as client:
        result = await client.authorize(AuthorizeRequest(
            agent_id="your-agent-uuid",
            model_id="my-model-v1",
            model_hash_hex="your-model-sha256",
            action=TradeAction.LONG,
            asset="BTC-USD",
            order_type=OrderType.MARKET,
            venue_id="coinbase",
            quantity=0.1,
            notional=6500.0,
            notional_currency="USD",
        ))

        assert result.authorized
        # Embed result.reasoning_hash in exchange order metadata before submitting

        tx_id = await exchange.place_order(reasoning_hash=result.reasoning_hash)

        await client.bind_execution(
            trace_id=result.trace_id,
            exchange_tx_id=tx_id,
            execution_status="Filled",
            asset="BTC-USD",
            executed_quantity=0.1,
            execution_price=65000.0,
        )

asyncio.run(run())
```

### TypeScript

```bash
npm install irl-sdk
```

```ts
import { IRLClient } from "irl-sdk";

const client = new IRLClient({
  irlUrl: "https://norve.dev",
  apiToken: process.env.IRL_API_TOKEN!,
});

const result = await client.authorize({
  agent_id: "your-agent-uuid",
  model_id: "my-model-v1",
  model_hash_hex: "your-model-sha256",
  action: "Long",
  asset: "BTC-USD",
  venue_id: "CBSE",
  quantity: 0.1,
  notional: 6500,
});

if (result.authorized) {
  // Embed result.reasoning_hash in exchange order metadata before submitting
  const txId = await exchange.placeOrder({ reasoning_hash: result.reasoning_hash });

  await client.bindExecution({
    trace_id: result.trace_id,
    exchange_tx_id: txId,
    execution_status: "Filled",
    asset: "BTC-USD",
    executed_quantity: 0.1,
    execution_price: 65000,
  });
}

await client.close();
```

---

## API Reference

All endpoints except `/irl/health`, `/irl/anchors` and `/irl/signup` require `Authorization: Bearer <token>`.

| Method | Route | Description |
|---|---|---|
| `GET` | `/irl/health` | Liveness check |
| `POST` | `/irl/signup` | Self-serve paper-tier token (when `SIGNUP_ENABLED=true`) |
| `GET` | `/irl/anchors` | Public Merkle anchor feed |
| `POST` | `/irl/agents` | Register an agent (model hash, notional cap, regime permissions) |
| `GET` | `/irl/agents` | List all registered agents (admin only) |
| `GET` | `/irl/agents/:id` | Retrieve agent profile |
| `PATCH` | `/irl/agents/:id/status` | Suspend or deregister an agent |
| `POST` | `/irl/authorize` | Seal a CognitiveSnapshot, receive `reasoning_hash` |
| `POST` | `/irl/authorize/batch` | Authorize up to 50 intents in one round-trip; errors embedded inline |
| `POST` | `/irl/bind-execution` | Bind exchange confirmation, receive `final_proof` |
| `GET` | `/irl/trace/:id` | Full audit record for a trace (forensic replay) |
| `GET` | `/irl/trace/:id/chain` | Full causal ancestry chain for multi-agent traces |
| `GET` | `/irl/pending` | Traces awaiting bind-execution |
| `GET` | `/irl/orphans` | `DIVERGENT` and `EXPIRED` traces |
| `GET` | `/irl/traces` | Paginated trace list with filters |
| `GET` | `/irl/shadow-violations` | Traces intercepted by shadow mode |
| `GET` | `/irl/admin/audit-log` | Paginated admin audit log (admin only) |
| `GET` | `/irl/admin/evidence` | SOC 2 evidence ZIP: `?from=YYYY-MM-DD&to=YYYY-MM-DD` (admin only) |
| `GET` | `/irl/admin/shadow-mode` | Current shadow mode state (admin only) |
| `POST` | `/irl/admin/shadow-mode` | Enable / disable shadow mode (admin only) |
| `POST` | `/irl/admin/gdpr-erase/:agent_id` | GDPR Article 17 erasure (admin only) |
| `POST` | `/irl/admin/tokens` | Issue a new API token (admin only) |
| `DELETE` | `/irl/admin/tokens/:id` | Revoke an API token (admin only) |
| `GET` | `/metrics` | Prometheus metrics endpoint |

Full request and response schemas are available at the sandbox Swagger UI: `https://norve.dev/swagger-ui/`

---

## Architecture

IRL is a single Axum 0.7 service backed by PostgreSQL. All components run in-process.

| Component | Source | Responsibility |
|---|---|---|
| **Multi-Agent Registry (MAR)** | `registry.rs` | Agent lifecycle: model hash pinning, notional caps, regime permissions, active/suspended status |
| **Policy engine** | `policy.rs` | Evaluates each authorize request against MAR constraints and current MTA regime state |
| **Seal module** | `seal.rs` | RFC 8785 canonical JSON serialization + SHA-256 hashing of CognitiveSnapshot |
| **Heartbeat verifier** | `heartbeat.rs` | Ed25519 signature verification, sequence ID tracking, anti-replay enforcement (L2) |
| **Snapshot store** | `snapshot.rs` | Bitemporal persistence of CognitiveSnapshot records |
| **Binding verifier** | `binding.rs` | Post-trade reconciliation, `final_proof` computation, `MATCHED`/`DIVERGENT`/`EXPIRED` verdict |
| **Merkle anchor** | `merkle.rs` | Daily OpenTimestamps anchoring of the audit log leaf set to Bitcoin |
| **KMS layer** | `kms.rs` | AWS KMS, HashiCorp Vault, or local AES-256 DEK envelope encryption |
| **Shadow mode** | `shadow_mode.rs` | Intercepts policy decisions and converts blocks to audit-only observations |
| **Backfill** | `backfill.rs` | Replay and re-seal historical snapshots for migration or forensic reconstruction |
| **GDPR** | `gdpr.rs` | Right-to-erasure handler; soft-purges agent data while preserving audit integrity |
| **Token manager** | `token_manager.rs` | Bearer token issuance, rotation, and revocation |
| **Metrics** | `metrics.rs` | Prometheus counters and histograms for authorize latency, bind rate, divergence rate, MAR size |

---

## Compliance Mapping

| Regulation | Provision | How IRL addresses it |
|---|---|---|
| **MiFID II Article 17** | Algorithmic trading — organisational requirements and pre-trade controls | Pre-execution authorization gate with cryptographic proof of intent; full audit trail per decision; model hash pinning ties each trace to a specific deployed model version |
| **EU AI Act** | High-risk AI system obligations — transparency, traceability, human oversight capability | Immutable, bitemporal trace log; CognitiveSnapshot records complete epistemic state; Merkle anchoring provides tamper-evidence independent of the IRL operator |
| **SEC Rule 15c3-5** | Market Access Rule — pre-trade risk controls for broker-dealers | Notional cap enforcement per agent per regime; side restrictions enforced before any order is placed; audit log available for regulatory examination |
| **DORA** | Digital Operational Resilience Act — ICT risk and incident reporting | Prometheus metrics for operational visibility; shadow mode for resilience testing without disrupting live control; bitemporal records support incident reconstruction |

---

## Ecosystem

| Resource | URL |
|---|---|
| Sandbox | `https://norve.dev` |
| Swagger UI | `https://norve.dev/swagger-ui/` |
| Public documentation | `https://github.com/norve-labs/irl-public-docs` |
| MCP gateway | `https://github.com/norve-labs/irl-gateway` |
| Python SDK | `https://github.com/norve-labs/irl-sdk-python` |
| TypeScript SDK | `https://github.com/norve-labs/irl-sdk-ts` |
| Example regime source (MacroPulse) | `https://macropulse.live` |

---

## License

Functional Source License 1.1, Apache 2.0 future license (FSL-1.1-ALv2). See [`LICENSE.md`](LICENSE.md).

In short, you may use, copy, modify and redistribute IRL for any purpose except a Competing Use, meaning offering it, or something substantially similar, to others as a commercial product or service. Each version becomes available under Apache 2.0 on the second anniversary of its release. To resell, embed or host IRL for others, ask for a commercial license.

Questions, ideas and bug reports: [open an issue](https://github.com/norve-labs/irl-gateway/issues) or write to hello@macropulse.live.
