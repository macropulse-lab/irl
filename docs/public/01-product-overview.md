# What is IRL?

*v2.0 · October 2026*

## One-Line Answer

IRL is a **pre-execution compliance gateway** for AI agents that trade. It checks every order against the agent's mandate before it reaches the exchange, seals the reasoning, reconciles the fill, and anchors the record to Bitcoin. It runs on its own, or bound to a signed regime signal you trust. AI agents connect through the IRL Gateway, an MCP server (`pip install irl-gateway`).

---

## The Problem It Solves

Every autonomous trading agent has the same structural problem:

> The agent reasons about the market, then acts. But there is no cryptographic
> link between the reasoning and the action. If a trade goes wrong — or a
> regulator asks — you cannot prove what the agent knew, what it was allowed
> to do, or whether the exchange executed what was actually authorised.

This is the **Ownership Gap**: the missing chain of custody between AI
reasoning and market execution.

Manual logging doesn't close it. Post-hoc reconstruction doesn't close it.
Attestation services that record after the fact don't close it.

IRL closes it — before the order leaves the firm.

---

## What It Is Not

IRL is **not** replacing anything you already have:

| System | What it does | IRL's relationship |
|--------|-------------|-------------------|
| Execution Management System (EMS) | Smart order routing, algo execution | IRL sits upstream — it authorises the intent before the EMS routes it |
| Order Management System (OMS) | Portfolio-level position and order tracking | IRL's trace ID can be attached to OMS records as a compliance reference |
| Risk system | Pre-trade and real-time risk limits | IRL enforces regime-aware policy; risk systems enforce portfolio-level limits. Complementary. |
| Trade surveillance | Post-trade pattern detection | IRL is pre-trade and real-time. Surveillance uses IRL traces as evidence, not reconstructed logs. |
| Audit logging | Recording what happened | IRL creates cryptographic proof of intent before it happens. Fundamentally different. |

No existing product provides a cryptographic, pre-execution chain of custody
that is both signal-agnostic and hardware-rootable. Risk systems enforce limits,
blockchains provide immutability after the fact, and audit logs record what
happened. IRL is the first to seal intent before execution and bind it
cryptographically to exchange outcomes. You are not displacing a vendor.
You are filling a structural gap.

---

## Three Layers

Each layer adds one guarantee. These are not price tiers: L1 and L2 ship in
the engine and are free to use; L3 is research.

### L1 — Audit rail
*Prove what happened. Operational in under a day.*

- Pre-execution mandate enforcement: notional cap, allowed assets and venues, agent status
- Cryptographic reasoning seal (SHA-256 / RFC 8785)
- Bitemporal audit ledger (tamper-evident, replay-safe)
- Multi-Agent Registry (fleet identity and governance)
- Post-trade verifier (MATCHED / DIVERGENT / EXPIRED lifecycle)
- REST API — wraps any existing bot in ~20 lines of code
- **Shadow mode** — `SHADOW_MODE=true` logs policy violations without blocking; use to instrument your agent fleet before enabling enforcement

The sidecar exposes a REST API. Any agent is instrumented by adding a
pre-flight call to `/irl/authorize` and a post-trade call to
`/irl/bind-execution`. For a typical Python bot, this is under 20 lines of
code, with no changes to routing, execution, or existing infrastructure.

**Target:** Any firm running autonomous agents that needs audit-ready compliance
without changing its infrastructure. Works at any trading frequency — from
intraday systematic strategies to high-volume AI agents. For agents generating
> 1 000 decisions per second, see the High-Volume (Batch) Mode described in the
whitepaper (§21); standard mode handles ~5 000 req/s per instance with
sub-200 µs seal latency.

**Requires:** A signed MTA feed — MacroPulse turnkey, or any Ed25519-signed
source via the `MtaClient` interface.

---

### L2 — Signed market truth
*Prove what the market was.*

Everything in L1, plus:

- **Layer 2 signed heartbeats** — monotonic sequence + Ed25519 signature
  prevents replay attacks. This ensures a stale or replayed market regime
  cannot be used to authorise a trade, closing a class of sophisticated
  manipulation that standard logging cannot detect.
- **MTA integration** — any signed regime source (MacroPulse turnkey, or your
  own via the `MtaClient` interface)
- **Compliance dashboard** — real-time feed of PENDING, DIVERGENT, and EXPIRED
  traces
- **Forensic replay** — any historical trade reconstructed from its sealed
  snapshot

**Target:** Hedge funds with LP reporting requirements, prop firms under SEC
scrutiny, any firm where "we logged it after we knew the outcome" is a
liability.

**Requires:** A heartbeat broadcaster and a signed MTA source. MacroPulse
provides both turnkey; custom integrations are supported via the `MtaClient`
interface.

---

### L3 — Prove without revealing (research)
*For firms where compliance cannot reveal alpha.*

Everything in L2, plus:

- **TEE execution** (Intel TDX / AMD SEV) — policy runs in a hardware-attested
  enclave; the host operator cannot inspect or tamper with the enforcement
- **Wasm policy modules** — hot-reloadable sandboxed policy code runs inside
  the enclave; clients deploy custom compliance logic without touching engine
  code, and even the host operator cannot inspect or alter it
- **ZK compliance proofs** — prove that a trade passed all policy checks
  without revealing the agent's model, strategy logic, or proprietary features.
  The regime signal and policy thresholds remain visible (as required for
  verification), but the agent's internal state stays confidential.

The ZK layer is not complexity for its own sake. For a fund with proprietary
alpha encoded in its model features, a standard audit trail reveals the model.
ZK proofs allow the fund to prove compliance to a regulator without revealing
the strategy. That is the only way to make compliance compatible with alpha
preservation.

**Target:** Multi-strategy funds, quant shops with proprietary model IP,
any client operating under regulatory regimes that require proof-of-compliance
without disclosure.

**Requires:** TEE-capable infrastructure (Intel TDX or AMD SEV). Cloud
instances with confidential computing support are sufficient; dedicated
hardware is not required.

---

## IRL in the Stack

IRL is a sidecar — it does not replace any existing component. It intercepts
between the agent runtime and the exchange.

```
Agent Runtime  →  IRL Sidecar  →  Exchange
                   ↑
               MTA Operator
             (any Ed25519-signed
              regime signal)
```

The agent calls `/irl/authorize` before placing any order and `/irl/bind-execution`
after receiving the exchange confirmation. Everything else — EMS, OMS, risk
system, surveillance — continues unchanged. IRL adds a compliance layer in front
of the exchange without touching the execution path.

The MTA Operator is the only external dependency. MacroPulse operates the
reference implementation; any firm with a proprietary regime signal can serve
as its own MTA by implementing the single `MtaClient` trait. This is the
**open protocol** design: the audit chain, the seal mechanism, and the compliance
guarantees are identical regardless of which regime signal powers the decisions.

See **Diagram 6** in the diagrams reference for a full stack view.

---

## Who Is Forced to Adopt First?

IRL is not a nice-to-have. It is a response to specific regulatory and
operational pressure that is already live:

**1. Prop firms under SEC AI audit pressure**
The SEC's Division of Examinations has flagged AI-driven trading as a 2024–2026
examination priority (SEC Division of Examinations 2024–2026 Examination
Priorities, published January 2024). Firms using autonomous agents need to
demonstrate that those agents operated within defined parameters. Manual logs
don't satisfy this.

**2. Hedge funds with LP reporting requirements**
Institutional LPs are increasingly asking: "How do you know your AI didn't go
rogue?" IRL gives funds a concrete, auditable answer.

**3. Brokers enabling AI-driven client order flow**
A broker that routes orders from an autonomous agent shares liability for that
agent's behaviour. IRL creates a clean separation of proof: the agent's intent
was authorised, the broker routed it faithfully.

**4. Compliance teams at any firm scaling autonomous agents**
One agent is manageable. Ten agents across multiple strategies, venues, and
regimes is not. The Multi-Agent Registry gives compliance teams visibility and
control they cannot get from logs.

**5. Firms preparing for MiCA, DORA, or equivalent AI-governance mandates**
The EU AI Act (Article 12, traceability obligations, effective August 2024) and
DORA's ICT risk management requirements are moving toward mandatory
explainability and auditability for high-frequency decision systems. IRL is the
infrastructure layer that makes compliance technically possible.

---

## Cost of Non-Compliance

Firms without a cryptographic pre-execution audit trail face three concrete costs
that IRL eliminates:

**Regulatory response time.** When a regulator requests records for a specific
algorithmic trade, reconstruction from logs typically takes days to weeks. With
IRL, the full `Reasoning_Trace_v1` is retrievable in seconds by `trace_id`.

**Audit exposure.** Without a sealed record, you cannot prove the agent was
operating within its authorised parameters at the moment of the trade. IRL
produces `policy_result = ALLOWED` with a hash of the exact policy constraints
in effect — proof that cannot be manufactured after the fact.

**Incident liability.** When an autonomous agent causes a market incident, the
liability question is: "Was this trade authorised under the conditions that
existed at that time?" Without IRL, the answer is reconstructed. With IRL, it is
proven.

For regulatory fine benchmarks and liability framework detail, see the
**Compliance Guide** (08-compliance-guide.md).

---

## Competitive Landscape

```
                        Pre-trade        Post-trade
                        enforcement      reconstruction
                       ┌────────────────────────────────┐
Manual logging         │       ✗               ✗        │
Trade surveillance     │       ✗               ✓        │
Risk systems           │    partial*           ✗        │
Attestation services   │       ✗            partial     │
                       └────────────────────────────────┘
                              ↓
IRL                    │       ✓               ✓        │
                       │  + cryptographic  + replay-safe│
                       │  + regime-aware   + tamper-evident│
```

\* Risk systems may enforce limits pre-trade, but they do not produce a
cryptographically sealed reasoning record tied to the agent's inputs and
authorised intent. IRL complements them — it does not replace them.

The competitive moat is not the software. It is the combination of:
1. **The seal** — IRL is the entity that issues the cryptographic chain of custody. Any regime signal, any exchange, any agent fleet. The seal is what regulators and counterparties verify.
2. **Signal agnosticism** — firms with proprietary models don't have to expose their alpha to get compliance. They bring their own MTA. IRL seals it. No bundled solution can offer this.
3. **MacroPulse as turnkey MTA** — for firms without a proprietary signal, MacroPulse is the reference operator: signed, versioned, zero additional infrastructure.
4. **Incremental adoptability** — L1 in a day, L3 when mandated.

Any firm can build logging. Constructing a cryptographic chain of custody that
is sealed before execution and bound to exchange outcomes is a non-trivial
engineering problem. IRL solves it out of the box — and captures intent before
the order is placed, which is the only moment it can be captured honestly.

---

## Licensing

IRL is free to use. The engine is source-available under FSL-1.1-ALv2 (any
use except reselling it as a competing service; each release becomes Apache 2.0
after two years). The gateway, SDKs and verifier are MIT. Hosting or embedding
IRL for others needs a commercial licence: hello@macropulse.live.

---

## Summary

| | Manual Logging | Trade Surveillance | IRL |
|--|--|--|--|
| Pre-execution proof | ✗ | ✗ | **✓** |
| Tamper-evident | ✗ | ✗ | **✓** |
| Regime-aware policy | ✗ | ✗ | **✓** |
| Cryptographic chain | ✗ | ✗ | **✓** |
| Retroactive? | Yes | Yes | **No — sealed before order** |
| ZK privacy option | ✗ | ✗ | **✓ (L3)** |
| Drop-in deployment | — | No | **Yes (L1, <1 day)** |
