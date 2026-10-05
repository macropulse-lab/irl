# IRL Diagrams — Mermaid Specs

*v1.0 · March 2026*

Professional diagrams for the whitepaper. Each block below is a Mermaid diagram
ready to render at mermaid.live or hand off to a designer as a structural spec.

---

## Diagram 1 — End-to-End Execution Flow

```mermaid
sequenceDiagram
    participant MTA as MTA Operator
    participant AG as Autonomous Agent
    participant IRL as IRL Engine
    participant EX as Exchange

    MTA->>IRL: Ed25519-signed regime broadcast<br/>{regime_id, risk_level, allowed_sides, mta_hash}
    Note over IRL: Caches MTA state (100ms TTL)

    AG->>IRL: POST /irl/authorize<br/>{agent_id, model_hash, intent, valid_time}

    rect rgb(240, 248, 255)
        Note over IRL: MAR Check
        IRL->>IRL: Verify agent Active
        IRL->>IRL: Verify model_hash matches registry
        IRL->>IRL: Verify regime in allowed_regimes (None = allow all)
        IRL->>IRL: Verify notional ≤ agent_cap × mta.max_notional_scale
    end

    rect rgb(240, 255, 240)
        Note over IRL: Snapshot Seal
        IRL->>IRL: Compute L_t fingerprint (4-part SHA-256)
        IRL->>IRL: Enforce valid_time < txn_time
        IRL->>IRL: reasoning_hash = SHA-256(canonical(S_t))
    end

    IRL-->>AG: {authorized: true, trace_id, reasoning_hash}
    Note over IRL: Trace stored as PENDING

    AG->>EX: Place order (includes reasoning_hash)
    EX-->>AG: {exchange_tx_id, filled_qty, price}

    AG->>IRL: POST /irl/bind-execution<br/>{trace_id, exchange_tx_id, asset, qty}

    rect rgb(255, 250, 240)
        Note over IRL: Reconciliation
        IRL->>IRL: Check asset match
        IRL->>IRL: Check |qty_delta| ≤ tolerance
        IRL->>IRL: final_proof = SHA-256(reasoning_hash ∥ exchange_tx_id)
    end

    IRL-->>AG: {verification_status: MATCHED, final_proof}
    Note over IRL: Trace sealed — immutable audit record
```

---

## Diagram 2 — Cognitive Snapshot Anatomy

```mermaid
block-beta
    columns 3

    block:snapshot["Cognitive Snapshot  S_t"]:3
        block:Rt["R_t — Reasoning State"]:1
            mta["MTA regime\n(operator-signed)"]
            policy["Policy decision\n(constraints → ALLOWED/HALTED)"]
            lf["L_t latent fingerprint\nSHA-256(model∥prompt∥schema∥hyperparams)"]
        end

        block:Et["E_t — Execution Intent"]:1
            action["Action\n(Long/Short/Neutral + size)"]
            asset["Asset + Venue"]
            qty["Quantity + Notional"]
            order_type["Order Type\n(MARKET/LIMIT/TWAP/VWAP)"]
        end

        block:tt["τ_t — Temporal Proof"]:1
            valid_t["valid_time\n(agent's clock at reasoning)"]
            txn_t["txn_time\n(IRL engine wall clock)"]
            constraint["Invariant:\nvalid_time < txn_time"]
        end
    end

    hash["reasoning_hash = SHA-256(RFC 8785 canonical JSON of S_t)"]:3
```

---

## Diagram 3 — Three-Layer Trust Model

```mermaid
graph TB
    subgraph L1["Layer 1 — Pre-Execution Gateway"]
        direction LR
        snap["Cognitive Snapshot"]
        seal["SHA-256 Seal"]
        bitemp["Bitemporal Constraint"]
        policy["Policy Engine"]
        mar["Multi-Agent Registry"]
    end

    subgraph L2["Layer 2 — Audit & Verification"]
        direction LR
        hb["Signed Heartbeat\n(anti-replay)"]
        ptv["Post-Trade Verifier\nPENDING→MATCHED/DIVERGENT/EXPIRED"]
        ledger["Immutable Bitemporal Ledger"]
    end

    subgraph L3["Layer 3 — Sovereign Execution (future)"]
        direction LR
        tee["TEE Enclave\n(Intel TDX / AMD SEV)"]
        wasm["Wasm Policy Module\n(hot-reload, sandboxed)"]
        zk["ZK Compliance Proof\n(prove policy without revealing alpha)"]
    end

    MTA["MTA Operator\n(Ed25519-signed regime)"] --> L1
    L1 --> L2
    L2 --> L3
    L1 --> Exchange["Exchange / OMS"]
    L3 --> Regulator["Regulator / Auditor"]

    style L1 fill:#dbeafe,stroke:#3b82f6
    style L2 fill:#dcfce7,stroke:#22c55e
    style L3 fill:#fef3c7,stroke:#f59e0b
```

---

## Diagram 4 — The Ownership Gap: Before and After IRL

```mermaid
graph LR
    subgraph before["Without IRL"]
        direction TB
        agent1["Autonomous Agent"]
        black["Black Box\n(no audit trail)"]
        exchange1["Exchange"]
        outcome1["Trade Outcome"]

        agent1 -->|"reasons about market"| black
        black -->|"places order"| exchange1
        exchange1 --> outcome1

        audit1["❌ No proof of reasoning\n❌ No policy record\n❌ Retroactive reconstruction\n❌ Ownership Gap"]
    end

    subgraph after["With IRL"]
        direction TB
        agent2["Autonomous Agent"]
        irl["IRL Engine\n(pre-execution gateway)"]
        exchange2["Exchange"]
        outcome2["Trade Outcome"]

        agent2 -->|"POST /irl/authorize"| irl
        irl -->|"reasoning_hash + trace_id"| agent2
        agent2 -->|"places order"| exchange2
        exchange2 -->|"execution report"| agent2
        agent2 -->|"POST /irl/bind-execution"| irl
        exchange2 --> outcome2

        audit2["✓ Reasoning sealed before order\n✓ Policy enforced cryptographically\n✓ Tamper-evident audit chain\n✓ Ownership Gap closed"]
    end

    style before fill:#fee2e2,stroke:#ef4444
    style after fill:#dcfce7,stroke:#22c55e
```

---

## Diagram 5 — Multi-MTA Consensus (Phase 2+)

```mermaid
graph TB
    subgraph signers["MTA Signer Consortium (n=5)"]
        n1["Node A\n(MacroPulse)"]
        n2["Node B\n(Independent)"]
        n3["Node C\n(Academic)"]
        n4["Node D\n(Consortium)"]
        n5["Node E\n(Client-run)"]
    end

    agg["Threshold Aggregator\nCollects k-of-n broadcasts\nVerifies all signatures\nAssembles aggregate_hash"]

    n1 -->|"signed RegimeBroadcast"| agg
    n2 -->|"signed RegimeBroadcast"| agg
    n3 -->|"signed RegimeBroadcast"| agg
    n4 -->|"(offline)"| agg
    n5 -->|"signed RegimeBroadcast"| agg

    agg -->|"3-of-5 threshold MtaState"| irl["IRL Engine"]

    gov["Governance Contract\nadd_signer / remove_signer\nupdate_threshold\nslash on double-sign"]
    gov -.->|"manages signer set"| signers

    style agg fill:#dbeafe,stroke:#3b82f6
    style gov fill:#fef3c7,stroke:#f59e0b
```

---

---

## Diagram 6 — IRL in the Stack

How IRL fits between the agent runtime and the exchange — showing where the
compliance sidecar intercepts, what layers surround it, and which components
can be swapped by the operator.

```mermaid
graph LR
    subgraph Agent["Agent Runtime"]
        model["Model\n(any signal)"]
        sdk["IRL SDK\n(Python / TS)"]
        model -->|"trade decision"| sdk
    end

    subgraph Sidecar["IRL Engine Sidecar"]
        hb["Layer 2\nHeartbeat Validator"]
        mta_cli["MTA Client\n(pluggable)"]
        mar["Multi-Agent\nRegistry"]
        policy["Policy Engine\n(signal-agnostic)"]
        seal["CognitiveSnapshot\nSealer (SHA-256)"]
        db[("Audit DB\n(PostgreSQL)")]

        hb --> policy
        mta_cli --> policy
        mar --> policy
        policy -->|"ALLOWED"| seal
        policy -->|"HALTED / SHADOW_HALTED"| db
        seal --> db
    end

    subgraph MTA["Market Truth Anchor"]
        mp["MacroPulse MTA\n(reference)"]
        custom["Custom MTA\n(firm's own signal)"]
    end

    subgraph Exchange["Exchange / EMS"]
        oms["Order Management\nSystem"]
        exch["Exchange API"]
        oms --> exch
    end

    sdk -->|"POST /irl/authorize"| hb
    seal -->|"trace_id + reasoning_hash"| sdk
    sdk -->|"place order (with trace_id)"| oms
    exch -->|"execution report"| sdk
    sdk -->|"POST /irl/bind-execution"| seal

    mp --->|"Ed25519-signed RegimeBroadcast"| mta_cli
    custom -.->|"implements MtaClient trait"| mta_cli

    style Sidecar fill:#f0fdf4,stroke:#22c55e
    style MTA fill:#eff6ff,stroke:#3b82f6
    style Agent fill:#fafafa,stroke:#d1d5db
    style Exchange fill:#fff7ed,stroke:#f97316
```

**Reading the diagram:**
- The IRL sidecar is a network boundary — the agent SDK calls it over HTTP before
  placing any order. The exchange never receives an unauthorized intent.
- The MTA Client box is the only external dependency. Swap `MacroPulseMtaClient`
  for any `MtaClient` implementation to use a different regime signal.
- The Policy Engine reads only `allowed_sides` and `max_notional_scale` from the
  MTA state. It has no embedded knowledge of specific regime taxonomies.
- Shadow mode: when `SHADOW_MODE=true`, `HALTED` decisions write to the DB as
  `SHADOW_HALTED` and return `shadow_blocked: true` in the authorize response,
  without blocking the order flow.

---

## Design Notes for the Designer

- **Color palette**: Blue for L1/trust infrastructure, Green for verified/matched states,
  Amber for future/L3 work, Red for violations/divergence.
- **Font**: Use a monospace font for hash values and JSON snippets in diagrams.
- **Diagram 4** (Ownership Gap) is the most important for non-technical audiences —
  compliance officers and investors. Make it the largest and clearest.
- **Diagram 1** (sequence) is the most important for technical buyers — CTOs and
  quant teams. The flow should feel rigorous, not complex.
- All diagrams should be available in both light and dark versions for slide decks.
