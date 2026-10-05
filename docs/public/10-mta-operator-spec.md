# IRL Engine — MTA Operator Interface Specification

*v1.0 · March 2026*

---

This document defines the HTTP contract any Market Truth Anchor (MTA) operator must
implement to integrate with IRL Engine. MacroPulse provides the reference implementation;
any firm can bring its own signal by satisfying this interface.

## The MTA Interface

### Endpoint

```
GET /v1/regime/current
```

No authentication required. The response is signed; integrity is verified by IRL via
the pre-registered Ed25519 public key, not via HTTP auth.

### Response

**Content-Type:** `application/json`

```json
{
  "regime_id": 2,
  "macro_regime": "tightening",
  "model_version": "hmm-pca-v3.1",
  "broadcast_time": 1743120000000,
  "risk_level": 0.30,
  "max_notional_scale": 0.25,
  "allowed_sides": ["short", "neutral"],
  "signature": "<base64-encoded Ed25519 signature>"
}
```

### Field Reference

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `regime_id` | uint8 | yes | Opaque identifier (0–255). Operator-defined. Stored in every audit trace. |
| `macro_regime` | string | yes | Human-readable label. Stored for audit. |
| `model_version` | string | no | Semantic version of the operator's model. |
| `broadcast_time` | int64 | yes | Unix milliseconds when this regime was broadcast. |
| `risk_level` | float64 | yes | Normalized risk level: 0.0 = fully defensive, 1.0 = fully risk-on. |
| `max_notional_scale` | float64 | yes | Fraction of agent cap permitted now: 0.0–1.0. |
| `allowed_sides` | string[] | yes | Permitted trade directions. Values: `"long"`, `"short"`, `"neutral"`. |
| `signature` | string | yes | Base64 standard-encoded Ed25519 signature (see below). |

### `allowed_sides` Semantics

| Value | Meaning |
|-------|---------|
| `"long"` | New long positions permitted. |
| `"short"` | New short positions permitted. |
| `"neutral"` | Only flat/closing trades permitted. |
| `[]` | All directions blocked (full kill-switch). |

Orders with `reduce_only: true` bypass `allowed_sides` — an agent must always be able
to exit existing positions.

### `max_notional_scale` Semantics

```
effective_cap = agent.max_notional × mta.max_notional_scale
```

`0.0` blocks all notional (no new positions). Combined with `allowed_sides: ["neutral"]`
this is the full kill-switch state.

## Signature Specification

The `signature` field is a **Base64 standard-encoded Ed25519 signature** (RFC 8032) over
the **canonical JSON** of the response with the `signature` field removed.

**Canonical JSON:** `json.dumps(payload_without_signature, sort_keys=True, separators=(',', ':'))`

IRL verifies against the key registered at startup via `MTA_PUBKEY_HEX` (64-byte hex-encoded
Ed25519 verifying key).

### Signing example (Python)

```python
import json, base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

payload = {
    "regime_id": 2,
    "macro_regime": "tightening",
    "model_version": "v1.0",
    "broadcast_time": 1743120000000,
    "risk_level": 0.30,
    "max_notional_scale": 0.25,
    "allowed_sides": ["short", "neutral"],
}
canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
sig = private_key.sign(canonical.encode())
payload["signature"] = base64.standard_b64encode(sig).decode()
```

## Caching and Load

IRL caches MTA responses for `CACHE_TTL_MS` (default 100ms). At 1,000 req/sec IRL sees
≤10 MTA calls/sec. If the MTA is unreachable, IRL uses last-known state for up to
`MTA_FALLBACK_TTL_SECS` (default 60s) before failing closed.

## Custom Operator Implementation (Rust)

```rust
pub struct MyMta { /* ... */ }

#[async_trait::async_trait]
impl MtaClient for MyMta {
    async fn fetch_verified(&self) -> Result<MtaState, AppError> {
        // Run model, verify signature, return MtaState.
        // Your internal methodology stays private.
        Ok(MtaState {
            regime_id: 2,
            regime_label: "tightening".into(),
            risk_level: 0.30,
            max_notional_scale: 0.25,
            allowed_sides: vec!["short".into(), "neutral".into()],
            version: "v1.0".into(),
            hash: your_response_hash,
            broadcast_time: timestamp_ms,
        })
    }
}

// In main.rs — swap operators in one line:
let mta: Arc<dyn MtaClient> = Arc::new(MyMta::new(&config));
```

See `src/mta.rs` for the full trait definition and `MacroPulseMtaClient` reference
implementation.
