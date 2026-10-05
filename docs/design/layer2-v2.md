# Layer 2 v2: server-side regime binding

Status: **implemented** (#14), deployed 2026-10-05 with `LAYER2_MODE=both`; verified end-to-end by the trading bot (`IRL_L2_MODE=regime`). Open questions resolved with the defaults below: grace 300 s, `/irl/regime` authenticated, `irl.heartbeat_sequences` kept for audit history. Author: Claude (with Gabriel). Date: 2026-10-05.

## Problem

Layer 2 binds each authorize to the market regime the agent acted on and
prevents replay. Today that works as follows:

1. The agent calls MacroPulse `GET /v1/irl/heartbeat` (needs a separate
   MacroPulse `irl_sidecar` API key). MacroPulse fetches its own
   `/v1/regime/current`, sets `mta_ref = SHA-256(raw body)`, and signs
   `seq || timestamp_ms || regime_id || mta_ref` with the MTA key.
2. The agent puts that heartbeat in `POST /irl/authorize`.
3. IRL verifies the signature, requires `sequence_id` > the last one accepted
   **for this agent**, requires `now - timestamp_ms <= 200 ms`, and requires
   `mta_ref` to equal the hash of IRL's own cached MTA state.

The first end-to-end client integration (trading bot, 2026-10-05) and the
production incident review found these problems:

| # | Problem | Consequence |
|---|---|---|
| 1 | **200 ms wall-clock window** across two services | The agent must fetch from MacroPulse *and* reach IRL within 200 ms, plus clock skew. Fine on the same host; fails intermittently for any remote client (one cross-region RTT is ~80–150 ms). |
| 2 | **Second credential and second dependency** | Every agent needs a MacroPulse API key and MacroPulse uptime on the hot path, in addition to its IRL token. |
| 3 | **The heartbeat is not bound to the agent or the order** | It's a bearer token: any agent can present any heartbeat. The per-agent sequence check only stops one agent reusing its *own* heartbeat; a heartbeat captured from agent A is valid for agent B. |
| 4 | **IRL polls the MTA every 80 ms** to keep its cache within the window | 12.4 req/s, about 1M/day, for a payload that changes **daily** (the response is byte-identical between regime updates). These requests are 99.9% of MacroPulse's `request_audit_log` (83M rows, 17 GB since May). |
| 5 | **Silent failure mode** | When the MTA key and IRL's pubkey diverged, every heartbeat and every MTA refresh failed for months; only a WARN line every 80 ms showed it (fixed separately: rate-limited logs plus `/irl/health` `degraded`). |
| 6 | **Sequence counter in process memory** (MacroPulse) | Safe with today's single uvicorn worker. With more than one worker, sequences interleave across processes and agents get intermittent `HEARTBEAT_STALE_SEQUENCE`. |

What Layer 2 actually needs to guarantee:

- **(G1) Authentic regime.** The regime in the trace really came from the MTA operator.
- **(G2) Current regime.** The agent acted on the regime that was in force (or just replaced) at decision time.
- **(G3) No replay.** A captured authorize can't be resubmitted to create a second sealed intent.

## Proposal

IRL already fetches the MTA state itself and verifies its Ed25519 signature
(`MacroPulseMtaClient::fetch_and_verify`), and seals `mta_hash` into every
trace. So G1 is already met **server-side**; the heartbeat repeats it through
the client. v2 moves G2 and G3 to where they belong as well:

1. **G1: unchanged.** IRL fetches and verifies the signed MTA state and seals `mta_hash`, `mta_regime_id`, `mta_pubkey_used`.
2. **G2: regime reference instead of heartbeat.** New `GET /irl/regime` (client token) returns IRL's current verified state: `{regime_id, regime_label, mta_ref, broadcast_time, verified_at}`. The agent includes `mta_ref` in `AuthorizeRequest`. IRL accepts it if it equals the **current** verified `mta_ref`, or the **previous** one within a grace window (`MTA_REF_GRACE_SECS`, default 300) after a regime change. A stale reference gets `REGIME_REF_STALE` (409, retryable: refetch and resubmit). There's no wall-clock window between two services, so remote clients work.
3. **G3: request-level replay protection.** Enforce uniqueness of `(agent_id, client_order_id)`: a resubmitted authorize returns `409 DUPLICATE_INTENT` with the original `trace_id`, which also makes retries idempotent. This binds replay protection to the agent and the order, which the heartbeat never did. It's backed by a partial unique index, `irl.reasoning_traces(agent_id, client_order_id)`. (Partitioned tables need the partition key in unique indexes, so this is enforced through a small `irl.intent_keys` table written in the same transaction.)
4. **MTA polling:** refresh every `MTA_REFRESH_SECS` (default 5) with `If-None-Match`/ETag support, cache TTL above the refresh interval. That's about 0.2 req/s instead of 12.4. Regime changes land within seconds, and the regime is daily.
5. **Provider-agnostic:** nothing in v2 needs MacroPulse-specific client calls. Any `MtaClient` implementation works the same, which opens Layer 2 to other regime providers.

### Compatibility and rollout

- `LAYER2_MODE = legacy | v2 | both` (default `both` during migration).
  - `both`: accept a v2 `mta_ref`, *or* a legacy heartbeat. Traces record which mode was used (`l2_mode` in `trace_json`).
  - `v2`: heartbeats are ignored; `mta_ref` is required.
  - `legacy`: today's behavior.
- SDKs gain `get_regime()`, and `authorize(..., mta_ref=...)` fetches it automatically when omitted (with a short client-side cache).
- MacroPulse `/v1/irl/heartbeat` stays available until no traces use legacy mode for 30 days, then it's deprecated.

### What this does *not* weaken

- A client can still only reference a regime IRL itself verified as signed by the MTA operator; G1 is unchanged.
- The trace still proves which regime was in force and which the agent claimed.
- Replay protection gets **stronger**: bound to agent + order instead of a shareable token.

## Quick win, independent of v2

Change `MTA_REFRESH_MS` from 80 ms to about 5 s (and `CACHE_TTL_MS` above it).
This doesn't interact with heartbeat validation: the 200 ms drift is measured
against the **heartbeat's** timestamp, not IRL's cache age. It cuts MacroPulse
load and `request_audit_log` growth by about 60×. On the MacroPulse side,
separately: exclude internal polling from `request_audit_log` and add
retention for it.

## Open questions

1. Grace window length after a regime change (proposed 300 s).
2. Should `GET /irl/regime` be unauthenticated, like `/irl/anchors`? The regime is public MacroPulse data, but the endpoint reveals the deployment's MTA configuration.
3. Retire `irl.heartbeat_sequences` after the legacy period, or keep it for audit history?
