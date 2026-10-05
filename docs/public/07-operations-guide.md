# IRL Engine — Operations Guide

*v1.2 · March 2026*

---

## Contents

1. [Production Checklist](#1-production-checklist)
2. [Prometheus + Grafana](#2-prometheus--grafana)
3. [SQL Monitoring Queries](#3-sql-monitoring-queries)
4. [Disaster Recovery Scenarios](#4-disaster-recovery-scenarios)
5. [SIEM Export](#5-siem-export)
6. [Runbook — Common Incidents](#6-runbook--common-incidents)
7. [Concurrency Model](#7-concurrency-model)

---

## 1. Production Checklist

Complete this checklist before going live.

### Security

- [ ] Rotate all tokens from the default `eval-token-change-me` value
- [ ] `IRL_API_TOKENS` contains one token per client — never shared between agents
- [ ] `RATE_LIMIT_PER_SECOND` tuned for your expected peak request rate (default: 100 req/s per token)
- [ ] `MAX_BODY_BYTES` set appropriately (default 1 MB — sufficient for all normal payloads)
- [ ] `/metrics` endpoint is firewalled to internal Prometheus scraper only
- [ ] TLS termination in front of the IRL sidecar (nginx, Caddy, or cloud LB)
- [ ] Database connection over TLS (`?sslmode=require` in `DATABASE_URL`)
- [ ] MTA public key (`MTA_PUBKEY_HEX`) verified out-of-band with MTA operator

### Configuration

- [ ] `MTA_MODE=MacroPulse` (not `mock`)
- [ ] `LAYER2_ENABLED=true`
- [ ] `SHADOW_MODE=false` (or explicitly `true` if intentionally in shadow phase)
- [ ] `BIND_SIZE_TOLERANCE` tuned to your execution venue's fill model
- [ ] `TRACE_EXPIRY_MS` set to your maximum expected fill latency × 10

### Infrastructure

- [ ] PostgreSQL running with automated backups
- [ ] IRL Engine running as a systemd service or Docker container with restart policy
- [ ] Prometheus scrape job configured (`/metrics` every 15s)
- [ ] Grafana dashboard imported (see §2)
- [ ] Alert rules configured for `irl_policy_blocked_total` and DB errors
- [ ] Log pipeline (Loki / CloudWatch / Datadog) capturing `WARN` and above

### Validation

- [ ] Run a full authorize → bind cycle in staging with real MTA
- [ ] Confirm `final_proof` appears on bind response
- [ ] Query `/irl/orphans` — should be empty before first live session
- [ ] Check `/irl/pending` count drops to zero after each session

---

## 2. Prometheus + Grafana

### Metrics exposed at `GET /metrics`

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `irl_authorize_total` | Counter | `result` | Authorize calls by result (`authorized`, `policy_blocked`, `shadow_blocked`, `error`) |
| `irl_authorize_duration_ms` | Histogram | — | Latency of /authorize in ms (buckets: 1, 2, 5, 10, 25, 50, 100, 250, 500, 1000) |
| `irl_bind_total` | Counter | `status` | Bind calls by outcome (`matched`, `divergent`, `orphan`, `other`) |
| `irl_policy_blocked_total` | Counter | `regime`, `error_code` | Policy blocks by regime label and error code |
| `irl_agent_count` | Gauge | `status` | Agent count by status (`active`, `suspended`) |

Standard Go process metrics (`process_cpu_seconds_total`, `go_goroutines`, etc.)
are also emitted by the `prometheus` crate's `process` feature.

### Prometheus scrape config

```yaml
# prometheus.yml
scrape_configs:
  - job_name: irl_engine
    static_configs:
      - targets: ["irl-engine:4000"]
    metrics_path: /metrics
    scrape_interval: 15s
```

### Recommended Grafana panels

**Row 1 — Throughput & Latency**

- Authorize rate: `rate(irl_authorize_total[1m])`
- p50/p95 latency: `histogram_quantile(0.95, rate(irl_authorize_duration_ms_bucket[5m]))`
- Bind rate: `rate(irl_bind_total[1m])`

**Row 2 — Compliance**

- Policy block rate: `rate(irl_authorize_total{result="policy_blocked"}[5m])`
- Shadow block rate: `rate(irl_authorize_total{result="shadow_blocked"}[5m])`
- Top blocked regimes: `topk(5, irl_policy_blocked_total)`

**Row 3 — Audit Health**

- DIVERGENT bind rate: `rate(irl_bind_total{status="divergent"}[5m])`
- Active agents: `irl_agent_count{status="active"}`
- Suspended agents: `irl_agent_count{status="suspended"}`

### Alert rules

```yaml
# alerts.yml
groups:
  - name: irl_engine
    rules:
      - alert: IRLHighPolicyBlockRate
        expr: rate(irl_authorize_total{result="policy_blocked"}[5m]) > 0.1
        for: 2m
        annotations:
          summary: "High policy block rate — possible regime shift or agent misconfiguration"

      - alert: IRLHighDivergenceRate
        expr: rate(irl_bind_total{status="divergent"}[5m]) > 0.05
        for: 1m
        annotations:
          summary: "High divergence rate — exchange execution may deviate from authorized intent"

      - alert: IRLEngineDown
        expr: up{job="irl_engine"} == 0
        for: 1m
        annotations:
          summary: "IRL Engine is unreachable — agents cannot be authorized"
```

---

## 3. SQL Monitoring Queries

These queries run against the `irl.reasoning_traces` table. Connect with read-only
credentials.

### Active session health

```sql
-- Unbound intents older than 10 minutes (potential orphans)
SELECT
    trace_id,
    txn_time,
    execution_asset,
    execution_action,
    execution_notional,
    now() - txn_time AS age
FROM irl.reasoning_traces
WHERE verification_status = 'PENDING'
  AND txn_time < now() - interval '10 minutes'
ORDER BY txn_time ASC
LIMIT 50;
```

### Compliance summary (last 24 hours)

```sql
SELECT
    policy_result,
    COUNT(*)              AS total,
    MIN(txn_time)         AS first_seen,
    MAX(txn_time)         AS last_seen
FROM irl.reasoning_traces
WHERE txn_time > now() - interval '24 hours'
GROUP BY policy_result
ORDER BY total DESC;
```

### Divergent trades with detail

```sql
SELECT
    trace_id,
    txn_time,
    execution_asset,
    execution_action,
    execution_quantity,
    execution_price,
    exchange_tx_id,
    client_order_id,
    trace_json -> 'integrity' ->> 'divergence_reason' AS reason
FROM irl.reasoning_traces
WHERE verification_status = 'DIVERGENT'
  AND txn_time > now() - interval '7 days'
ORDER BY txn_time DESC;
```

### Policy violations by regime and error code

```sql
SELECT
    mta_regime_id,
    policy_result,
    COUNT(*) AS count
FROM irl.reasoning_traces
WHERE policy_result IN ('HALTED', 'SHADOW_HALTED')
  AND txn_time > now() - interval '30 days'
GROUP BY mta_regime_id, policy_result
ORDER BY count DESC;
```

### Agent activity

```sql
SELECT
    agent_id,
    COUNT(*)                                           AS total_intents,
    COUNT(*) FILTER (WHERE policy_result = 'ALLOWED') AS allowed,
    COUNT(*) FILTER (WHERE policy_result = 'HALTED')  AS halted,
    COUNT(*) FILTER (WHERE verification_status = 'MATCHED') AS matched,
    COUNT(*) FILTER (WHERE verification_status = 'DIVERGENT') AS divergent,
    MAX(txn_time) AS last_seen
FROM irl.reasoning_traces
WHERE txn_time > now() - interval '30 days'
GROUP BY agent_id
ORDER BY total_intents DESC;
```

### Audit completeness check

```sql
-- Intents with no corresponding bind, never expired
SELECT COUNT(*) AS unbound_count
FROM irl.reasoning_traces
WHERE verification_status = 'PENDING'
  AND txn_time < now() - interval '2 hours';
-- Should return 0 in a healthy system. Non-zero indicates missed bind calls.
```

---

## 4. Disaster Recovery Scenarios

### Scenario A — IRL Engine process crash

**Impact:** Agents cannot call `/irl/authorize`. Orders placed during the outage
have no trace_id and are not IRL-compliant.

**Recovery:**
1. Restart the IRL Engine process (systemd: `systemctl restart irl-engine`).
2. Review the gap period: query `irl.reasoning_traces` for the outage window —
   absence of traces confirms no orders were sealed during the outage.
3. If orders were placed without IRL authorization during the outage, flag them
   in your compliance log with the outage window timestamps.

**Prevention:** Run two IRL instances behind a local load balancer (round-robin).
Both instances write to the same PostgreSQL DB. The pool is stateless between
authorize calls — any instance can seal any intent.

### Scenario B — PostgreSQL outage

**Impact:** IRL cannot persist traces. The `/irl/authorize` endpoint returns
`500 DATABASE_ERROR` and agents are blocked.

**Recovery:**
1. Restore PostgreSQL from backup or failover to a replica.
2. Verify migration state: `SELECT version FROM sqlx_migrations ORDER BY version DESC LIMIT 1;`
3. Restart IRL Engine.
4. Confirm pending trace count returns to expected level.

**Prevention:** Use managed PostgreSQL (AWS RDS Multi-AZ, Supabase, Neon) with
automated failover. Set `DATABASE_URL` to the read-write endpoint or a pooler
(PgBouncer) pointing at the primary.

### Scenario C — MTA operator unreachable

**Circuit breaker behavior:** IRL has a 60-second last-known-good fallback.
If the MTA is unreachable, IRL continues using the cached regime for up to
`MTA_FALLBACK_TTL_SECS` (default: 60) seconds, logging `WARN`-level alerts.
After that window expires, IRL **fails closed** — all authorize calls return
`502 MTA_FETCH_FAILED` until the MTA recovers.

Watch for this log line to detect the transition to fallback mode:
```
WARN MTA unreachable — using last known regime as circuit-breaker fallback age_secs=N fallback_ttl=60
```

And for the hard close:
```
ERROR MTA unreachable and fallback TTL expired (60s) — failing closed
```

**Impact after TTL expires:** `MTA_FETCH_FAILED (502)` returned on every authorize call.
Agents are blocked.

**Recovery:**
1. Check `MTA_URL` is reachable: `curl -s $MTA_URL/health`.
2. If the MTA operator is degraded, contact them directly.
3. For temporary relief in a documented incident: set `MTA_MODE=mock` to
   allow trading to continue with the mock regime. **Log this decision** as a
   compliance exception with timestamps.
4. When the MTA operator recovers, revert `MTA_MODE=MacroPulse` and restart.

**Note:** All trades authorized during `MTA_MODE=mock` will have
`mta_regime_id=0` (mock expansion regime) in their traces. Flag these for
compliance review.

### Scenario D — Runaway agent (thousands of blocked trades)

**Impact:** `REGIME_VIOLATION` flood from a misconfigured agent — high policy
block rate, potential DB write pressure.

**Recovery:**
1. Suspend the agent immediately:
   ```bash
   curl -X PATCH http://localhost:4000/irl/agents/$AGENT_ID/status \
     -H "Authorization: Bearer $TOKEN" \
     -d '{"status": "Suspended"}'
   ```
2. All subsequent authorize calls from this agent return `403 AGENT_NOT_ACTIVE`.
3. Review the agent's `allowed_regimes` and `max_notional` configuration.
4. Fix the agent logic, re-register if needed, set status back to `Active`.

---

## 5. SIEM Export

For security event correlation (Splunk, Elastic, Datadog), export IRL trace
events via a continuous query or a CDC pipeline.

### Structured log fields

Every authorize call emits a structured `tracing` event at `INFO` level.
Parse the JSON log output and forward it to your SIEM.

Key fields to index:

| Log field | Notes |
|-----------|-------|
| `trace_id` | UUID — join with DB records |
| `agent_id` | From MAR |
| `mta_regime_id` | Regime at time of decision |
| `policy_result` | `ALLOWED` / `HALTED` / `SHADOW_HALTED` |
| `execution_asset` | Instrument |
| `execution_notional` | Position size |
| `reasoning_hash` | SHA-256 of the CognitiveSnapshot |
| `txn_time` | RFC 3339 timestamp |

### DB-to-SIEM query (polling approach)

```sql
-- Run every 60 seconds; track last_exported_txn_time externally
SELECT
    trace_id::text,
    txn_time,
    agent_id::text,
    mta_regime_id,
    policy_result,
    verification_status,
    execution_asset,
    execution_action,
    execution_notional::text,
    reasoning_hash,
    final_proof
FROM irl.reasoning_traces
WHERE txn_time > :last_exported_txn_time
ORDER BY txn_time ASC
LIMIT 1000;
```

### SIEM alert examples

- **Policy flood:** > 50 HALTED events in 60s from the same `agent_id`
- **Model hash drift:** Multiple HALTED events with `error_code=MODEL_HASH_MISMATCH`
- **Divergence cluster:** > 5 DIVERGENT verifications in 10 minutes
- **Orphan accumulation:** PENDING trace count growing without corresponding binds

---

## 6. Runbook — Common Incidents

### "I see SHADOW_HALTED traces but expected HALTED"

`SHADOW_MODE=true` is set in the environment. The engine is running in
observation mode. To enable enforcement, set `SHADOW_MODE=false` and restart.

### "bind-execution returns DIVERGENT unexpectedly"

Check:
1. Was `executed_quantity` passed in the bind request? If omitted, the engine
   cannot detect partial fill divergence.
2. Is `BIND_SIZE_TOLERANCE` appropriate for your venue? Some exchanges fill in
   lot sizes that introduce small rounding deltas.
3. Was the `exchange_tx_id` correct? A mismatch in ID does not cause DIVERGENT
   but means the trace is not correctly closed.

### "Agent returns 403 AGENT_NOT_ACTIVE after a code deploy"

A deploy likely triggered the suspended flag during testing. Check the agent
status: `GET /irl/agents/:id`. If suspended, activate: `PATCH /irl/agents/:id/status {"status": "Active"}`.

### "MTA_FETCH_FAILED after a network change"

`MTA_URL` is resolved at startup but called on every authorize request. If the
DNS name or IP changed, update `MTA_URL` in the environment and restart the
engine.

### "Concurrent authorizations for the same agent seem slower"

This is expected. IRL acquires a per-agent PostgreSQL advisory lock during the
atomic portfolio cap check before inserting a trace. Two simultaneous `/authorize`
calls for the same `agent_id` serialize at the DB level (the second waits for
the first to commit) — this prevents TOCTOU races that would allow cumulative
notional to bypass the cap. The overhead is typically <1 ms per queue position.
This is a feature, not a bug: without serialization, two concurrent requests
could together exceed the portfolio cap even if each individually was within limits.

### "bind-execution returns DIVERGENT unexpectedly on side"

IRL performs side-mismatch detection if `executed_side` is provided in the bind
request. Ensure the value matches the authorized action direction (`"Long"` or
`"Short"`). If your exchange does not return the side in the fill report, omit
`executed_side` from the bind request to skip the check.

### "Token revoked but agents still authenticating"

The token cache refreshes every 60 seconds. Wait up to 60 seconds after revoking
a token in the DB for it to take effect. If you need instant revocation, restart
the IRL Engine process.

---

## 7. Concurrency Model

Understanding IRL's internal concurrency model helps when diagnosing latency
anomalies and planning horizontal scale.

### Advisory locks — portfolio cap enforcement

Every `/authorize` request acquires a per-agent PostgreSQL advisory lock
(`pg_advisory_xact_lock`) before reading the cumulative pending notional and
inserting the trace. This means:

- **Concurrent requests for the same agent are serialized** at the DB level
- **Concurrent requests for different agents run in parallel** (lock key is per-agent UUID)
- **Lock is held for the duration of the trace insert transaction** (typically < 5 ms)
- **No deadlock risk** — each agent has a single lock key; no multi-lock acquisition

This design ensures the portfolio cap is correctly enforced even under high concurrency
without requiring application-level mutexes.

### Token cache

Active bearer tokens are loaded from the DB into a DashMap (concurrent hash map) at
startup and refreshed every 60 seconds in a background task. The per-request check
is a lock-free hash lookup — O(1) with no DB round-trip.

### MTA state cache

MTA regime state is cached for 100 ms. A cache miss triggers a fresh HTTP fetch
to the MTA operator. In the event of an MTA outage, the engine uses the last cached
state for up to 60 seconds before failing closed.

### Position ledger

The `irl.agent_positions` table is updated on every MATCHED bind via an upsert
(`ON CONFLICT DO UPDATE`). This operation is atomic at the PostgreSQL row level —
concurrent binds for the same `(agent_id, asset)` pair serialize on the row lock.

---
