# IRL Engine — Performance Benchmarks

**Version:** 1.1
**Last run:** 2026-04-02
**Environment:** See `results.md` for hardware spec.

---

## Benchmark Harness

The benchmark exercises `POST /irl/authorize` with realistic, randomised payloads.
Each request uses a unique `trace_id`, `client_order_id`, and `agent_valid_time` so
every call is treated as an independent decision event.

### Prerequisites

```bash
# Install wrk
brew install wrk       # macOS
apt install wrk        # Debian/Ubuntu

# Register a test agent and note its UUID + model_hash_hex
curl -s -X POST http://localhost:4000/irl/agents \
     -H "Authorization: Bearer $IRL_OPERATOR_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"name":"bench-agent","model_hash_hex":"<64-char-hex>","max_notional":1000000}'

# Issue a bearer token for that agent
curl -s -X POST http://localhost:4000/irl/admin/tokens \
     -H "Authorization: Bearer $IRL_OPERATOR_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"agent_id":"<agent-uuid>","label":"bench"}'
```

### Running

```bash
# 1. Start IRL Engine with benchmark config (mock MTA, no KMS, no L2, pool=50)
MTA_MODE=mock \
LAYER2_ENABLED=false \
KMS_PROVIDER=none \
DB_POOL_MAX_CONNECTIONS=50 \
RATE_LIMIT_PER_SECOND=0 \
cargo run --release

# 2. Export required environment variables for the Lua script
export IRL_API_TOKEN=<token-from-above>
export AGENT_ID=<agent-uuid>
export MODEL_HASH=<64-char-hex-matching-registered-agent>

# 3. Warm up (30 s — not recorded, allows DB pool and caches to stabilise)
wrk -t4 -c100 -d30s \
    -H "Authorization: Bearer $IRL_API_TOKEN" \
    -s bench/authorize.lua \
    http://localhost:4000/irl/authorize

# 4. Measure — run each concurrency level 3 times and average the results
#    100 concurrent agents
wrk -t4  -c100  -d60s -H "Authorization: Bearer $IRL_API_TOKEN" -s bench/authorize.lua http://localhost:4000/irl/authorize

#    500 concurrent agents
wrk -t8  -c500  -d60s -H "Authorization: Bearer $IRL_API_TOKEN" -s bench/authorize.lua http://localhost:4000/irl/authorize

#    1 000 concurrent agents
wrk -t16 -c1000 -d60s -H "Authorization: Bearer $IRL_API_TOKEN" -s bench/authorize.lua http://localhost:4000/irl/authorize
```

### Resource Utilisation (capture alongside wrk)

Run these in a separate terminal during each benchmark run and record the peak values
in `results.md`:

```bash
# IRL Engine process stats (CPU %, RSS) — record peak
pidstat -p $(pgrep irl-engine) 5

# PostgreSQL active connections
psql $DATABASE_URL -c "SELECT count(*) FROM pg_stat_activity WHERE datname = 'irl';"

# Open file descriptors
ls /proc/$(pgrep irl-engine)/fd | wc -l
```

---

## Interpreting Results

- **p50**: median latency — reflects typical agent experience
- **p95**: 95th percentile — reflects degraded but acceptable performance
- **p99**: 99th percentile — tail latency; must be ≤ SLA threshold for the operating
  concurrency tier (see `docs/public/10-sla.md §1`)
- **p99.9**: ultra-tail; useful for detecting outliers caused by GC pauses, lock spikes
- **Throughput**: authorizations/second sustainable at steady state

### What these numbers do NOT include

These benchmarks run with `MTA_MODE=mock`, `KMS_PROVIDER=none`, and `LAYER2_ENABLED=false`.
Production deployments add overhead on every request:

| Feature | Additive overhead (estimated) |
|---------|------------------------------|
| MTA network fetch + Ed25519 verify | +2–10 ms p50 / +5–20 ms p99 |
| KMS DEK generation | +5–15 ms p50 |
| Heartbeat validation (L2) | +1–3 ms (extra DB read) |

Always qualify shared benchmark numbers with this context.

---

## Results

See [results.md](results.md) for committed benchmark results.
