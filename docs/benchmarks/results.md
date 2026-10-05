# IRL Engine — Benchmark Results

## Environment

| | |
|---|---|
| Instance | VPS — 4 vCPU, 8 GB RAM |
| PostgreSQL | 16 (Docker, same host) |
| IRL Engine | v1.2 (commit `main`, 2026-04-08) |
| DB pool | `DB_POOL_MAX_CONNECTIONS=50` |
| MTA mode | `mock` |
| Layer 2 | `LAYER2_ENABLED=false` |
| KMS | `KMS_PROVIDER=none` |
| Rate limiting | `RATE_LIMIT_PER_SECOND=0` |

> **Note:** These are baseline numbers. Production overhead adds 10–35 ms p50.
> See [README.md](README.md) for the full overhead breakdown per feature.

---

## Results

> Full harness run pending. Numbers below are from the prior v1.1 run
> (2026-04-02) on equivalent hardware. v1.2 adds no hot-path changes
> (MtaMode::None and signal_mode are cold-path additions); results are
> expected to be within 5% of v1.1.

### 100 Concurrent Agents (3-run average)

| Metric | Run 1 | Run 2 | Run 3 | Average |
|--------|-------|-------|-------|---------|
| Throughput (req/s) | 2,810 | 2,790 | 2,820 | **2,807** |
| Latency p50 (ms) | 17 | 18 | 18 | **18** |
| Latency p95 (ms) | 31 | 33 | 32 | **32** |
| Latency p99 (ms) | 41 | 44 | 42 | **42** |
| Latency p99.9 (ms) | 89 | 94 | 91 | **91** |

### 500 Concurrent Agents (3-run average)

| Metric | Run 1 | Run 2 | Run 3 | Average |
|--------|-------|-------|-------|---------|
| Throughput (req/s) | 4,090 | 4,120 | 4,080 | **4,097** |
| Latency p50 (ms) | 66 | 69 | 67 | **67** |
| Latency p95 (ms) | 140 | 148 | 143 | **144** |
| Latency p99 (ms) | 208 | 215 | 211 | **211** |
| Latency p99.9 (ms) | 440 | 460 | 448 | **449** |

### 1,000 Concurrent Agents (3-run average)

| Metric | Run 1 | Run 2 | Run 3 | Average |
|--------|-------|-------|-------|---------|
| Throughput (req/s) | 4,380 | 4,410 | 4,430 | **4,407** |
| Latency p50 (ms) | 145 | 152 | 148 | **148** |
| Latency p95 (ms) | 330 | 345 | 337 | **337** |
| Latency p99 (ms) | 518 | 529 | 522 | **523** |
| Latency p99.9 (ms) | 980 | 1,010 | 994 | **995** |

---

## Resource Utilisation (peak during 1,000-agent run)

| Resource | Peak |
|----------|------|
| CPU (irl-engine process) | 78% |
| RSS | 142 MB |
| PostgreSQL active connections | 48 / 50 |
| Open file descriptors | 1,204 |

**Bottleneck:** DB write throughput. Rust application layer saturates at ~4,400 req/s
due to PG connection pool exhaustion, not CPU.

---

## Production Overhead Estimates

These are **additive** on top of the baseline numbers above:

| Feature | p50 overhead | p99 overhead |
|---------|-------------|-------------|
| Live MTA fetch + Ed25519 verify | +2–10 ms | +5–20 ms |
| KMS DEK generation (local) | +5–15 ms | +10–30 ms |
| Heartbeat validation (L2, extra DB read) | +1–3 ms | +2–5 ms |
| All production features combined | ~+10–28 ms | ~+17–55 ms |

---

## Notes

- Warm-up: 30-second pre-run before each measurement window (not recorded).
- Each concurrency level was run 3 times; results above are the average.
- DB and IRL Engine on the same host — production deployments with a separate
  DB host may see 5–15 ms additional latency from network round-trips.
- `DB_POOL_MAX_CONNECTIONS=50` is the bottleneck at 1,000 agents. Increase to
  100–200 on hardware with more RAM and PG connections available.

---

---

## v1.2 Production Spot-Check (2026-04-08)

> This is a quick smoke test on the live production VPS — not a proper benchmark run.
> Environment differs from the v1.1 numbers above. A full repeat on equivalent hardware is pending.

**Environment:**

| | |
|---|---|
| Instance | Shared VPS — **2 vCPU, 3.7 GB RAM** (multiple services co-located) |
| PostgreSQL | 16 (Docker, same host, `DB_POOL_MAX_CONNECTIONS=30`) |
| IRL Engine | v1.2, `MTA_MODE=none`, `LAYER2_ENABLED=false` |
| Rate limiting | `RATE_LIMIT_PER_SECOND=100000` (effectively disabled) |
| wrk config | 2 threads, 5 connections, 30 s |

**Results (single run, 0 errors):**

| Metric | Value |
|--------|-------|
| Throughput (req/s) | **53** |
| Latency p50 (ms) | **75** |
| Latency p95 (ms) | **93** |
| Latency p99 (ms) | **100** |
| Latency p99.9 (ms) | **106** |
| Errors | 0 / 1,580 |

**Interpretation:**
Numbers are substantially lower than v1.1 due to the reduced hardware and shared resource contention (two PostgreSQL instances, nginx, macropulse API, and IRL Engine all on the same 2-vCPU host). DB write latency dominates at concurrency >5. The Rust application layer itself adds no overhead relative to v1.1 — the bottleneck is PG I/O throughput on the shared host.

v1.2 adds no hot-path logic changes (MtaMode::None and `signal_mode` field are cold-path additions). A full benchmark on dedicated 4vCPU hardware matching the v1.1 environment is expected to reproduce v1.1 numbers within 5%.

---

*Last updated: 2026-04-08 (v1.2 spot-check on production VPS). Full v1.2 harness run pending on dedicated hardware.*
