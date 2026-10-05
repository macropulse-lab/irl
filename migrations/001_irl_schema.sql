-- IRL Engine: Immutable Reasoning Log Schema
-- Separate schema "irl" on the shared TimescaleDB instance.
-- Standalone schema — no dependency on any MTA operator's database.

CREATE SCHEMA IF NOT EXISTS irl;

CREATE TABLE IF NOT EXISTS irl.reasoning_traces (
    -- Primary key
    trace_id              UUID PRIMARY KEY,

    -- Bitemporal timestamps
    -- Invariant: valid_time < txn_time (enforced in application layer)
    valid_time            TIMESTAMPTZ NOT NULL,   -- when the MTA regime was valid in the market
    txn_time              TIMESTAMPTZ NOT NULL,   -- when IRL sealed this snapshot

    -- Market Truth Anchor
    mta_regime_id         SMALLINT NOT NULL,
    mta_version           TEXT NOT NULL,
    mta_hash              TEXT NOT NULL,          -- SHA-256 of raw MTA response body

    -- Agent fingerprint (no IP exposed)
    latent_fingerprint    TEXT NOT NULL,          -- SHA-256(model_id || prompt_version || feature_schema_id)
    feature_schema_id     TEXT NOT NULL,

    -- Execution intent
    execution_action      TEXT NOT NULL,          -- "Long(1.5)", "Short(2.0)", "Neutral"
    execution_asset       TEXT NOT NULL,
    client_order_id       TEXT NOT NULL,

    -- Exchange binding (filled by /bind-execution)
    exchange_tx_id        TEXT,
    verification_status   TEXT NOT NULL DEFAULT 'PENDING',
    execution_status      TEXT,                   -- FILLED | REJECTED | PARTIAL
    execution_price       NUMERIC(20, 8),
    execution_time        TIMESTAMPTZ,

    -- Layer 2: Heartbeat
    heartbeat_seq         BIGINT NOT NULL,        -- required (not nullable)

    -- Policy audit (proves WHICH policy version made the decision)
    policy_id             TEXT NOT NULL,
    policy_version        TEXT NOT NULL,
    policy_hash           TEXT NOT NULL,
    policy_result         TEXT NOT NULL,          -- ALLOWED | HALTED

    -- Cryptographic chain
    reasoning_hash        TEXT NOT NULL UNIQUE,   -- canonical SHA-256 of CognitiveSnapshot
    final_proof           TEXT,                   -- SHA-256(reasoning_hash || "||" || exchange_tx_id)

    -- Full Reasoning_Trace_v1 for forensic replay
    trace_json            JSONB NOT NULL
);

-- Indexes for regulator queries and operational dashboards
CREATE INDEX IF NOT EXISTS idx_irl_traces_regime_time
    ON irl.reasoning_traces (mta_regime_id, txn_time DESC);

CREATE INDEX IF NOT EXISTS idx_irl_traces_client_order
    ON irl.reasoning_traces (client_order_id);

CREATE INDEX IF NOT EXISTS idx_irl_traces_pending_binding
    ON irl.reasoning_traces (verification_status)
    WHERE verification_status = 'PENDING';

CREATE INDEX IF NOT EXISTS idx_irl_traces_policy_result
    ON irl.reasoning_traces (policy_result, txn_time DESC);

CREATE INDEX IF NOT EXISTS idx_irl_traces_asset_time
    ON irl.reasoning_traces (execution_asset, txn_time DESC);

-- Check constraint: enforce bitemporal invariant at DB level (belt and suspenders)
ALTER TABLE irl.reasoning_traces
    ADD CONSTRAINT chk_bitemporal CHECK (valid_time < txn_time);
