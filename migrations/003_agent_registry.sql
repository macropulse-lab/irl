-- Migration 003: Multi-Agent Registry (MAR) — whitepaper v3 §10.
-- Each agent is a unique cryptographic entity with a registered model hash,
-- allowed regimes, notional/leverage limits, and lifecycle status.

CREATE TABLE IF NOT EXISTS irl.agent_registry (
    agent_id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Display name for humans — not used in crypto checks
    name              TEXT        NOT NULL,
    -- SHA-256 of model version + config (32 bytes stored as hex for readability)
    model_hash_hex    TEXT        NOT NULL,
    -- Policy module identifier — currently 'default' (IrlConstraintPolicy)
    policy_module_id  TEXT        NOT NULL DEFAULT 'default',
    -- Opaque operator-defined regime IDs this agent may trade in.
    -- NULL = allow all regime IDs (correct default for custom MTA operators).
    -- For MacroPulse: use ARRAY[0,1,2,3] to restrict to standard regimes.
    -- See migration 005 for the NOT NULL → nullable change.
    allowed_regimes   SMALLINT[]  NOT NULL DEFAULT ARRAY[0,1,2,3],
    -- Per-decision notional ceiling in USD
    max_notional      NUMERIC(20, 8) NOT NULL DEFAULT 1000000.00,
    -- Maximum leverage multiple
    max_leverage      NUMERIC(8, 4)  NOT NULL DEFAULT 4.0,
    -- NULL = all venues permitted; otherwise array of MIC codes or internal IDs
    allowed_venues    TEXT[],
    -- Active | Suspended | Deregistered
    status            TEXT        NOT NULL DEFAULT 'Active',
    registered_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Index for status-based lookups (common in authorization hot path)
CREATE INDEX IF NOT EXISTS idx_irl_agents_status ON irl.agent_registry (status);

-- Add FK from reasoning_traces.agent_id → agent_registry.agent_id
-- (column added in migration 002; FK constraint added here)
ALTER TABLE irl.reasoning_traces
    DROP CONSTRAINT IF EXISTS fk_traces_agent;

ALTER TABLE irl.reasoning_traces
    ADD CONSTRAINT fk_traces_agent
    FOREIGN KEY (agent_id) REFERENCES irl.agent_registry (agent_id);
