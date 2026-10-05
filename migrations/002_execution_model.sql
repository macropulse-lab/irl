-- Migration 002: Expand execution intent columns to match whitepaper v3 §5.2 E_t spec.
-- Adds order_type, venue_id, quantity, notional, limit_price, and agent_id FK.

ALTER TABLE irl.reasoning_traces
    ADD COLUMN IF NOT EXISTS execution_order_type  TEXT,
    ADD COLUMN IF NOT EXISTS execution_venue_id    TEXT,
    ADD COLUMN IF NOT EXISTS execution_quantity    NUMERIC(20, 8),
    ADD COLUMN IF NOT EXISTS execution_notional    NUMERIC(20, 8),
    ADD COLUMN IF NOT EXISTS execution_limit_price NUMERIC(20, 8),
    ADD COLUMN IF NOT EXISTS agent_id              UUID;

-- Index for per-agent audit queries
CREATE INDEX IF NOT EXISTS idx_irl_traces_agent_id ON irl.reasoning_traces (agent_id);
