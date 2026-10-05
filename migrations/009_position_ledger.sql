-- Migration 009: Agent Position Ledger
--
-- Tracks net open position per agent per asset.
-- Updated by bind-execution when verification_status becomes MATCHED.
-- Enables: reduce_only validation, exposure reporting, risk dashboards.

CREATE TABLE IF NOT EXISTS irl.agent_positions (
    position_id  UUID           DEFAULT gen_random_uuid() PRIMARY KEY,
    agent_id     UUID           NOT NULL,
    asset        TEXT           NOT NULL,
    net_quantity NUMERIC(20, 8) NOT NULL DEFAULT 0,
    last_trace_id UUID,
    updated_at   TIMESTAMPTZ    NOT NULL DEFAULT now(),
    UNIQUE (agent_id, asset)
);

CREATE INDEX IF NOT EXISTS idx_agent_positions_agent
    ON irl.agent_positions (agent_id);
