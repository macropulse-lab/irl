-- Migration 007: Portfolio Notional Aggregation Support
--
-- Adds a partial index to make the per-agent PENDING notional SUM fast.
-- Used by the authorize route to enforce cumulative (portfolio-level) notional caps.

CREATE INDEX IF NOT EXISTS idx_reasoning_traces_agent_pending
    ON irl.reasoning_traces (agent_id)
    WHERE verification_status = 'PENDING';
