-- Migration 006: Shadow Mode
--
-- No schema change required. policy_result is TEXT NOT NULL with no CHECK
-- constraint, so the new 'SHADOW_HALTED' value is accepted by the existing
-- schema without modification.
--
-- This migration serves as a versioned record that SHADOW_HALTED is an
-- intentional, supported policy_result value alongside ALLOWED and HALTED.
--
-- Index: add a partial index to make GET /irl/shadow-violations fast even
-- at high trace volumes.

CREATE INDEX IF NOT EXISTS idx_reasoning_traces_shadow_halted
    ON irl.reasoning_traces (txn_time DESC)
    WHERE policy_result = 'SHADOW_HALTED';
