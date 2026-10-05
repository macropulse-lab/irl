-- Migration 010: CHECK Constraints + Covering Index
--
-- 1. Add CHECK constraints on policy_result and verification_status so the DB
--    rejects any values outside the documented enum (belt-and-suspenders guard
--    against application bugs and direct-SQL inserts).
--
-- 2. Replace the partial index on (agent_id) WHERE PENDING with a covering
--    index that also includes execution_notional. The portfolio SUM query
--    in get_pending_notional / insert_trace_atomic can now be satisfied entirely
--    from the index without touching the heap.
--
-- 3. Add index on (agent_id, verification_status) for the traces compliance
--    export query (GET /irl/traces with agent_id + status filters).

-- ── 1. CHECK constraints ────────────────────────────────────────────────────

ALTER TABLE irl.reasoning_traces
    ADD CONSTRAINT chk_policy_result CHECK (
        policy_result IN ('ALLOWED', 'HALTED', 'SHADOW_HALTED')
    );

ALTER TABLE irl.reasoning_traces
    ADD CONSTRAINT chk_verification_status CHECK (
        verification_status IN ('PENDING', 'MATCHED', 'DIVERGENT', 'ORPHAN', 'EXPIRED')
    );

-- ── 2. Covering index for portfolio cap enforcement ─────────────────────────

-- Drop the old non-covering partial index from migration 007.
DROP INDEX IF EXISTS irl.idx_reasoning_traces_agent_pending;

-- Covering index: (agent_id, execution_notional) WHERE PENDING
-- Allows COALESCE(SUM(execution_notional), 0) to be resolved index-only.
CREATE INDEX IF NOT EXISTS idx_reasoning_traces_agent_pending_notional
    ON irl.reasoning_traces (agent_id, execution_notional)
    WHERE verification_status = 'PENDING';

-- ── 3. Compliance export index ──────────────────────────────────────────────

CREATE INDEX IF NOT EXISTS idx_reasoning_traces_agent_status_time
    ON irl.reasoning_traces (agent_id, verification_status, txn_time DESC);
