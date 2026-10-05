-- Migration 023: multi-agent trace linking
--
-- Adds parent_trace_id so sub-agent decisions can reference the orchestrator
-- trace that triggered them. Enables full ancestry chain queries for compliance.
--
-- The column is nullable — existing single-agent traces are unaffected.
-- No FK constraint: reasoning_traces is RANGE-partitioned on txn_time and PG15
-- does not support unique constraints on non-partition-key columns across partitions.
-- Referential integrity is enforced at the application layer (routes/chain.rs).

ALTER TABLE irl.reasoning_traces
  ADD COLUMN IF NOT EXISTS parent_trace_id UUID;

CREATE INDEX IF NOT EXISTS idx_reasoning_traces_parent
  ON irl.reasoning_traces (parent_trace_id)
  WHERE parent_trace_id IS NOT NULL;
