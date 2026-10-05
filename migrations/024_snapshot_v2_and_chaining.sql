-- Migration 024: v2 split-commitment seal + per-trace chaining columns
--
-- Supports the T-1.0/T-1.1 split public/private commitment seal and reserves
-- the T-1.3 per-agent hash-chain columns.
--
-- Non-breaking:
--   * snapshot_version defaults to 1 (whole-snapshot v1 seal) for every
--     existing row and every trace sealed while SNAPSHOT_V2_ENABLED=false.
--   * private_commitment is NULL for v1 traces (only v2 traces populate it).
--   * chain_seq / prev_reasoning_hash are added NULLABLE and are NOT populated
--     by the request path yet — populating them requires the single-writer
--     sequence assigner (T-2.0), so that per-request chaining does not
--     reintroduce a hot-path lock. Left dormant here on purpose.

ALTER TABLE irl.reasoning_traces
  ADD COLUMN IF NOT EXISTS snapshot_version   SMALLINT NOT NULL DEFAULT 1,
  ADD COLUMN IF NOT EXISTS private_commitment TEXT,
  ADD COLUMN IF NOT EXISTS chain_seq          BIGINT,
  ADD COLUMN IF NOT EXISTS prev_reasoning_hash TEXT;

-- Fast lookup of v2 traces during proof-bundle export (once the v2-aware
-- verifier ships). Partial index keeps it cheap while v2 adoption is low.
CREATE INDEX IF NOT EXISTS idx_reasoning_traces_snapshot_v2
  ON irl.reasoning_traces (snapshot_version)
  WHERE snapshot_version >= 2;

-- NOTE (T-2.0): the per-agent chain uniqueness index is intentionally deferred
-- until the single-writer assigns chain_seq. Adding it now would be a no-op
-- (all chain_seq are NULL) and PG15 range-partitioning constrains cross-
-- partition uniqueness. Ship it with the chaining writer:
--   CREATE UNIQUE INDEX ux_traces_agent_chain
--     ON irl.reasoning_traces (agent_id, chain_seq)
--     WHERE chain_seq IS NOT NULL;
