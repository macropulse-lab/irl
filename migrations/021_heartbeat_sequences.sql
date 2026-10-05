-- Migration 021: Per-agent heartbeat sequence tracking
--
-- Persists the last accepted heartbeat sequence number for each agent.
-- This allows the HeartbeatValidator to survive server restarts without
-- losing its anti-replay state — an attacker cannot replay a heartbeat
-- that was accepted before the restart.
--
-- The in-memory DashMap is the hot path; this table is the source of truth
-- used to hydrate the map on startup and to persist accepted sequences.

CREATE TABLE IF NOT EXISTS irl.heartbeat_sequences (
    agent_id      UUID        NOT NULL,
    last_sequence BIGINT      NOT NULL DEFAULT 0,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT heartbeat_sequences_pkey PRIMARY KEY (agent_id)
);

COMMENT ON TABLE irl.heartbeat_sequences IS
    'Crash-recovery store for per-agent heartbeat sequence numbers. '
    'The HeartbeatValidator loads this on startup to restore anti-replay state '
    'and upserts here after every accepted heartbeat.';

COMMENT ON COLUMN irl.heartbeat_sequences.last_sequence IS
    'Highest sequence_id accepted from this agent. Any incoming heartbeat with '
    'sequence_id <= last_sequence is rejected as a replay attempt.';

CREATE INDEX IF NOT EXISTS idx_heartbeat_sequences_updated_at
    ON irl.heartbeat_sequences (updated_at DESC);
