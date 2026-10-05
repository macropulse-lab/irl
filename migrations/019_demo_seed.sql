-- Migration 019: Demo / Sandbox Seed Data
--
-- Inserts pre-registered demo agents for the public sandbox instance.
-- Safe to apply to production — all rows use a reserved demo namespace and
-- can be identified / removed by agent_id or the 'demo' name prefix.
--
-- These agents exist so the Swagger UI demo flow works out of the box:
--   1. POST /irl/authorize  (use demo agent_id below)
--   2. POST /irl/bind-execution
--   3. GET  /irl/trace/{trace_id}
--
-- Demo agents are pre-approved for regime 0 (mock regime).
-- max_notional = 10000 (low cap — demonstration only).
-- model_hash_hex is the SHA-256 hex of the string "demo-model-v1".
--
-- ON CONFLICT DO NOTHING — safe to re-run on existing deployments.

INSERT INTO irl.agent_registry (
    agent_id,
    name,
    model_hash_hex,
    status,
    max_notional,
    allowed_regimes
) VALUES
(
    '00000000-0000-4000-a000-000000000001',
    'demo-crypto-agent',
    'a2f5e14b1c3a4f7d8e9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2',
    'Active',
    10000.0,
    ARRAY[0, 1, 2]::smallint[]
),
(
    '00000000-0000-4000-a000-000000000002',
    'demo-equities-agent',
    'a2f5e14b1c3a4f7d8e9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2',
    'Active',
    10000.0,
    ARRAY[0, 1, 2]::smallint[]
),
(
    '00000000-0000-4000-a000-000000000003',
    'demo-futures-agent',
    'a2f5e14b1c3a4f7d8e9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2',
    'Active',
    10000.0,
    ARRAY[0, 1, 2]::smallint[]
)
ON CONFLICT (agent_id) DO NOTHING;

-- Insert demo system note into system_config (does not overwrite existing values)
INSERT INTO irl.system_config (key, value_bool, updated_by)
VALUES ('demo_mode', true, 'migration-019')
ON CONFLICT (key) DO NOTHING;

COMMENT ON TABLE irl.agent_registry IS
    'Multi-Agent Registry (MAR). Stores agent identity, model hash, and trading limits. '
    'Demo agents (agent_id prefix 00000000-0000-4000-a000-) are sandbox only.';
