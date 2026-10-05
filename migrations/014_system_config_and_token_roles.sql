-- Migration 014: system_config table + role column on api_tokens
--
-- DB-01: Add role column to irl.api_tokens to distinguish owner vs client tokens.
-- DB-01: Create irl.system_config as a DB-backed key/value store for operator settings.
--        Initial seed: shadow_mode row (value_bool = false).

-- ── 1. Add role column to irl.api_tokens ─────────────────────────────────────

ALTER TABLE irl.api_tokens
    ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'client'
        CHECK (role IN ('owner', 'client'));

-- Env-loaded tokens are owner-level (bootstrap / operator tokens).
UPDATE irl.api_tokens SET role = 'owner' WHERE source = 'env';

-- ── 2. Create irl.system_config ───────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS irl.system_config (
    key        TEXT        NOT NULL PRIMARY KEY,
    value_text TEXT,
    value_bool BOOLEAN,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by TEXT        NOT NULL DEFAULT 'system'
);

COMMENT ON TABLE irl.system_config IS
    'DB-backed key/value store for operator-controlled runtime settings. '
    'Reads are cached in-process (ShadowModeCache) to avoid per-request DB round-trips. '
    'Write via admin API; background refresh every 30 s picks up changes.';

-- ── 3. Seed shadow_mode row ───────────────────────────────────────────────────

INSERT INTO irl.system_config (key, value_bool, updated_by)
VALUES ('shadow_mode', false, 'system')
ON CONFLICT (key) DO NOTHING;
