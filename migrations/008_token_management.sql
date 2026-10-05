-- Migration 008: DB-backed Token Management
--
-- Replaces the static IRL_API_TOKENS env-var list with a persistent table.
-- Tokens loaded from env at startup are inserted here automatically.
-- Supports runtime rotation without restart.

CREATE TABLE IF NOT EXISTS irl.api_tokens (
    token_id     UUID        DEFAULT gen_random_uuid() PRIMARY KEY,
    token_hash   TEXT        NOT NULL UNIQUE,
    client_name  TEXT        NOT NULL DEFAULT 'env-loaded',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ,
    status       TEXT        NOT NULL DEFAULT 'active'
                             CHECK (status IN ('active', 'revoked')),
    source       TEXT        NOT NULL DEFAULT 'env'
);

CREATE INDEX IF NOT EXISTS idx_api_tokens_hash_active
    ON irl.api_tokens (token_hash)
    WHERE status = 'active';
