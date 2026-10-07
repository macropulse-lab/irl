-- Migration 029: self-serve signup.
--
-- POST /irl/signup issues a client token without an operator. Such tokens are
-- tier 'paper': they may only authorize on paper venues (venue_id starting
-- with "paper") and own a limited number of agents. An operator upgrades a
-- token with: UPDATE irl.api_tokens SET tier = 'full' WHERE token_hash LIKE '<token_id>%';
--
-- signup_ip_hash is SHA-256 of the requester IP (never the raw IP), used only
-- for the per-IP daily signup limit.

ALTER TABLE irl.api_tokens
    ADD COLUMN IF NOT EXISTS tier TEXT NOT NULL DEFAULT 'full'
        CHECK (tier IN ('full', 'paper'));

ALTER TABLE irl.api_tokens ADD COLUMN IF NOT EXISTS contact TEXT;
ALTER TABLE irl.api_tokens ADD COLUMN IF NOT EXISTS signup_ip_hash TEXT;

CREATE INDEX IF NOT EXISTS idx_api_tokens_signup
    ON irl.api_tokens (created_at, signup_ip_hash)
    WHERE source = 'signup';
