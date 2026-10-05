-- ============================================================
-- Migration 016 — Multi-MTA Trust (MTA-01, MTA-03)
--
-- Adds:
--   irl.agent_registry.allowed_mta_pubkeys TEXT[]
--     NULL = accept any MTA operator (default, backward-compatible).
--     Non-NULL = only accept MTAs whose pubkey hex fingerprint is in this list.
--     Enables firms to pin to a specific operator or declare a set of
--     acceptable operators (e.g. MacroPulse + in-house backup).
--
--   irl.reasoning_traces.mta_pubkey_used TEXT
--     Records the hex fingerprint of the specific Ed25519 public key that
--     signed the MTA broadcast for this trace.
--     Provides a complete audit trail: auditors can verify which operator
--     signed every individual trade decision.
-- ============================================================

-- MTA-01: Agent-level MTA pubkey allowlist
ALTER TABLE irl.agent_registry
    ADD COLUMN IF NOT EXISTS allowed_mta_pubkeys TEXT[] DEFAULT NULL;

COMMENT ON COLUMN irl.agent_registry.allowed_mta_pubkeys IS
    'Hex-encoded Ed25519 public key fingerprints of acceptable MTA operators.
     NULL means any operator is trusted. Set to restrict to specific operators.';

-- MTA-03: Per-trace record of which MTA key was used
ALTER TABLE irl.reasoning_traces
    ADD COLUMN IF NOT EXISTS mta_pubkey_used TEXT DEFAULT NULL;

COMMENT ON COLUMN irl.reasoning_traces.mta_pubkey_used IS
    'Hex fingerprint of the Ed25519 public key that signed the MTA regime
     broadcast for this trace. Populated on every authorize call.';

CREATE INDEX IF NOT EXISTS idx_reasoning_traces_mta_pubkey
    ON irl.reasoning_traces (mta_pubkey_used)
    WHERE mta_pubkey_used IS NOT NULL;
