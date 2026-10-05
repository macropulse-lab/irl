-- Migration 020: Merkle anchor receipts table
--
-- Stores one row per anchoring cycle: the binary Merkle root computed over
-- all reasoning_hash values in the period, plus the raw OpenTimestamps receipt.
-- Even if the OTS POST fails, the Merkle root is preserved — the receipt can
-- be obtained retroactively by re-submitting the root to OTS.

CREATE TABLE IF NOT EXISTS irl.merkle_anchors (
    id            BIGSERIAL    PRIMARY KEY,
    period_start  TIMESTAMPTZ  NOT NULL,
    period_end    TIMESTAMPTZ  NOT NULL,
    leaf_count    INT          NOT NULL,
    merkle_root   TEXT         NOT NULL,   -- lower-hex SHA-256 of binary Merkle root
    ots_receipt   BYTEA,                   -- raw OTS calendar receipt bytes; NULL if POST failed
    ots_error     TEXT,                    -- error message when ots_receipt IS NULL
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now()
);

COMMENT ON TABLE irl.merkle_anchors IS
    'One row per daily anchoring cycle. merkle_root is the binary Merkle root of all '
    'reasoning_hash values in [period_start, period_end). ots_receipt is the raw '
    'OpenTimestamps calendar receipt that proves the root existed before a Bitcoin block.';

COMMENT ON COLUMN irl.merkle_anchors.merkle_root IS
    'Lower-hex SHA-256 binary Merkle root over reasoning_hash values sorted by txn_time. '
    'Can be independently verified by any auditor who holds the leaf hashes.';

COMMENT ON COLUMN irl.merkle_anchors.ots_receipt IS
    'Raw binary OpenTimestamps receipt (incomplete calendar timestamp). '
    'Submit to an OTS calendar to obtain the Bitcoin block proof. '
    'NULL means the OTS POST failed; ots_error holds the reason.';

CREATE INDEX IF NOT EXISTS idx_merkle_anchors_period_end
    ON irl.merkle_anchors (period_end DESC);
