-- Migration 022: OTS receipt upgrade tracking
--
-- Adds two columns to irl.merkle_anchors:
--   ots_upgraded_at     — when an OTS receipt was successfully obtained (initial or retry)
--   ots_complete_receipt — the Bitcoin-confirmed complete OTS proof, once available
--
-- Lifecycle:
--   1. run_anchor_cycle: INSERT with ots_receipt + ots_upgraded_at set when POST succeeds.
--      If POST fails: ots_receipt=NULL, ots_error=<reason>, ots_upgraded_at=NULL.
--   2. run_ots_upgrade_worker (hourly): re-submits failed rows; sets ots_receipt +
--      ots_upgraded_at when a retry succeeds.
--   3. ots_complete_receipt: populated out-of-band by the `ots upgrade` CLI once the
--      Bitcoin block containing the anchor has been mined (~10–20 min per block).

ALTER TABLE irl.merkle_anchors
    ADD COLUMN IF NOT EXISTS ots_upgraded_at      TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS ots_complete_receipt  BYTEA;

COMMENT ON COLUMN irl.merkle_anchors.ots_upgraded_at IS
    'Timestamp when an OTS receipt was successfully obtained for this anchor '
    '(either on initial POST or on a retry by the upgrade worker). NULL means '
    'the OTS POST has never succeeded for this anchor.';

COMMENT ON COLUMN irl.merkle_anchors.ots_complete_receipt IS
    'Bitcoin-confirmed complete OTS proof. Populated out-of-band via `ots upgrade` '
    'after the anchor block has been mined (~10–20 min). NULL until upgraded.';

-- Partial index: quickly find anchors that still need an OTS receipt.
CREATE INDEX IF NOT EXISTS idx_merkle_anchors_needs_ots
    ON irl.merkle_anchors (period_end DESC)
    WHERE ots_receipt IS NULL;
