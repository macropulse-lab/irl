-- Migration 018: Execution Intent v2 — Multi-Market Columns
--
-- Adds the three new fields introduced in v1.1 (multi-market readiness):
--   execution_notional_currency — ISO 4217 currency of the notional (default: USD)
--   execution_multiplier        — contract multiplier for futures/options (default: 1.0)
--   execution_stop_price        — stop trigger price for StopLimit orders (nullable)
--
-- All columns have safe defaults so all existing rows and INSERT statements
-- remain valid without modification. New INSERTs should populate all three.

ALTER TABLE irl.reasoning_traces
    ADD COLUMN IF NOT EXISTS execution_notional_currency TEXT           NOT NULL DEFAULT 'USD',
    ADD COLUMN IF NOT EXISTS execution_multiplier        NUMERIC(10, 6) NOT NULL DEFAULT 1.0,
    ADD COLUMN IF NOT EXISTS execution_stop_price        NUMERIC(20, 8);

-- Backfill existing rows: already have DEFAULT values above, nothing needed.

COMMENT ON COLUMN irl.reasoning_traces.execution_notional_currency IS
    'ISO 4217 currency of execution_notional. Default USD. '
    'Enables multi-currency position tracking and cross-asset cap enforcement.';
COMMENT ON COLUMN irl.reasoning_traces.execution_multiplier IS
    'Contract multiplier. 1.0 for spot/equities/crypto perps. '
    'Examples: CME ES = 50, Euronext CAC40 futures = 10, equity options = 100.';
COMMENT ON COLUMN irl.reasoning_traces.execution_stop_price IS
    'Stop trigger price for StopLimit orders. NULL for non-stop order types.';

-- Also extend the partitioned table (irl.reasoning_traces_partitioned) if it exists.
-- This guard keeps the migration safe whether or not partitioning has been deployed.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'irl'
          AND table_name = 'reasoning_traces_partitioned'
    ) THEN
        ALTER TABLE irl.reasoning_traces_partitioned
            ADD COLUMN IF NOT EXISTS execution_notional_currency TEXT           NOT NULL DEFAULT 'USD',
            ADD COLUMN IF NOT EXISTS execution_multiplier        NUMERIC(10, 6) NOT NULL DEFAULT 1.0,
            ADD COLUMN IF NOT EXISTS execution_stop_price        NUMERIC(20, 8);
    END IF;
END $$;
