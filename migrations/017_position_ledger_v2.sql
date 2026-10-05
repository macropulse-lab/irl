-- Migration 017: Position Ledger v2 — Multi-Market Columns
--
-- Extends irl.agent_positions with columns needed for multi-market, multi-currency
-- position tracking across equities, futures, crypto perps, and FX.
--
-- New columns (all nullable for backward compatibility with existing rows):
--   venue_id          — MIC code or internal route ID (matches ExecutionIntent.venue_id)
--   currency          — ISO 4217 currency of the position notional (default: USD)
--   average_price     — volume-weighted average entry price (NULL until first fill)
--   unfilled_quantity — quantity submitted but not yet confirmed matched
--   notional          — current notional exposure (net_quantity × average_price)
--   multiplier        — contract multiplier, default 1.0 (for futures/options)
--
-- Index change:
--   Old UNIQUE(agent_id, asset) → New UNIQUE(agent_id, asset, venue_id, currency)
--   This allows the same agent to hold positions in the same asset across multiple
--   venues (e.g. AAPL on XNAS and XLON), or the same asset in different currencies
--   (e.g. BTC-PERP in USD and EUR).
--
-- NOTE: The old unique constraint is dropped before the new one is added.
-- Existing rows get venue_id='UNKNOWN' and currency='USD' as defaults so they
-- satisfy the new constraint. Update via application backfill if needed.

-- Step 1: Add new columns with safe defaults
ALTER TABLE irl.agent_positions
    ADD COLUMN IF NOT EXISTS venue_id      TEXT           NOT NULL DEFAULT 'UNKNOWN',
    ADD COLUMN IF NOT EXISTS currency      TEXT           NOT NULL DEFAULT 'USD',
    ADD COLUMN IF NOT EXISTS average_price NUMERIC(24, 8),
    ADD COLUMN IF NOT EXISTS unfilled_quantity NUMERIC(20, 8) NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS notional      NUMERIC(24, 8) NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS multiplier    NUMERIC(10, 6) NOT NULL DEFAULT 1.0;

-- Step 2: Drop the old unique constraint (covers agent_id, asset only)
ALTER TABLE irl.agent_positions
    DROP CONSTRAINT IF EXISTS agent_positions_agent_id_asset_key;

-- Step 3: Add the new composite unique constraint
ALTER TABLE irl.agent_positions
    ADD CONSTRAINT agent_positions_unique_position
    UNIQUE (agent_id, asset, venue_id, currency);

-- Step 4: Additional indexes for query patterns
CREATE INDEX IF NOT EXISTS idx_agent_positions_venue
    ON irl.agent_positions (venue_id);

CREATE INDEX IF NOT EXISTS idx_agent_positions_currency
    ON irl.agent_positions (currency);

-- Step 5: Comment the table
COMMENT ON TABLE irl.agent_positions IS
    'Net open position per agent per asset/venue/currency. '
    'Updated atomically by bind-execution on MATCHED verification. '
    'v2: multi-market columns (venue_id, currency, average_price, multiplier).';
