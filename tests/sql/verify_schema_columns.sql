-- verify_schema_columns.sql
-- Verifies SCHEMA-02 and SCHEMA-03: all 6 new columns exist on irl.reasoning_traces
-- (whether heap or partitioned after migration 013).
--
-- Usage:
--   psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f tests/sql/verify_schema_columns.sql
--
-- Expected output (after migration 011):
--   NOTICE:  PASS: All 6 new columns present on irl.reasoning_traces
--   NOTICE:  PASS: encryption_version has DEFAULT 0
--
-- Exit code 0 on success; non-zero if any RAISE EXCEPTION is hit.

-- Check 1: All 6 columns present
DO $$
DECLARE
    missing_cols TEXT[] := ARRAY[]::TEXT[];
    col TEXT;
    expected TEXT[] := ARRAY[
        'key_version', 'trace_nonce', 'encrypted_dek', 'encryption_version',
        'gdpr_erased_at', 'gdpr_request_id'
    ];
BEGIN
    FOREACH col IN ARRAY expected LOOP
        IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_schema = 'irl'
              AND table_name   = 'reasoning_traces'
              AND column_name  = col
        ) AND NOT EXISTS (
            -- Also check legacy table or unified view post-migration-013
            SELECT 1 FROM information_schema.columns
            WHERE table_schema = 'irl'
              AND table_name   IN ('reasoning_traces_legacy', 'reasoning_traces_unified')
              AND column_name  = col
        ) THEN
            missing_cols := array_append(missing_cols, col);
        END IF;
    END LOOP;

    IF array_length(missing_cols, 1) > 0 THEN
        RAISE EXCEPTION 'Missing columns on irl.reasoning_traces: %', array_to_string(missing_cols, ', ');
    ELSE
        RAISE NOTICE 'PASS: All 6 new columns present on irl.reasoning_traces';
    END IF;
END $$;

-- Check 2: encryption_version has DEFAULT 0
DO $$
DECLARE
    col_default TEXT;
BEGIN
    SELECT column_default INTO col_default
    FROM information_schema.columns
    WHERE table_schema = 'irl'
      AND table_name   = 'reasoning_traces'
      AND column_name  = 'encryption_version';

    IF col_default IS NULL OR col_default NOT LIKE '%0%' THEN
        RAISE EXCEPTION 'encryption_version must have DEFAULT 0, got: %', COALESCE(col_default, 'NULL');
    ELSE
        RAISE NOTICE 'PASS: encryption_version has DEFAULT 0';
    END IF;
END $$;
