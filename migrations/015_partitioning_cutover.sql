-- Migration 015: Partitioning cutover — backfill, atomic view removal, retention config
--
-- Phase F-G of the partitioning track started in migration 013.
--
-- Steps:
--   1. Backfill rows from reasoning_traces_legacy into the partitioned parent.
--   2. Atomic cutover: drop dual-write trigger, function, and UNION ALL view.
--   3. Configure pg_partman retention (36-month default; overridden at startup
--      by DB_RETENTION_MONTHS via the application partman update in main.rs).
--
-- Safety: ALL DDL in PostgreSQL is transactional. If the COMMIT fails, none of
-- the changes apply — the view and trigger are restored automatically.
--
-- Do NOT run this migration until reasoning_traces_legacy row count matches the
-- rows inserted into irl.reasoning_traces (partitioned parent) during the
-- dual-write window. Verify with:
--   SELECT (SELECT count(*) FROM irl.reasoning_traces_legacy)
--          = (SELECT count(*) FROM irl.reasoning_traces
--             WHERE txn_time < '<migration_013_date>'::timestamptz);

BEGIN;

-- ─────────────────────────────────────────────────────────────────────────────
-- Step 1: Backfill legacy rows (DB-03)
--
-- Copies all rows from reasoning_traces_legacy that do not already exist in the
-- partitioned parent. The NOT EXISTS guard makes this idempotent — safe to run
-- multiple times without duplicating rows.
-- ─────────────────────────────────────────────────────────────────────────────

INSERT INTO irl.reasoning_traces (
    trace_id, valid_time, txn_time, mta_regime_id, mta_version, mta_hash,
    latent_fingerprint, feature_schema_id, execution_action, execution_asset,
    client_order_id, exchange_tx_id, verification_status, execution_status,
    execution_price, execution_time, heartbeat_seq, policy_id, policy_version,
    policy_hash, policy_result, reasoning_hash, final_proof, trace_json,
    execution_order_type, execution_venue_id, execution_quantity,
    execution_notional, execution_limit_price, agent_id,
    key_version, trace_nonce, encrypted_dek, encryption_version,
    gdpr_erased_at, gdpr_request_id
)
SELECT
    trace_id, valid_time, txn_time, mta_regime_id, mta_version, mta_hash,
    latent_fingerprint, feature_schema_id, execution_action, execution_asset,
    client_order_id, exchange_tx_id, verification_status, execution_status,
    execution_price, execution_time, heartbeat_seq, policy_id, policy_version,
    policy_hash, policy_result, reasoning_hash, final_proof, trace_json,
    execution_order_type, execution_venue_id, execution_quantity,
    execution_notional, execution_limit_price, agent_id,
    key_version, trace_nonce, encrypted_dek, encryption_version,
    gdpr_erased_at, gdpr_request_id
FROM irl.reasoning_traces_legacy legacy
WHERE NOT EXISTS (
    SELECT 1 FROM irl.reasoning_traces pt
    WHERE pt.trace_id = legacy.trace_id
      AND pt.txn_time = legacy.txn_time
);

-- ─────────────────────────────────────────────────────────────────────────────
-- Step 2: Atomic cutover — drop dual-write infrastructure (DB-03)
--
-- Order matters:
--   a. Drop the redirect trigger on the view first (no new writes via view)
--   b. Drop the redirect function
--   c. Drop the UNION ALL view
--
-- After this step, all application queries MUST target irl.reasoning_traces
-- directly (db.rs has already been updated to do this in the same deployment).
-- ─────────────────────────────────────────────────────────────────────────────

-- Drop redirect trigger on the view first (stops new writes routing through view)
DROP TRIGGER IF EXISTS trg_rt_insert_redirect ON irl.reasoning_traces_unified;

-- Drop the redirect function
DROP FUNCTION IF EXISTS irl.rt_insert_redirect() CASCADE;

-- Drop the UNION ALL view — after this, all queries must target reasoning_traces directly
DROP VIEW IF EXISTS irl.reasoning_traces_unified;

-- reasoning_traces_legacy is NOT dropped here. Verify row counts match,
-- then run migration 016_drop_legacy.sql.
-- Verify with:
--   SELECT (SELECT count(*) FROM irl.reasoning_traces_legacy)
--          = (SELECT count(*) FROM irl.reasoning_traces
--             WHERE txn_time < '<migration_013_date>'::timestamptz)
--          AS backfill_complete;

-- ─────────────────────────────────────────────────────────────────────────────
-- Step 3: Configure pg_partman retention (DB-04)
--
-- Sets 36-month default retention. The application startup task (main.rs)
-- will override this with DB_RETENTION_MONTHS on every restart.
-- retention_keep_table = false means partitions are actually DROPped (not
-- just detached) when they exceed the retention window.
-- ─────────────────────────────────────────────────────────────────────────────

UPDATE partman.part_config
    SET retention              = '36 months',
        retention_keep_table   = false,
        retention_keep_index   = false,
        infinite_time_partitions = false,
        premake                = 3
    WHERE parent_table = 'irl.reasoning_traces';

COMMIT;
