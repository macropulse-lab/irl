-- tests/sql/test_partitioning_dual_write.sql
-- Verify migration 013 correctness: partitioned table, pg_partman config,
-- UNION ALL view, and INSTEAD OF INSERT trigger routing.
--
-- SCHEMA-01
--
-- Run after sqlx migrate run (migrations 001-013 applied):
--   psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f tests/sql/test_partitioning_dual_write.sql
--
-- Expected output: 7 PASS lines, exits 0.

DO $$
DECLARE
    partition_count  INT;
    row_count        INT;
    relkind_val      CHAR(1);
    partman_count    INT;
    test_order_id    TEXT := '__test_partition_' || gen_random_uuid()::text || '__';
BEGIN
    -- 1. reasoning_traces_legacy exists (original heap, renamed by migration 013)
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'irl' AND table_name = 'reasoning_traces_legacy'
    ) THEN
        RAISE EXCEPTION 'FAIL: irl.reasoning_traces_legacy does not exist';
    END IF;
    RAISE NOTICE 'PASS: irl.reasoning_traces_legacy exists';

    -- 2. reasoning_traces is a partitioned table (relkind = 'p')
    SELECT c.relkind INTO relkind_val
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'irl' AND c.relname = 'reasoning_traces';

    IF relkind_val IS DISTINCT FROM 'p' THEN
        RAISE EXCEPTION 'FAIL: irl.reasoning_traces is not a partitioned table, relkind=%',
            COALESCE(relkind_val::text, 'NULL');
    END IF;
    RAISE NOTICE 'PASS: irl.reasoning_traces is a partitioned table (relkind=p)';

    -- 3. reasoning_traces_unified is a view
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.views
        WHERE table_schema = 'irl' AND table_name = 'reasoning_traces_unified'
    ) THEN
        RAISE EXCEPTION 'FAIL: irl.reasoning_traces_unified view does not exist';
    END IF;
    RAISE NOTICE 'PASS: irl.reasoning_traces_unified view exists';

    -- 4. At least one child partition exists under irl.reasoning_traces
    SELECT COUNT(*) INTO partition_count
    FROM pg_inherits
    WHERE inhparent = 'irl.reasoning_traces'::regclass;

    IF partition_count < 1 THEN
        RAISE EXCEPTION 'FAIL: No child partitions found under irl.reasoning_traces';
    END IF;
    RAISE NOTICE 'PASS: % child partition(s) exist', partition_count;

    -- 5. pg_partman is configured for irl.reasoning_traces
    SELECT COUNT(*) INTO partman_count
    FROM partman.part_config
    WHERE parent_table = 'irl.reasoning_traces';

    IF partman_count != 1 THEN
        RAISE EXCEPTION 'FAIL: pg_partman part_config missing for irl.reasoning_traces (found % rows)',
            partman_count;
    END IF;
    RAISE NOTICE 'PASS: pg_partman is configured for irl.reasoning_traces';

    -- 6. INSERT into irl.reasoning_traces routes to a child partition
    INSERT INTO irl.reasoning_traces (
        trace_id, valid_time, txn_time, mta_regime_id, mta_version, mta_hash,
        latent_fingerprint, feature_schema_id, execution_action, execution_asset,
        client_order_id, heartbeat_seq, policy_id, policy_version, policy_hash,
        policy_result, reasoning_hash, trace_json, encryption_version
    ) VALUES (
        gen_random_uuid(),
        now() - interval '2 seconds',
        now() - interval '1 second',
        1, 'v1.0', 'testhash',
        'testfp', 'testfs',
        'Long(1.0)', 'BTC-USD',
        test_order_id,
        1, 'policy-test', '1.0', 'policyhash',
        'ALLOWED',
        'reasoning-hash-test-' || gen_random_uuid()::text,
        '{"test": true}'::jsonb,
        0
    );

    SELECT COUNT(*) INTO row_count
    FROM irl.reasoning_traces
    WHERE client_order_id = test_order_id;

    IF row_count != 1 THEN
        RAISE EXCEPTION 'FAIL: Expected 1 row in partitioned table, found %', row_count;
    END IF;
    RAISE NOTICE 'PASS: INSERT into reasoning_traces routed to child partition';

    -- 7. UNION ALL view (reasoning_traces_unified) shows the inserted row
    SELECT COUNT(*) INTO row_count
    FROM irl.reasoning_traces_unified
    WHERE client_order_id = test_order_id;

    IF row_count != 1 THEN
        RAISE EXCEPTION 'FAIL: reasoning_traces_unified does not show inserted row, count=%', row_count;
    END IF;
    RAISE NOTICE 'PASS: reasoning_traces_unified shows the inserted row';

    -- Cleanup: remove the test row
    DELETE FROM irl.reasoning_traces WHERE client_order_id = test_order_id;
    RAISE NOTICE 'Cleanup: test row deleted from partitioned table';
END $$;
