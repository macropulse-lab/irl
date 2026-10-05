-- tests/sql/test_audit_log_immutable.sql
-- SCHEMA-04 verification: irl.admin_audit_log immutability
--
-- Verifies:
--   1. Table exists
--   2. INSERT succeeds
--   3. UPDATE raises exception (trigger enforces restrict_violation SQLSTATE 23001)
--   4. DELETE raises exception (same trigger)
--
-- Expected output: 4 PASS NOTICE lines, exits 0.
-- Note: test row remains in table after the run (DELETE was blocked — expected).

DO $$
DECLARE
    test_id UUID;
    caught  BOOLEAN;
BEGIN
    -- 1. Verify table exists
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'irl' AND table_name = 'admin_audit_log'
    ) THEN
        RAISE EXCEPTION 'FAIL: irl.admin_audit_log does not exist';
    END IF;
    RAISE NOTICE 'PASS: irl.admin_audit_log exists';

    -- 2. INSERT succeeds
    INSERT INTO irl.admin_audit_log (operator_id, action, target_type, target_id, details_json, ip_address)
    VALUES ('__test__', 'TEST_ACTION', 'AGENT', '__test-agent__', '{"test": true}', '127.0.0.1')
    RETURNING id INTO test_id;
    RAISE NOTICE 'PASS: INSERT succeeded, id=%', test_id;

    -- 3. UPDATE raises exception
    caught := false;
    BEGIN
        UPDATE irl.admin_audit_log SET operator_id = 'tampered' WHERE id = test_id;
    EXCEPTION WHEN OTHERS THEN
        caught := true;
    END;
    IF NOT caught THEN
        RAISE EXCEPTION 'FAIL: UPDATE on admin_audit_log did not raise an exception';
    END IF;
    RAISE NOTICE 'PASS: UPDATE on admin_audit_log correctly raised exception';

    -- 4. DELETE raises exception
    caught := false;
    BEGIN
        DELETE FROM irl.admin_audit_log WHERE id = test_id;
    EXCEPTION WHEN OTHERS THEN
        caught := true;
    END;
    IF NOT caught THEN
        RAISE EXCEPTION 'FAIL: DELETE on admin_audit_log did not raise an exception';
    END IF;
    RAISE NOTICE 'PASS: DELETE on admin_audit_log correctly raised exception';

    -- Note: test_id row remains in the table (delete was blocked). This is correct.
    -- The row with operator_id='__test__' is the evidence that the trigger works.
END $$;
