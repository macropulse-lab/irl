-- tests/sql/test_kms_key_metadata.sql
-- SCHEMA-05 verification: irl.kms_key_metadata constraints
--
-- Verifies:
--   1. Table exists
--   2. INSERT with status='active' succeeds
--   3. INSERT with status='rotating' succeeds
--   4. INSERT with status='retired' succeeds
--   5. INSERT with status='INVALID' raises check_violation (SQLSTATE 23514)
--   6. Duplicate (key_version, provider) raises unique_violation (SQLSTATE 23505)
--
-- Expected output: 6 PASS NOTICE lines + 1 Cleanup line, exits 0.

DO $$
DECLARE
    caught BOOLEAN;
BEGIN
    -- 1. Table exists
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'irl' AND table_name = 'kms_key_metadata'
    ) THEN
        RAISE EXCEPTION 'FAIL: irl.kms_key_metadata does not exist';
    END IF;
    RAISE NOTICE 'PASS: irl.kms_key_metadata exists';

    -- 2. Valid INSERT: active
    INSERT INTO irl.kms_key_metadata (key_version, provider, key_arn_or_path, status)
    VALUES (9001, 'aws_kms', 'arn:aws:kms:us-east-1:0:key/test-active', 'active');
    RAISE NOTICE 'PASS: INSERT with status=active succeeded';

    -- 3. Valid INSERT: rotating (different key_version to avoid UNIQUE violation)
    INSERT INTO irl.kms_key_metadata (key_version, provider, key_arn_or_path, status)
    VALUES (9002, 'aws_kms', 'arn:aws:kms:us-east-1:0:key/test-rotating', 'rotating');
    RAISE NOTICE 'PASS: INSERT with status=rotating succeeded';

    -- 4. Valid INSERT: retired
    INSERT INTO irl.kms_key_metadata (key_version, provider, key_arn_or_path, status)
    VALUES (9003, 'aws_kms', 'arn:aws:kms:us-east-1:0:key/test-retired', 'retired');
    RAISE NOTICE 'PASS: INSERT with status=retired succeeded';

    -- 5. Invalid status raises check_violation
    caught := false;
    BEGIN
        INSERT INTO irl.kms_key_metadata (key_version, provider, key_arn_or_path, status)
        VALUES (9999, 'aws_kms', 'arn:test', 'INVALID');
    EXCEPTION WHEN check_violation THEN
        caught := true;
    END;
    IF NOT caught THEN
        RAISE EXCEPTION 'FAIL: INSERT with invalid status should raise check_violation';
    END IF;
    RAISE NOTICE 'PASS: CHECK constraint correctly rejected invalid status';

    -- 6. Duplicate (key_version, provider) raises unique_violation
    caught := false;
    BEGIN
        INSERT INTO irl.kms_key_metadata (key_version, provider, key_arn_or_path, status)
        VALUES (9001, 'aws_kms', 'arn:duplicate', 'active');
    EXCEPTION WHEN unique_violation THEN
        caught := true;
    END;
    IF NOT caught THEN
        RAISE EXCEPTION 'FAIL: Duplicate (key_version, provider) should raise unique_violation';
    END IF;
    RAISE NOTICE 'PASS: UNIQUE constraint on (key_version, provider) enforced';

    -- Cleanup
    DELETE FROM irl.kms_key_metadata WHERE key_version IN (9001, 9002, 9003) AND provider = 'aws_kms';
    RAISE NOTICE 'Cleanup: test rows deleted';
END $$;
