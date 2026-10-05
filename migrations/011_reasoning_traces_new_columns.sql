-- Migration 011: Add encryption and GDPR tombstone columns to irl.reasoning_traces
--
-- These columns must exist before Phase 2 (KMS + encryption) writes any encrypted data.
-- All columns are nullable or have safe defaults to preserve backward compatibility
-- with all existing INSERT statements in db.rs.
--
-- SCHEMA-02: key_version, trace_nonce, encrypted_dek, encryption_version
-- SCHEMA-03: gdpr_erased_at, gdpr_request_id

ALTER TABLE irl.reasoning_traces
    ADD COLUMN IF NOT EXISTS key_version        INT,
    ADD COLUMN IF NOT EXISTS trace_nonce        BYTEA,
    ADD COLUMN IF NOT EXISTS encrypted_dek      BYTEA,
    ADD COLUMN IF NOT EXISTS encryption_version INT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS gdpr_erased_at     TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS gdpr_request_id    UUID;

COMMENT ON COLUMN irl.reasoning_traces.key_version IS
    'KMS CMK version that wrapped the DEK for this trace. NULL = plaintext legacy row (encryption_version=0).';
COMMENT ON COLUMN irl.reasoning_traces.trace_nonce IS
    'AES-256-GCM nonce (12 bytes), unique per trace. NULL = plaintext legacy row.';
COMMENT ON COLUMN irl.reasoning_traces.encrypted_dek IS
    'KMS-wrapped data encryption key for this trace. NULL = plaintext legacy row.';
COMMENT ON COLUMN irl.reasoning_traces.encryption_version IS
    '0 = legacy plaintext row; 1 = AES-256-GCM envelope encryption. '
    'Phase 2 read path branches on this value. Default 0 ensures all existing rows are treated as plaintext.';
COMMENT ON COLUMN irl.reasoning_traces.gdpr_erased_at IS
    'Timestamp when PII fields within trace_json were tombstone-erased per a GDPR Art. 17 request. '
    'NULL = not erased. reasoning_hash is preserved unchanged after erasure.';
COMMENT ON COLUMN irl.reasoning_traces.gdpr_request_id IS
    'UUID of the GDPR erasure request that produced this tombstone. '
    'References the corresponding admin_audit_log row. NULL = not erased.';
