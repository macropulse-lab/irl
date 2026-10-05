-- Migration 012: admin_audit_log (append-only) and kms_key_metadata
--
-- SCHEMA-04: admin_audit_log — immutable audit trail for all operator actions.
--   Append-only enforced at DB level via trigger (cannot be bypassed by any DB user
--   that does not have SUPERUSER or the ability to DROP the trigger).
--
-- SCHEMA-05: kms_key_metadata — tracks KMS key versions and their lifecycle status
--   to prevent unreadable-data-on-key-deletion.

-- ── admin_audit_log ───────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS irl.admin_audit_log (
    id           UUID        NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    operator_id  TEXT        NOT NULL,
    action       TEXT        NOT NULL,  -- AGENT_REGISTER | AGENT_SUSPEND | AGENT_ACTIVATE |
                                        -- TOKEN_ISSUE | TOKEN_REVOKE | TOKEN_ROTATE |
                                        -- SHADOW_MODE_CHANGE | GDPR_ERASURE
    target_type  TEXT        NOT NULL,  -- AGENT | TOKEN | SHADOW_MODE | TRACE
    target_id    TEXT,                  -- UUID or identifier of the affected resource
    details_json JSONB,                 -- Arbitrary structured detail (old/new values, reason)
    ip_address   INET,                  -- Source IP of the operator request
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE irl.admin_audit_log IS
    'Append-only audit log for all operator management actions. '
    'Immutability enforced by trg_admin_audit_log_immutable trigger. '
    'MiFID II Art. 17 / SOC 2 CC6.2 evidence table.';

CREATE INDEX IF NOT EXISTS idx_admin_audit_log_operator_time
    ON irl.admin_audit_log (operator_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_admin_audit_log_target
    ON irl.admin_audit_log (target_type, target_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_admin_audit_log_action_time
    ON irl.admin_audit_log (action, created_at DESC);

-- Immutability trigger: raises an exception on any UPDATE or DELETE attempt.
-- SQLSTATE 'restrict_violation' (23001) is used to signal a referential integrity
-- violation — appropriate because deleting an audit record violates audit chain integrity.
CREATE OR REPLACE FUNCTION irl.admin_audit_log_immutable()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION
        'admin_audit_log is append-only. % is forbidden on this table. (row id: %)',
        TG_OP, OLD.id
        USING ERRCODE = '23001';  -- restrict_violation
END;
$$;

CREATE TRIGGER trg_admin_audit_log_immutable
    BEFORE UPDATE OR DELETE ON irl.admin_audit_log
    FOR EACH ROW EXECUTE FUNCTION irl.admin_audit_log_immutable();

-- ── kms_key_metadata ──────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS irl.kms_key_metadata (
    id              UUID        NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    key_version     INT         NOT NULL,
    provider        TEXT        NOT NULL,        -- 'aws_kms' | 'vault_transit'
    key_arn_or_path TEXT        NOT NULL,        -- AWS KMS ARN or Vault Transit key path
    status          TEXT        NOT NULL DEFAULT 'active'
                                CHECK (status IN ('active', 'rotating', 'retired')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    rotated_at      TIMESTAMPTZ,                -- When this key version was superseded
    retired_at      TIMESTAMPTZ,                -- When this key version became inactive
    CONSTRAINT uq_kms_key_version_provider UNIQUE (key_version, provider)
);

COMMENT ON TABLE irl.kms_key_metadata IS
    'Tracks KMS key versions and their lifecycle status. '
    'Prevents unreadable-data-on-key-deletion: a key version cannot be retired until '
    'no reasoning_traces rows reference it (enforced in application layer, Phase 2). '
    'Referenced by irl.reasoning_traces.key_version.';

COMMENT ON COLUMN irl.kms_key_metadata.status IS
    'active = current key for new encryptions; '
    'rotating = new key created, backfill in progress, old key still valid for reads; '
    'retired = all data re-encrypted with newer key; this version is read-only for decryption only.';

CREATE INDEX IF NOT EXISTS idx_kms_key_metadata_status_version
    ON irl.kms_key_metadata (status, key_version DESC);
