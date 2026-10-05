-- Migration 013: Partitioning dual-write — Phases A-B only
--
-- Goal: Convert irl.reasoning_traces from a plain heap table to a RANGE-partitioned
-- table using the 5-phase zero-downtime dual-write pattern.
--
-- Phases delivered here (A-B):
--   A. Rename legacy heap table to reasoning_traces_legacy
--   B. Create partitioned parent (reasoning_traces) with same column set + migration 011 columns
--   C. Install pg_partman extension and configure automated partitioning
--   D. Create UNION ALL view (reasoning_traces_unified) spanning legacy + partitioned
--   E. Add INSTEAD OF INSERT trigger to route new writes through view to partitioned table
--
-- Phases C-E of the full 5-phase pattern (backfill + atomic rename + legacy drop)
-- are deferred to Phase 5 (migration 014+), after GDPR erasure context is available.
--
-- After this migration:
--   irl.reasoning_traces_legacy  — original heap, holds all rows inserted before 013
--   irl.reasoning_traces         — partitioned parent (RANGE on txn_time), new rows go here
--   irl.reasoning_traces_unified — UNION ALL view, used by all SELECT queries in db.rs
--
-- Naming notes:
--   - db.rs INSERT still targets irl.reasoning_traces (now the partitioned parent directly)
--   - db.rs SELECT queries are updated in plan 01-02 task 3 to use irl.reasoning_traces_unified
--
-- SCHEMA-01

BEGIN;

-- ============================================================
-- Phase A: Rename existing heap table to legacy
-- ============================================================

ALTER TABLE irl.reasoning_traces RENAME TO reasoning_traces_legacy;

-- ============================================================
-- Phase B: Create partitioned parent with identical column set
-- ============================================================
-- Column order must match reasoning_traces_legacy exactly.
-- Migration 001 columns + migration 002 columns + migration 011 columns.
--
-- Key constraints:
--   PRIMARY KEY (trace_id, txn_time) — partition key must be part of PK
--   UNIQUE on reasoning_hash dropped — cross-partition UNIQUE not supported in PG15;
--   uniqueness of reasoning_hash is enforced in application layer (insert_trace_atomic)
--   CHECK constraints reproduced: chk_bitemporal, chk_policy_result, chk_verification_status

CREATE TABLE irl.reasoning_traces (
    -- From migration 001
    trace_id              UUID          NOT NULL,
    valid_time            TIMESTAMPTZ   NOT NULL,
    txn_time              TIMESTAMPTZ   NOT NULL,
    mta_regime_id         SMALLINT      NOT NULL,
    mta_version           TEXT          NOT NULL,
    mta_hash              TEXT          NOT NULL,
    latent_fingerprint    TEXT          NOT NULL,
    feature_schema_id     TEXT          NOT NULL,
    execution_action      TEXT          NOT NULL,
    execution_asset       TEXT          NOT NULL,
    client_order_id       TEXT          NOT NULL,
    exchange_tx_id        TEXT,
    verification_status   TEXT          NOT NULL DEFAULT 'PENDING',
    execution_status      TEXT,
    execution_price       NUMERIC(20, 8),
    execution_time        TIMESTAMPTZ,
    heartbeat_seq         BIGINT        NOT NULL,
    policy_id             TEXT          NOT NULL,
    policy_version        TEXT          NOT NULL,
    policy_hash           TEXT          NOT NULL,
    policy_result         TEXT          NOT NULL,
    reasoning_hash        TEXT          NOT NULL,
    final_proof           TEXT,
    trace_json            JSONB         NOT NULL,

    -- From migration 002
    execution_order_type  TEXT,
    execution_venue_id    TEXT,
    execution_quantity    NUMERIC(20, 8),
    execution_notional    NUMERIC(20, 8),
    execution_limit_price NUMERIC(20, 8),
    agent_id              UUID,

    -- From migration 011 (encryption + GDPR tombstone columns)
    key_version           INT,
    trace_nonce           BYTEA,
    encrypted_dek         BYTEA,
    encryption_version    INT           NOT NULL DEFAULT 0,
    gdpr_erased_at        TIMESTAMPTZ,
    gdpr_request_id       UUID,

    CONSTRAINT pk_reasoning_traces PRIMARY KEY (trace_id, txn_time),
    CONSTRAINT chk_bitemporal CHECK (valid_time < txn_time),
    CONSTRAINT chk_policy_result CHECK (policy_result IN ('ALLOWED', 'HALTED', 'SHADOW_HALTED')),
    CONSTRAINT chk_verification_status CHECK (
        verification_status IN ('PENDING', 'MATCHED', 'DIVERGENT', 'ORPHAN', 'EXPIRED')
    )
) PARTITION BY RANGE (txn_time);

-- ============================================================
-- Phase C: Install pg_partman and configure automated partitioning
-- ============================================================

CREATE SCHEMA IF NOT EXISTS partman;
CREATE EXTENSION IF NOT EXISTS pg_partman SCHEMA partman;

SELECT partman.create_parent(
    p_parent_table    => 'irl.reasoning_traces',
    p_control         => 'txn_time',
    p_interval        => '1 month',
    p_start_partition => date_trunc('month', now())::text,
    p_premake         => 3
);

-- Enable infinite time partitions (no data expiry in Phase 1)
-- Retention enforcement is a Phase 5 / DB-04 concern.
UPDATE partman.part_config
    SET infinite_time_partitions = true,
        retention_keep_table     = true
    WHERE parent_table = 'irl.reasoning_traces';

-- ============================================================
-- Phase D: Create UNION ALL view spanning legacy and partitioned tables
-- ============================================================
-- All SELECT queries in db.rs that must return historical rows use this view.
-- Column list is explicit (not SELECT *) to guarantee stable column ordering.

CREATE OR REPLACE VIEW irl.reasoning_traces_unified AS
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
    FROM irl.reasoning_traces_legacy
    UNION ALL
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
    FROM irl.reasoning_traces;

-- ============================================================
-- Phase E: INSTEAD OF INSERT trigger on the view
-- ============================================================
-- Routes all INSERT statements targeting the view to the partitioned parent.
-- Explicit column list (not NEW.*) is used to prevent positional ordering issues.

CREATE OR REPLACE FUNCTION irl.rt_insert_redirect()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
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
    ) VALUES (
        NEW.trace_id, NEW.valid_time, NEW.txn_time, NEW.mta_regime_id, NEW.mta_version,
        NEW.mta_hash, NEW.latent_fingerprint, NEW.feature_schema_id, NEW.execution_action,
        NEW.execution_asset, NEW.client_order_id, NEW.exchange_tx_id,
        NEW.verification_status, NEW.execution_status, NEW.execution_price,
        NEW.execution_time, NEW.heartbeat_seq, NEW.policy_id, NEW.policy_version,
        NEW.policy_hash, NEW.policy_result, NEW.reasoning_hash, NEW.final_proof,
        NEW.trace_json, NEW.execution_order_type, NEW.execution_venue_id,
        NEW.execution_quantity, NEW.execution_notional, NEW.execution_limit_price,
        NEW.agent_id, NEW.key_version, NEW.trace_nonce, NEW.encrypted_dek,
        NEW.encryption_version, NEW.gdpr_erased_at, NEW.gdpr_request_id
    );
    RETURN NULL;
END;
$$;

CREATE TRIGGER trg_rt_insert_redirect
    INSTEAD OF INSERT ON irl.reasoning_traces_unified
    FOR EACH ROW EXECUTE FUNCTION irl.rt_insert_redirect();

COMMIT;
