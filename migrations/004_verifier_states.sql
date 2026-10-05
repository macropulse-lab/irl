-- Migration 004: Post-Trade Verifier lifecycle states — whitepaper v3 §11.
-- Adds an index to accelerate the async expiry worker's PENDING → EXPIRED sweep.

CREATE INDEX IF NOT EXISTS idx_irl_traces_pending_expiry
    ON irl.reasoning_traces (txn_time)
    WHERE verification_status = 'PENDING';
