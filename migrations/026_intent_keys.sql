-- Layer 2 v2 replay protection: one authorized intent per (agent_id, client_order_id).
-- A resubmitted authorize returns 409 DUPLICATE_INTENT with the original trace_id,
-- which also makes client retries idempotent. Kept outside the partitioned
-- irl.reasoning_traces because unique constraints there must include the
-- partition key (txn_time).
CREATE TABLE IF NOT EXISTS irl.intent_keys (
    agent_id        UUID        NOT NULL,
    client_order_id TEXT        NOT NULL,
    trace_id        UUID        NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (agent_id, client_order_id)
);
