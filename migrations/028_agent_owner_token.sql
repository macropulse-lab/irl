-- Migration 028: tenant isolation — each agent belongs to the token that registered it.
--
-- Before this, any active client token could authorize, bind and read traces
-- for any agent_id. owner_token_id records the registering token; client
-- tokens may only act on agents they own. Owner-role tokens keep full access.
--
-- NULL owner_token_id = operator-owned (registered before this migration with
-- no audit record, or seeded): reachable by owner-role tokens only.

ALTER TABLE irl.agent_registry
    ADD COLUMN IF NOT EXISTS owner_token_id UUID
        REFERENCES irl.api_tokens (token_id);

CREATE INDEX IF NOT EXISTS idx_irl_agents_owner_token
    ON irl.agent_registry (owner_token_id);

-- Backfill from the audit log: AGENT_REGISTER rows record the registering
-- token as the first 12 hex chars of its SHA-256 hash (OperatorId). Only an
-- unambiguous prefix match is used.
UPDATE irl.agent_registry a
SET owner_token_id = m.token_id
FROM (
    SELECT DISTINCT ON (l.target_id) l.target_id, t.token_id
    FROM irl.admin_audit_log l
    JOIN irl.api_tokens t ON left(t.token_hash, 12) = l.operator_id
    WHERE l.action = 'AGENT_REGISTER'
      AND (SELECT count(*) FROM irl.api_tokens t2
           WHERE left(t2.token_hash, 12) = l.operator_id) = 1
    ORDER BY l.target_id, l.created_at ASC
) m
WHERE a.agent_id::text = m.target_id
  AND a.owner_token_id IS NULL;
