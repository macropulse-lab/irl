-- Per-agent asset allowlist, enforced at /irl/authorize alongside allowed_venues.
-- NULL = any asset (the existing behaviour). Matching is case-insensitive on the
-- asset string the agent submits, so register the same symbol format it sends.
ALTER TABLE irl.agent_registry ADD COLUMN IF NOT EXISTS allowed_assets TEXT[];
