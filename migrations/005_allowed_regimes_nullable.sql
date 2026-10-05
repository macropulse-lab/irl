-- Migration 005: Make allowed_regimes nullable.
--
-- NULL means "allow all regime IDs" — correct default for operators using
-- custom MTA implementations with their own regime taxonomy.
-- The old DEFAULT ARRAY[0,1,2,3] was MacroPulse-specific and would silently
-- block all authorize calls for any agent registered against a custom MTA.
--
-- Existing rows with ARRAY[0,1,2,3] are left unchanged (their behavior
-- does not change for MacroPulse-based deployments).

ALTER TABLE irl.agent_registry
    ALTER COLUMN allowed_regimes DROP NOT NULL;

ALTER TABLE irl.agent_registry
    ALTER COLUMN allowed_regimes SET DEFAULT NULL;
