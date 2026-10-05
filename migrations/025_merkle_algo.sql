-- Migration 025: tag each Merkle anchor with its root construction
--
-- Supports the T-1.2 anchor-worker migration to domain-separated (RFC-6962)
-- roots that fix the v1 second-preimage weakness.
--
-- Non-breaking: the column is NULLABLE and NULL means the legacy v1
-- construction (`SHA256(l||r)`, no domain separation, last-node duplication).
-- Every existing anchor stays v1. New anchors written while MERKLE_V2_ENABLED
-- is true store 'rfc6962-sha256-v2'. The offline verifier selects the root
-- recomputation per anchor from this tag.

ALTER TABLE irl.merkle_anchors
  ADD COLUMN IF NOT EXISTS merkle_algo TEXT;
