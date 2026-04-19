-- 0004_grant_tri_phase: dual-gate approval + tri-phase lifecycle columns.
-- Mirrors the sqlite migration. See that file for the deadline semantics.

ALTER TABLE grants ADD COLUMN IF NOT EXISTS manager_subject     TEXT NOT NULL DEFAULT '';
ALTER TABLE grants ADD COLUMN IF NOT EXISTS manager_approved_by TEXT NOT NULL DEFAULT '';
ALTER TABLE grants ADD COLUMN IF NOT EXISTS manager_approved_at TIMESTAMPTZ;
ALTER TABLE grants ADD COLUMN IF NOT EXISTS request_expires_at  TIMESTAMPTZ;
ALTER TABLE grants ADD COLUMN IF NOT EXISTS claim_expires_at    TIMESTAMPTZ;
ALTER TABLE grants ADD COLUMN IF NOT EXISTS policy_mode         TEXT NOT NULL DEFAULT '';
