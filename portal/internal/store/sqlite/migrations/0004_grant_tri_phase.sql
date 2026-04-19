-- 0004_grant_tri_phase: dual-gate approval + tri-phase lifecycle columns.
-- Adds the manager-approval half of the four-eyes gate (manager_subject is
-- captured at create-time from Entra; manager_approved_{by,at} record the
-- transition) and splits the single ExpiresAt into three deadlines:
--   * request_expires_at — phase 1, the validation window
--   * claim_expires_at   — phase 2, when an APPROVED grant stops being claimable
--   * expires_at         — phase 3, the credential TTL after /claim (existing column)
-- All new columns are NULL/empty-default for backwards compat with rows
-- predating the dual-gate flow.

ALTER TABLE grants ADD COLUMN manager_subject     TEXT NOT NULL DEFAULT '';
ALTER TABLE grants ADD COLUMN manager_approved_by TEXT NOT NULL DEFAULT '';
ALTER TABLE grants ADD COLUMN manager_approved_at TEXT;
ALTER TABLE grants ADD COLUMN request_expires_at  TEXT;
ALTER TABLE grants ADD COLUMN claim_expires_at    TEXT;
-- policy_mode caches the trio policy verdict (permanent | ephemeral) so the
-- /claim path doesn't have to re-resolve groups against the policy table.
-- Empty = admin/static-bearer bypass (treated as permanent at /claim).
ALTER TABLE grants ADD COLUMN policy_mode         TEXT NOT NULL DEFAULT '';
