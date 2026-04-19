-- 0003_grant_ephemeral: add per-grant ephemeral backend user columns.
-- Mirrors the sqlite migration. Empty strings mean "not provisioned" — the
-- policy engine falls back to the shared BackendAccount for the role.

ALTER TABLE grants ADD COLUMN IF NOT EXISTS ephemeral_username TEXT NOT NULL DEFAULT '';
ALTER TABLE grants ADD COLUMN IF NOT EXISTS ephemeral_password TEXT NOT NULL DEFAULT '';
