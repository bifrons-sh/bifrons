-- 0003_grant_ephemeral: add per-grant ephemeral backend user columns.
-- When the ephemeral provisioner is enabled, /approve populates these with the
-- randomly generated backend credential (username + 32-byte password) so the
-- policy engine can serve them instead of the shared BackendAccount secret.
-- Empty strings mean "not provisioned" — the engine falls back to the shared
-- account, preserving backwards compatibility with existing rows.

ALTER TABLE grants ADD COLUMN ephemeral_username TEXT NOT NULL DEFAULT '';
ALTER TABLE grants ADD COLUMN ephemeral_password TEXT NOT NULL DEFAULT '';
