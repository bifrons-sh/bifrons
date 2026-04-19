-- 0002_users_external_id: add OIDC subject linking for first-login provisioning.
-- ExternalID is the OIDC `sub` claim — stable across IdP email/username changes
-- so we can match a returning user even after rename events. NULL for users
-- created out-of-band via the admin API; UNIQUE prevents two portal users from
-- claiming the same IdP identity.

ALTER TABLE users ADD COLUMN external_id TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_external_id ON users(external_id) WHERE external_id IS NOT NULL;
