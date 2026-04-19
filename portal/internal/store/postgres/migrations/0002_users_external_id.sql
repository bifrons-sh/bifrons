-- 0002_users_external_id: add OIDC subject linking for first-login provisioning.
-- ExternalID is the OIDC `sub` claim — stable across IdP email/username changes.
-- Partial UNIQUE index means NULL values don't collide (users created via the
-- admin API without an IdP binding).

ALTER TABLE users ADD COLUMN IF NOT EXISTS external_id TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_external_id ON users(external_id) WHERE external_id IS NOT NULL;
