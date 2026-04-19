-- 0002_oidc_sessions: persistent OIDC session store for cluster-safe auth.
-- Mirrors the sqlite migration; see that file for the rationale.

CREATE TABLE IF NOT EXISTS oidc_sessions (
    id         TEXT PRIMARY KEY,
    subject    TEXT NOT NULL DEFAULT '',
    email      TEXT NOT NULL DEFAULT '',
    name       TEXT NOT NULL DEFAULT '',
    is_admin   BOOLEAN NOT NULL DEFAULT FALSE,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_oidc_sessions_expires ON oidc_sessions(expires_at);
