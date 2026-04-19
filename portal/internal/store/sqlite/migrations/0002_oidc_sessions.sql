-- 0002_oidc_sessions: persistent OIDC session store for cluster-safe auth.
-- Sessions are opaque 256-bit tokens minted at callback; storing them here
-- means any portal replica sharing the DB can validate the cookie.

CREATE TABLE IF NOT EXISTS oidc_sessions (
    id         TEXT PRIMARY KEY,
    subject    TEXT NOT NULL DEFAULT '',
    email      TEXT NOT NULL DEFAULT '',
    name       TEXT NOT NULL DEFAULT '',
    is_admin   INTEGER NOT NULL DEFAULT 0,
    expires_at TEXT NOT NULL
);

-- Index used by the sweeper's `DELETE WHERE expires_at < ?` scan.
CREATE INDEX IF NOT EXISTS idx_oidc_sessions_expires ON oidc_sessions(expires_at);
