-- 0001_initial: baseline portal schema (PostgreSQL).
-- Timestamps use TIMESTAMPTZ — pgx round-trips these to time.Time directly.
-- Audit id is BIGSERIAL so it stays monotonic and we can do cheap "keep last N"
-- via DELETE WHERE id < pivot.

CREATE TABLE IF NOT EXISTS schema_migrations (
    id         BIGSERIAL PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    applied_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL DEFAULT '',
    display_name  TEXT NOT NULL DEFAULT '',
    email         TEXT NOT NULL DEFAULT '',
    is_admin      BOOLEAN NOT NULL DEFAULT FALSE,
    status        TEXT NOT NULL DEFAULT 'active',
    created_at    TIMESTAMPTZ NOT NULL,
    updated_at    TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS backends (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    type       TEXT NOT NULL,
    host       TEXT NOT NULL,
    port       INTEGER NOT NULL,
    databases  TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE(host, port)
);

CREATE TABLE IF NOT EXISTS backend_accounts (
    id         TEXT PRIMARY KEY,
    backend_id TEXT NOT NULL REFERENCES backends(id) ON DELETE CASCADE,
    role       TEXT NOT NULL,
    username   TEXT NOT NULL,
    password   TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE(backend_id, role)
);

CREATE TABLE IF NOT EXISTS grants (
    id                     TEXT PRIMARY KEY,
    user_id                TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    backend_id             TEXT NOT NULL REFERENCES backends(id) ON DELETE CASCADE,
    database               TEXT NOT NULL DEFAULT '',
    role                   TEXT NOT NULL,
    status                 TEXT NOT NULL,
    reason                 TEXT NOT NULL DEFAULT '',
    portal_password        TEXT NOT NULL DEFAULT '',
    approved_by            TEXT NOT NULL DEFAULT '',
    requested_at           TIMESTAMPTZ NOT NULL,
    approved_at            TIMESTAMPTZ,
    expires_at             TIMESTAMPTZ,
    revoked_at             TIMESTAMPTZ,
    connection_ttl_seconds INTEGER NOT NULL DEFAULT 0,
    created_at             TIMESTAMPTZ NOT NULL,
    updated_at             TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_grants_user    ON grants(user_id);
CREATE INDEX IF NOT EXISTS idx_grants_backend ON grants(backend_id);
CREATE INDEX IF NOT EXISTS idx_grants_status  ON grants(status);
CREATE INDEX IF NOT EXISTS idx_grants_created ON grants(created_at);

CREATE TABLE IF NOT EXISTS audit (
    id             BIGSERIAL PRIMARY KEY,
    timestamp      TIMESTAMPTZ NOT NULL,
    grant_id       TEXT NOT NULL DEFAULT '',
    username       TEXT NOT NULL DEFAULT '',
    proxy_type     TEXT NOT NULL DEFAULT '',
    backend_server TEXT NOT NULL DEFAULT '',
    database       TEXT NOT NULL DEFAULT '',
    query          TEXT NOT NULL DEFAULT '',
    truncated      BOOLEAN NOT NULL DEFAULT FALSE,
    source_ip      TEXT NOT NULL DEFAULT '',
    duration_ms    BIGINT NOT NULL DEFAULT 0,
    trace_id       TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_grant     ON audit(grant_id);
CREATE INDEX IF NOT EXISTS idx_audit_username  ON audit(username);
