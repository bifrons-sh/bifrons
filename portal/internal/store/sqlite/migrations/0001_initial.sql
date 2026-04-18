-- 0001_initial: baseline portal schema.
-- All timestamps stored as ISO8601 text (UTC) for human readability and to
-- side-step sqlite's loose date typing. NUMERIC types are fine — sqlite stores
-- them with type affinity rules; we rely on Go's side to format consistently.

CREATE TABLE IF NOT EXISTS schema_migrations (
    id         INTEGER PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL DEFAULT '',
    display_name  TEXT NOT NULL DEFAULT '',
    email         TEXT NOT NULL DEFAULT '',
    is_admin      INTEGER NOT NULL DEFAULT 0,
    status        TEXT NOT NULL DEFAULT 'active',
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS backends (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    type       TEXT NOT NULL,
    host       TEXT NOT NULL,
    port       INTEGER NOT NULL,
    databases  TEXT NOT NULL DEFAULT '', -- comma-separated, empty = wildcard
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(host, port)
);

CREATE TABLE IF NOT EXISTS backend_accounts (
    id         TEXT PRIMARY KEY,
    backend_id TEXT NOT NULL REFERENCES backends(id) ON DELETE CASCADE,
    role       TEXT NOT NULL,
    username   TEXT NOT NULL,
    password   TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
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
    requested_at           TEXT NOT NULL,
    approved_at            TEXT,
    expires_at             TEXT,
    revoked_at             TEXT,
    connection_ttl_seconds INTEGER NOT NULL DEFAULT 0,
    created_at             TEXT NOT NULL,
    updated_at             TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_grants_user      ON grants(user_id);
CREATE INDEX IF NOT EXISTS idx_grants_backend   ON grants(backend_id);
CREATE INDEX IF NOT EXISTS idx_grants_status    ON grants(status);
CREATE INDEX IF NOT EXISTS idx_grants_created   ON grants(created_at);

-- Audit uses AUTOINCREMENT so id is monotonic — we need this to implement a
-- cheap "keep last N rows" cap via `DELETE WHERE id <= max_id - N`.
CREATE TABLE IF NOT EXISTS audit (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp      TEXT NOT NULL,
    grant_id       TEXT NOT NULL DEFAULT '',
    username       TEXT NOT NULL DEFAULT '',
    proxy_type     TEXT NOT NULL DEFAULT '',
    backend_server TEXT NOT NULL DEFAULT '',
    database       TEXT NOT NULL DEFAULT '',
    query          TEXT NOT NULL DEFAULT '',
    truncated      INTEGER NOT NULL DEFAULT 0,
    source_ip      TEXT NOT NULL DEFAULT '',
    duration_ms    INTEGER NOT NULL DEFAULT 0,
    trace_id       TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_grant     ON audit(grant_id);
CREATE INDEX IF NOT EXISTS idx_audit_username  ON audit(username);
