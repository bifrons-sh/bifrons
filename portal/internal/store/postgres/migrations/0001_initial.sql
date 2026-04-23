-- 0001_initial: baseline portal schema (PostgreSQL).
-- Pre-deployment squash: every column / table / index the portal needs in
-- one file. Timestamps use TIMESTAMPTZ — pgx round-trips these to time.Time
-- directly. Audit id is BIGSERIAL so `DELETE WHERE id < pivot` caps quickly.

CREATE TABLE IF NOT EXISTS schema_migrations (
    id         BIGSERIAL PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    applied_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id              TEXT PRIMARY KEY,
    username        TEXT NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL DEFAULT '',
    display_name    TEXT NOT NULL DEFAULT '',
    email           TEXT NOT NULL DEFAULT '',
    -- external_id binds this portal user to an IdP subject (OIDC `sub`).
    -- NULL for users minted via admin API; partial UNIQUE keeps multiple
    -- non-IdP users from claiming the empty string.
    external_id     TEXT,
    -- validator_user_id is the portal id of this user's validator. Populated by
    -- the entra-sync script (or any other org-hierarchy source). Null for
    -- top-of-hierarchy users + out-of-band admins.
    validator_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    is_admin        BOOLEAN NOT NULL DEFAULT FALSE,
    status          TEXT NOT NULL DEFAULT 'active',
    created_at      TIMESTAMPTZ NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_external_id
    ON users(external_id) WHERE external_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_users_validator ON users(validator_user_id);

CREATE TABLE IF NOT EXISTS groups (
    id           TEXT PRIMARY KEY,
    slug         TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL DEFAULT '',
    external_id  TEXT,
    created_at   TIMESTAMPTZ NOT NULL,
    updated_at   TIMESTAMPTZ NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_groups_external_id
    ON groups(external_id) WHERE external_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS group_members (
    group_id  TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    user_id   TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    joined_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (group_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_group_members_user ON group_members(user_id);

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
    password   TEXT NOT NULL DEFAULT '',
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
    validator_subject        TEXT NOT NULL DEFAULT '',
    validator_approved_by    TEXT NOT NULL DEFAULT '',
    validator_approved_at    TIMESTAMPTZ,
    request_expires_at     TIMESTAMPTZ,
    claim_expires_at       TIMESTAMPTZ,
    requested_at           TIMESTAMPTZ NOT NULL,
    approved_at            TIMESTAMPTZ,
    expires_at             TIMESTAMPTZ,
    revoked_at             TIMESTAMPTZ,
    connection_ttl_seconds INTEGER NOT NULL DEFAULT 0,
    policy_mode            TEXT NOT NULL DEFAULT '',
    ephemeral_username     TEXT NOT NULL DEFAULT '',
    ephemeral_password     TEXT NOT NULL DEFAULT '',
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

CREATE TABLE IF NOT EXISTS oidc_sessions (
    id         TEXT PRIMARY KEY,
    subject    TEXT NOT NULL DEFAULT '',
    email      TEXT NOT NULL DEFAULT '',
    name       TEXT NOT NULL DEFAULT '',
    is_admin   BOOLEAN NOT NULL DEFAULT FALSE,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_oidc_sessions_expires ON oidc_sessions(expires_at);
