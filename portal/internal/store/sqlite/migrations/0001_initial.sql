-- 0001_initial: baseline portal schema.
-- Pre-deployment squash: every column / table / index the portal needs in
-- one file. All timestamps are ISO8601 text (UTC) — sqlite's loose date
-- typing is awkward, so we let Go format consistently on both sides.

CREATE TABLE IF NOT EXISTS schema_migrations (
    id         INTEGER PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id              TEXT PRIMARY KEY,
    username        TEXT NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL DEFAULT '',
    display_name    TEXT NOT NULL DEFAULT '',
    email           TEXT NOT NULL DEFAULT '',
    -- external_id binds this portal user to an IdP subject (OIDC `sub`).
    -- NULL for users minted via admin API; partial UNIQUE index keeps
    -- multiple non-IdP users from claiming the empty string.
    external_id     TEXT,
    -- validator_user_id is the portal id of this user's validator. Populated
    -- by the entra-sync script (or any other org-hierarchy source) and
    -- read at grant-creation time to stamp ValidatorSubject on the grant.
    -- Nullable: top-of-hierarchy users and out-of-band admins have no validator.
    validator_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    is_operator        INTEGER NOT NULL DEFAULT 0,
    status          TEXT NOT NULL DEFAULT 'active',
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_external_id
    ON users(external_id) WHERE external_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_users_validator ON users(validator_user_id);

-- Groups populated by the sync script. slug is a stable human-readable id
-- (e.g. "dba-team") and the source-of-truth for policy lookups; external_id
-- carries the upstream system's id (Entra group object-id today) so the
-- syncer can reconcile without duplicating.
CREATE TABLE IF NOT EXISTS groups (
    id           TEXT PRIMARY KEY,
    slug         TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL DEFAULT '',
    external_id  TEXT,
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_groups_external_id
    ON groups(external_id) WHERE external_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS group_members (
    group_id  TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    user_id   TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    joined_at TEXT NOT NULL,
    PRIMARY KEY (group_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_group_members_user ON group_members(user_id);

CREATE TABLE IF NOT EXISTS backends (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    type       TEXT NOT NULL,
    host       TEXT NOT NULL,
    port       INTEGER NOT NULL,
    databases  TEXT NOT NULL DEFAULT '', -- comma-separated; empty = wildcard
    -- See specs/phase-7-validation-ui.md §7.8.1 for the three modes.
    approval_mode TEXT NOT NULL DEFAULT 'dual_strict'
        CHECK (approval_mode IN ('dual_strict', 'dual_or', 'validator_only')),
    -- t2_group_slug names the T2-eligible group for this backend
    -- (populated by entra-sync). Per-backend, not global — §7.8.1.
    t2_group_slug TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(host, port)
);

CREATE TABLE IF NOT EXISTS backend_accounts (
    id         TEXT PRIMARY KEY,
    backend_id TEXT NOT NULL REFERENCES backends(id) ON DELETE CASCADE,
    role       TEXT NOT NULL,
    username   TEXT NOT NULL,
    password   TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(backend_id, role)
);

-- Grants: the dual-gate + tri-phase lifecycle columns land here from day 1.
CREATE TABLE IF NOT EXISTS grants (
    id                     TEXT PRIMARY KEY,
    user_id                TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    backend_id             TEXT NOT NULL REFERENCES backends(id) ON DELETE CASCADE,
    database               TEXT NOT NULL DEFAULT '',
    role                   TEXT NOT NULL,
    status                 TEXT NOT NULL,
    reason                 TEXT NOT NULL DEFAULT '',
    portal_password        TEXT NOT NULL DEFAULT '',
    t2_approved_by         TEXT NOT NULL DEFAULT '',
    -- Dual-gate T1 half.
    -- T1/T2 columns (specs/phase-7-validation-ui.md §7.8.1).
    t1_subject               TEXT NOT NULL DEFAULT '',
    t1_approved_by           TEXT NOT NULL DEFAULT '',
    t1_approved_at           TEXT,
    t1_approved_on_behalf    INTEGER NOT NULL DEFAULT 0,
    t1_on_behalf_reason      TEXT NOT NULL DEFAULT '',
    -- Tri-phase deadlines.
    request_expires_at     TEXT,
    claim_expires_at       TEXT,
    requested_at           TEXT NOT NULL,
    t2_approved_at         TEXT,
    expires_at             TEXT,
    revoked_at             TEXT,
    connection_ttl_seconds INTEGER NOT NULL DEFAULT 0,
    -- Cached trio-policy verdict so /claim doesn't re-resolve groups.
    policy_mode            TEXT NOT NULL DEFAULT '',
    -- Per-grant ephemeral backend user (empty = fall back to shared account).
    ephemeral_username     TEXT NOT NULL DEFAULT '',
    ephemeral_password     TEXT NOT NULL DEFAULT '',
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

CREATE TABLE IF NOT EXISTS oidc_sessions (
    id         TEXT PRIMARY KEY,
    subject    TEXT NOT NULL DEFAULT '',
    email      TEXT NOT NULL DEFAULT '',
    name       TEXT NOT NULL DEFAULT '',
    is_operator   INTEGER NOT NULL DEFAULT 0,
    expires_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_oidc_sessions_expires ON oidc_sessions(expires_at);
