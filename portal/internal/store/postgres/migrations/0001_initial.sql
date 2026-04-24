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
    is_operator        BOOLEAN NOT NULL DEFAULT FALSE,
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
    -- approval_mode picks the workflow for grants on this backend
    -- (specs/phase-7-validation-ui.md §7.8.1):
    --   dual_strict    — T1 then T2 (default; preserves four-eyes)
    --   dual_or        — first eligible from {T1 ∪ T2} wins, single approval
    --   validator_only — T1 only; T2 may act as fallback for absent T1
    -- CHECK keeps the column self-validating without a separate enum type.
    approval_mode TEXT NOT NULL DEFAULT 'dual_strict'
        CHECK (approval_mode IN ('dual_strict', 'dual_or', 'validator_only')),
    -- t2_group_slug names the portal-internal group (populated by
    -- entra-sync) whose members are T2-eligible for THIS backend — they
    -- clear gate2 and receive admin-gate notifications. Empty = no T2
    -- group configured; gate2 only reachable via static-bearer.
    -- Per-backend rather than global because different backends typically
    -- have different admin tiers (DBA team for prod, platform team for
    -- staging, etc.). §7.8.1.
    t2_group_slug TEXT NOT NULL DEFAULT '',
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
    t2_approved_by         TEXT NOT NULL DEFAULT '',
    -- T1/T2 columns (specs/phase-7-validation-ui.md §7.8.1):
    -- t1_subject is the eligible T1 validator captured at create time
    -- (bridge field; replaced by grant_validators table in §7.3 final).
    t1_subject               TEXT NOT NULL DEFAULT '',
    t1_approved_by           TEXT NOT NULL DEFAULT '',
    t1_approved_at           TIMESTAMPTZ,
    -- t1_approved_on_behalf marks gate1 cleared by a T2 stepping in for an
    -- absent T1 (§7.8.7). Lets the same actor subsequently clear gate2 in
    -- dual_strict mode without tripping the four-eyes guard, since the
    -- exception was justified at gate1.
    t1_approved_on_behalf    BOOLEAN NOT NULL DEFAULT FALSE,
    t1_on_behalf_reason      TEXT NOT NULL DEFAULT '',
    request_expires_at     TIMESTAMPTZ,
    claim_expires_at       TIMESTAMPTZ,
    requested_at           TIMESTAMPTZ NOT NULL,
    t2_approved_at         TIMESTAMPTZ,
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
    is_operator   BOOLEAN NOT NULL DEFAULT FALSE,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_oidc_sessions_expires ON oidc_sessions(expires_at);
