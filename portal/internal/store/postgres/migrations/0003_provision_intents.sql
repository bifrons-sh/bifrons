-- 0003_provision_intents: the provisioning outbox (PostgreSQL).
--
-- A durable table the portal (producer) writes and a separate worker
-- (consumer) coordinates through. The portal emits one row per
-- provision/revoke directive; workers claim rows under a lease, run backend
-- DDL, and report the result (or an error) back here. See spec §8.4.
--
-- Least-privilege worker DB role (DOCUMENTATION ONLY — this migration does NOT
-- create any role; provision it out-of-band per deployment):
--   GRANT SELECT, UPDATE ON provision_intents TO portal_worker;
--   GRANT SELECT             ON backends, grants TO portal_worker;
--   -- NO access to backend_accounts, oidc_sessions, audit.
-- The worker never INSERTs intents (the portal does) and never reads the
-- shared backend credentials or session/audit tables — it only needs to claim
-- rows, run DDL with its own master creds, and write results back.

CREATE TABLE IF NOT EXISTS provision_intents (
    id                         TEXT PRIMARY KEY,
    -- FK to grants so a deleted grant cascades its outbox rows away; the worker
    -- reading a row can trust the grant still existed at emit time.
    grant_id                   TEXT NOT NULL REFERENCES grants(id) ON DELETE CASCADE,
    kind                       TEXT NOT NULL CHECK (kind IN ('provision', 'revoke')),
    -- Grant context frozen at emit time so a concurrent grant edit doesn't
    -- shift the ground under an in-flight worker.
    backend_id                 TEXT NOT NULL,
    database                   TEXT NOT NULL DEFAULT '',
    role                       TEXT NOT NULL CHECK (role IN ('ro', 'app', 'dba')),
    requested_duration_seconds INTEGER NOT NULL DEFAULT 0,
    -- For revoke intents: the user to drop. Empty on provision (worker derives
    -- the name deterministically from the intent id).
    target_username            TEXT NOT NULL DEFAULT '',
    -- Lifecycle.
    status                     TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'in_flight', 'done', 'failed')),
    worker_id                  TEXT NOT NULL DEFAULT '',
    lease_expires_at           TIMESTAMPTZ,
    -- Result (provision only). SecretBox-encrypted at rest by the portal's
    -- store.Encrypting decorator — protects against a DB backup leak. Both the
    -- username and password are encrypted (the username is sensitive infra
    -- detail). See spec §8.4.1 for the threat model.
    result_username            TEXT NOT NULL DEFAULT '',
    result_password            TEXT NOT NULL DEFAULT '',
    -- Error bookkeeping; error_class is a closed enum (spec §8.4.2),
    -- error_detail a sanitised single-line summary safe for the requester.
    error_class                TEXT NOT NULL DEFAULT '',
    error_detail               TEXT NOT NULL DEFAULT '',
    retry_count                INTEGER NOT NULL DEFAULT 0,
    created_at                 TIMESTAMPTZ NOT NULL,
    updated_at                 TIMESTAMPTZ NOT NULL,
    completed_at               TIMESTAMPTZ
);

-- Hot path: workers scan pending intents in age order.
CREATE INDEX IF NOT EXISTS idx_provision_intents_pending
    ON provision_intents(created_at) WHERE status = 'pending';

-- Catch-up path: workers reclaim stale in_flight intents by lease deadline.
CREATE INDEX IF NOT EXISTS idx_provision_intents_stale_lease
    ON provision_intents(lease_expires_at) WHERE status = 'in_flight';

-- Latest-intent-per-grant lookups (GetLatestIntentForGrant) filter on
-- (grant_id, kind) and order by created_at.
CREATE INDEX IF NOT EXISTS idx_provision_intents_grant
    ON provision_intents(grant_id, kind, created_at);
