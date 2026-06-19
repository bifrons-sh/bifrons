-- 0004_provisioning_workers: worker-liveness heartbeat (PostgreSQL).
--
-- ONE row per worker PROCESS (keyed by worker_id). The row carries a
-- per-backend-instance health map so operators can tell, from a single read,
-- both that a worker is alive (even when idle, between outbox claims) AND
-- which backend instances it currently reaches. NOT one row per techno and
-- NOT one row per instance — the instance dimension lives inside the JSON
-- health array, not in the table's grain.
--
-- Least-privilege worker DB role (DOCUMENTATION ONLY — this migration does NOT
-- create any role; provision it out-of-band per deployment). Extending the
-- note from 0003: the worker now also writes its own heartbeat, so on top of
-- the outbox grants it needs INSERT + UPDATE here:
--   GRANT SELECT, UPDATE         ON provision_intents      TO portal_worker;
--   GRANT SELECT                 ON backends, grants       TO portal_worker;
--   GRANT INSERT, UPDATE         ON provisioning_workers   TO portal_worker;
--   -- still NO access to backend_accounts, oidc_sessions, audit.
-- The worker upserts its own row (INSERT on first beat, UPDATE thereafter);
-- DELETE of stale rows is the portal's job (PruneStaleWorkers), so the worker
-- role does not need DELETE here.

CREATE TABLE IF NOT EXISTS provisioning_workers (
    worker_id    TEXT PRIMARY KEY,
    -- JSON array of backend_ids this worker serves. '[]' means "all backends"
    -- (no whitelist configured) — mirrors ClaimPendingIntents' empty-whitelist
    -- semantics so the two agree on what an unfiltered worker covers.
    instances    TEXT NOT NULL DEFAULT '[]',
    -- JSON array of per-instance health objects ({backend_id, ok, last_ok_at,
    -- error_class}). Not split into its own table: the map is small, written
    -- atomically with the heartbeat, and only ever read whole.
    health       TEXT NOT NULL DEFAULT '[]',
    version      TEXT NOT NULL DEFAULT '',
    -- started_at is set once on first insert and preserved across heartbeats so
    -- operators can read process uptime; last_seen_at advances every beat and
    -- drives the staleness scan below.
    started_at   TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL
);

-- Stale-worker scans (PruneStaleWorkers) filter on last_seen_at < cutoff.
CREATE INDEX IF NOT EXISTS idx_provisioning_workers_last_seen
    ON provisioning_workers(last_seen_at);
