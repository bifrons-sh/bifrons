# Phase 8 — Provisioning worker split

**Status:** ⬜ draft — TBD. Deferred from phase-7. No implementation
blockers on v1.

Splits DDL authority off the portal process. A dedicated **worker**
service holds the master credentials for each managed instance and is
the only component that runs `CREATE USER` / `DROP USER` / `GRANT` /
`REVOKE` against the backend. The portal owns workflow, authz, audit,
and never touches master creds.

Supersedes `phase-7-validation-ui.md` §6.

## 8.1 Context

Today the portal's `ephemeral` package runs as an in-process library:

- `portal/internal/ephemeral/registry.go` → `Manager.Provision()`.
- `ephemeral/postgres.go` / `mysql.go` / `mongo.go` implement protocol
  DDL using credentials resolved from `backend_accounts(role=dba)`.
- Same process that handles HTTP, serves the SPA, talks to Entra,
  also holds root-equivalent DB credentials.

That's fine for the PoC. It's wrong for production: a portal-CVE
yielding code execution gets the attacker DROP USER authority across
every managed instance. The split is a security hardening — no
functional change from the caller's POV.

## 8.2 Invariants (non-negotiable)

- **Portal process never loads master creds into memory.** At any
  time, `ps auxE` on the portal host must show no resolvable master
  secret in the portal's env / heap. Secrets live exclusively in
  the worker's address space.
- **Worker has no HTTP surface toward users / browsers / proxies.**
  Only the portal emits intents to it; only via the shared postgres
  outbox.
- **Every DDL action is attributable to a grant.** Worker never
  runs unattached DDL. Every CREATE/DROP originates from a portal
  intent row with a grant id + requester subject.
- **Portal crash between intent emission and result doesn't strand
  privileges.** Intent row persists; worker picks it up on next
  wakeup. Either the user was created and the sweeper finds it, or
  the intent is replayable. Never "created but forgotten".
- **Worker is horizontally replaceable.** Kill a worker, start
  another, intents resume via the same outbox table + lease recovery.
  No per-worker state beyond the master creds it's authorised for.

## 8.3 Architecture

```
 ┌──────────────┐                          ┌──────────────┐     DDL       ┌─────────┐
 │  Portal      │                          │  Worker      │ ────────────► │ Backend │
 │              │                          │              │   CREATE USER │ (mysql/ │
 │  - workflow  │                          │  - master    │   GRANT …     │  pg/    │
 │  - authz     │                          │    creds     │               │  mongo) │
 │  - audit     │                          │  - protocol  │               └─────────┘
 │  - HTTP API  │                          │    provisioner│
 └──────┬───────┘                          └──────┬───────┘
        │                                         │
        │  INSERT intent +          LISTEN / read │
        │  NOTIFY provision_intent                │
        │         ┌───────────────────────────────┤
        │         │                               │
        ▼         ▼                               │
     ┌────────────────────────────┐               │
     │   postgres (portal store)  │               │
     │                            │               │
     │   table: provision_intents │◄──────────────┘
     │                            │  UPDATE result
     └────────────────────────────┘
```

**One transport: the portal's existing store acts as the
outbox.** No broker, no message bus, no separate pub/sub. Workers and
portal share the same database; everything they need to coordinate
lives in one table.

**Store-type agnostic at the semantic level**: the outbox pattern +
lease + idempotency are pure SQL — they work identically on sqlite
and postgres. The only difference is the fast-path trigger: postgres
has `LISTEN / NOTIFY` for sub-ms wakeup, sqlite only has the
catch-up poll. Same correctness, same durability, same replay
behaviour; postgres is just faster at the "idle → wake" transition.

→ sqlite deployments are functionally valid production for low-
volume portals (where the catch-up interval's latency isn't
user-visible). Postgres is the recommended default because the
LISTEN/NOTIFY trigger gets you sub-ms wakeups basically for free.

**Coordination primitives**:
- **Durable queue**: the `provision_intents` table. Every intent is
  a row; every row transitions through `pending → in_flight → done
  | failed`.
- **Fast trigger**: postgres `NOTIFY provision_intent` on insert.
  Worker `LISTEN`s and wakes within a few ms of intent emission.
- **Catch-up loop**: worker polls the table every N seconds
  (e.g. 30s) for rows in `pending` OR rows in `in_flight` with a
  stale lease. Safety net for missed NOTIFYs (connection blips,
  network partitions, worker restart races) — the loop guarantees
  eventual pick-up even if every NOTIFY is dropped.

**Why both**: NOTIFY alone is not durable (delivered only to
currently-connected LISTENers); polling alone is too slow (30s
latency on `/claim`). Together: fast path when things work,
self-healing when they don't.

**Worker responsibilities**:
- `LISTEN provision_intent` on startup; reconnect with exponential
  backoff on connection loss.
- On wakeup (NOTIFY received OR catch-up tick OR startup): scan
  `provision_intents` for eligible rows, claim with
  `UPDATE … WHERE status='pending' RETURNING …` inside a `FOR UPDATE
  SKIP LOCKED` cursor, set `status='in_flight'`, `worker_id=<self>`,
  `updated_at=now()`.
- Load master creds for the target instance (via secret-ref:
  `aws-sm://`, `vault://`, `env://`, `file://`).
- Open a short-lived privileged connection to the backend; run
  CREATE USER + GRANT for the role-specific defaults (ephemeral-only,
  phase-7 §7).
- Update the row with `status='done'`, `result_username`,
  `result_password` (SecretBox-encrypted by the worker before
  insert), `completed_at=now()`.
- On failure: `status='failed'`, populate `error_class` +
  `error_detail`; transient errors trigger bounded internal retry
  before marking failed.

**Portal responsibilities**:
- At `/claim`: INSERT intent row (same tx as the grant status flip
  from APPROVED→CLAIMED), issue NOTIFY.
- Wait for result: LISTEN on a reply channel + time-bounded poll of
  the same row; return creds to caller when `status='done'`.
- At `/revoke` / sweeper-expire: INSERT revoke intent; don't block
  the caller, revocation is async.
- Has zero DB-privilege code.

**Worker does NOT**:
- Terminate client connections (proxy's job).
- Serve HTTP to users or proxies.
- Authenticate or authorise human callers (portal's job).
- Talk to Entra, OIDC, or the operator SPA.
- Write to `grants` directly — only to `provision_intents`. Portal
  reads the intent result and propagates to `grants.ephemeral_*`.
  This keeps worker's DB role scoped to one table.

## 8.4 Schema

```sql
CREATE TABLE provision_intents (
    id                 TEXT PRIMARY KEY,   -- idempotency key (portal-generated UUID/ULID)
    grant_id           TEXT NOT NULL REFERENCES grants(id),
    kind               TEXT NOT NULL CHECK (kind IN ('provision', 'revoke')),
    -- Context the worker needs to run DDL. Pulled from the grant
    -- at intent emit time, frozen here so a concurrent grant edit
    -- doesn't shift the ground under the worker.
    instance_id        TEXT NOT NULL,
    database_id        TEXT NOT NULL,
    role               TEXT NOT NULL CHECK (role IN ('ro', 'app', 'dba')),
    requested_duration_seconds INTEGER NOT NULL DEFAULT 0,
    -- For revoke intents: the ephemeral username to drop. Empty
    -- string on provision intents (worker generates the name).
    target_username    TEXT NOT NULL DEFAULT '',
    -- Lifecycle.
    status             TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'in_flight', 'done', 'failed')),
    worker_id          TEXT NOT NULL DEFAULT '',
    lease_expires_at   TIMESTAMPTZ,
    -- Result (provision only). SecretBox-encrypted by the worker.
    result_username    TEXT NOT NULL DEFAULT '',
    result_password    TEXT NOT NULL DEFAULT '',
    -- Error bookkeeping.
    error_class        TEXT NOT NULL DEFAULT '',
    error_detail       TEXT NOT NULL DEFAULT '',
    retry_count        INTEGER NOT NULL DEFAULT 0,
    -- Timestamps.
    created_at         TIMESTAMPTZ NOT NULL,
    updated_at         TIMESTAMPTZ NOT NULL,
    completed_at       TIMESTAMPTZ
);

-- Hot path: workers scan for pending intents in age order.
CREATE INDEX idx_provision_intents_pending
    ON provision_intents(created_at) WHERE status = 'pending';

-- Catch-up path: workers reclaim stale in_flight intents.
CREATE INDEX idx_provision_intents_stale_lease
    ON provision_intents(lease_expires_at) WHERE status = 'in_flight';
```

**Lease discipline**: worker sets `lease_expires_at = now + 60s` on
claim, heartbeats (`UPDATE … SET lease_expires_at = now + 60s`) while
working. DDL on any sane backend completes in <1s — 60s is slack for
network blips. Another worker seeing `status='in_flight' AND
lease_expires_at < now` takes over after a jittered delay.

**Idempotency**: the `id` is the portal-generated UUID/ULID used for
the whole intent lifetime. Portal retries on `/claim` reuse the same
intent id, so re-emitting is a no-op (`INSERT ... ON CONFLICT DO
NOTHING`). Workers running DDL can use
`CREATE USER IF NOT EXISTS` (MySQL 8+) or a DO-block catching
"already exists" SQLSTATE (Postgres) to make re-execution safe.

## 8.5 Notification + catch-up timing

```
t=0     Portal INSERT intent (status='pending')
        Portal NOTIFY provision_intent '<intent_id>'
t=0+ε   Worker receives NOTIFY, wakes from idle LISTEN
t=0+2ε  Worker claims intent via UPDATE … RETURNING, status='in_flight'
t=0+30ms Worker finishes DDL, writes result, status='done'
t=0+40ms Worker NOTIFY provision_result '<intent_id>'
t=0+45ms Portal wakes, reads intent result, returns creds to caller

─── in the sad path, NOTIFY never arrives ──────────────────────

t=0     Portal INSERT + NOTIFY (NOTIFY lost — connection blip)
t=30s   Worker catch-up tick: scans pending rows, claims this one
t=30s+… Worker proceeds as above
```

**Catch-up interval**: 30s is a reasonable default. Trade-off:
shorter = more DB queries idle-time; longer = worse p99 latency on
the sad path. Configurable, default 30s, floor 5s (below that the
polling load dominates).

**Stale-lease timeout**: 60s. A lease that's 60s+ past expiry gets
reclaimed — covers worker crash / OOM / host restart. Workers
heartbeat their lease every 30s while working, so healthy work
never hits this.

## 8.6 Failure semantics

### Portal crash after emitting intent

- Intent row persists. Worker picks it up on next NOTIFY or catch-up
  tick.
- Portal recovers, retries `/claim` (or user retries). Portal looks
  up the intent by `grant_id` + `kind` + `status IN ('in_flight',
  'done')`, waits for `done`, returns the result.
- Idempotent: intent id is derived from grant_id + kind, so retry
  doesn't create a second intent.

### Worker crash mid-provision

- `status='in_flight'` with stale `lease_expires_at`. Another worker
  takes over via the stale-lease index.
- Re-execution safe per the idempotency discipline above.
- If only one worker exists and it's hard-down: portal's `/claim`
  hits its own timeout (say, 5s) and returns 504. User retries when
  worker is back.

### DDL fails (transient — network / backend timeout)

- Worker increments `retry_count`, leaves `status='in_flight'` with
  extended lease, backs off (e.g. exponential with jitter up to
  some cap). After N attempts, writes `status='failed'` with
  `error_class='transient_exhausted'`.

### DDL fails (terminal — permission / syntax / schema)

- Worker immediately writes `status='failed'` with the error class.
  No retry.
- Portal on `/claim` returns 422 (preconditions not met — e.g.
  backend's master creds got rotated and we haven't caught up) with
  the error class surfaced to the operator.
- Admin SPA shows failed intents with a "retry" button — resets
  `status='pending'`, zeroes `retry_count`, re-triggers NOTIFY.

### Postgres unreachable

- Portal `/claim` 503s; grant stays APPROVED.
- Worker backs off and reconnects; LISTEN resumes, catch-up picks
  up any pending work.
- No user-visible state corruption — the only durable state is in
  postgres, the thing everyone's waiting on.

### Orphan DB users (worker created, portal forgot)

- Existing sweeper (`portal/internal/ephemeral/sweep.go`) already
  scans `grants` for terminal-state rows with non-empty
  `ephemeral_username`, emits revoke intent. Works unchanged under
  the worker split.

### Concurrent provision + revoke for same grant

- Race: portal approves, claim pending, operator revokes before
  `/claim` completes. Two intents in the table; revoke must win.
- Worker orders by (kind='revoke' DESC, created_at ASC) when
  scanning — revoke always preempts provision for the same grant.
- If provision had already written `status='in_flight'`, revoke
  waits for it to finish (worker processes revoke next), then DROPs
  the user. Net effect: user briefly exists, then gone. Tradeoff
  is tolerable; alternative would be cross-intent cancellation,
  which complicates the worker.

## 8.7 Revocation path

Same table. Portal on `/revoke` (or sweeper on expire) inserts:

```sql
INSERT INTO provision_intents (id, grant_id, kind, target_username, …)
VALUES ($id, $gid, 'revoke', $grant.ephemeral_username, …);
NOTIFY provision_intent '<intent_id>';
```

Worker processes identically — same LISTEN, same scan, same lease —
except the DDL is `DROP USER IF EXISTS` instead of CREATE + GRANT.

Idempotency: dropping a non-existent user is a no-op per protocol.
Re-running after crash is safe.

## 8.8 Observability

**Portal-side metrics**:
- `portal_provision_intents_emitted_total{kind}`
- `portal_provision_intents_pending` (gauge, queue depth)
- `portal_provision_intent_latency_seconds` (emit → result
  received, histogram)
- `portal_provision_claim_timeout_total` (portal gave up waiting
  for worker)

**Worker-side metrics**:
- `worker_provision_intents_processed_total{kind, instance_id, result}`
- `worker_provision_ddl_latency_seconds{instance_id, backend_type}`
- `worker_master_connection_errors_total{instance_id}`
- `worker_intent_retries_total{error_class}`
- `worker_stale_leases_reclaimed_total`
- `worker_notify_missed_total` (intent found via catch-up, not
  NOTIFY — indicator of connection health)

Alerts:
- `portal_provision_intents_pending > 10 for 5m` → queue backlog;
  worker stuck?
- `worker_notify_missed_total rate > 0.1/s` → LISTEN connection
  issues.
- `portal_provision_claim_timeout_total > 0` → user-visible
  impact; page oncall.

**Logs**: structured, correlated by `intent_id` on both sides.

**Audit stream**: every successful provision + revoke appends to the
existing audit table, attributed to the portal's requester subject
(not the worker — the worker is anonymous infra, the authorisation
decision lives with the portal).

## 8.9 Phasing

**Phase 8A — the production milestone**: postgres outbox + worker
binary.

- Schema: add `provision_intents` table (amend `0001_initial.sql`
  pre-deploy; sqlite mirror can stay simpler — polling-only,
  no NOTIFY, accepted as local-dev degraded mode).
- `portal/internal/provisioning/` package:
  - `intent.go` — `Intent` struct + `INSERT` helper.
  - `notify.go` — NOTIFY wrapper.
  - `client.go` — portal-side emit + wait-for-result.
- `cmd/provisioner-worker/main.go` — new binary:
  - LISTEN loop + catch-up ticker.
  - Claim-scan-process state machine.
  - Loads master creds via secret-refs (`aws-sm://`, `vault://`,
    `env://`, `file://`).
  - Imports `portal/internal/ephemeral/*` — the existing DDL code
    moves here verbatim.
  - Distroless non-root, own Dockerfile.
- Portal loses its direct dep on `portal/internal/ephemeral/*`.
  The handler's `/claim` path emits an intent instead of calling
  `ephemeral.Manager.Provision()`.
- Dev convenience: a `make dev-worker` target that runs the worker
  against the same postgres the portal is using — one-command
  standup.

Duration: ~4-5 days.

**Phase 8B — sqlite compatibility**: the outbox pattern is
store-agnostic; the only piece that's postgres-specific is the
`LISTEN/NOTIFY` fast-path wakeup. Sqlite falls back to catch-up-poll
as the only wakeup mechanism — same table, same lease, same
idempotency, just slower to start work on an idle queue (bounded by
the poll interval). Worker constructor picks wakeup mode based on
the store URL scheme.

This is a natural property of the design, not a degraded-mode
special case. Small / single-tenant deployments can legitimately
run sqlite in production if the poll-interval latency is acceptable
(most portals handle <1 grant/min; a 30s wakeup tail isn't user-
visible). Postgres remains recommended for sub-ms `/claim` p99.

Duration: ~0.5 day (mostly the store-type detection + two
different tickers).

**Phase 8C — hardening**:
- Multi-region / multi-trust-boundary worker topology.
- Cross-portal shared workers (one worker servicing N portals via
  the same outbox schema). Interesting for multi-tenant SaaS; not
  on the current roadmap.
- Alerts + runbooks for worker outage.

## 8.10 Open questions

- **Multi-instance master routing**: if one worker holds creds for
  `prod-pg` and another for `staging-mysql`, the shared
  `provision_intents` table needs routing. Options:
  - **Per-worker instance whitelist**: each worker filters its scan
    `WHERE instance_id IN (…)`. Rows for other instances are
    ignored, eventually picked up by the right worker or reclaimed
    on stale lease. Simplest; slight risk of unclaimed rows if a
    worker is misconfigured.
  - **Per-instance NOTIFY channel**: portal NOTIFYs
    `provision_intent_<instance_id>`. Workers LISTEN only on their
    instances. Tidier but scales poorly past ~100 instances (LISTEN
    channels are cheap but not free).
  - **Leaderless leasing + explicit routing table**: a
    `worker_instance_assignments(worker_id, instance_id)` table;
    workers only claim rows for assigned instances. Adds state.
  - Recommend **per-worker whitelist** for v1 — explicit config,
    minimal new machinery.
- **Master creds rotation without worker restart**: worker
  periodically re-resolves its secret-refs (configurable TTL,
  ~1h). Avoids rolling restart on every rotation.
- **Worker DB role**: read/write on `provision_intents` only.
  Read-only on `instances`, `databases`, `grants` (for context).
  No access to `users`, `audit`, `oidc_sessions`, `backend_accounts`
  (if any remain post §7), etc. Scoped DB role minimises
  worker-compromise blast radius.
- **TLS to postgres**: worker connects over TLS like the portal.
  Same `PORTAL_STORE_URL`-style ref, same SecretBox key for result
  encryption so portal can decrypt.
- **Deployment topology**: worker per trust boundary ("which
  instances share the same master-cred scope"). Starts as one
  worker per portal; splits only when operators need to isolate
  masters across cred boundaries.

## 8.11 Design-property notes

**Store-portable semantics**: the outbox + lease + idempotency is
SQL-standard enough that sqlite and postgres execute it identically.
The portal can change store backends (or run different stores in
different environments) without the worker caring beyond "how do I
get a fast wakeup on this store".

**Poll interval as the tuning knob**: on any store, the sole tuning
parameter for queue-wakeup latency is the catch-up poll interval.
Postgres LISTEN/NOTIFY reduces it to "sub-ms in the happy path,
poll-interval in the sad path". Sqlite has only the poll path, so
wakeup latency ≈ poll interval. Operators pick based on their
tolerance.

**Reconsider alternative transports only if**:
- Workload exceeds ~100 intents/sec sustained (postgres query load
  from the outbox becomes meaningful).
- Multi-portal SaaS where many portals feed one worker pool and
  portal-isolation matters more than shared-DB convenience.
- Cross-region provisioning where the shared DB isn't practical.

Until then, postgres outbox is the simplest thing that works.

## 8.12 Out of scope

- Alternative transports (Redis, RabbitMQ, NATS, Kafka, gRPC RPC).
  Considered and dropped — postgres outbox covers the workload
  without new infra. See 8.11 for reconsider criteria.
- Declarative user management (Terraform-style). Portal stays
  imperative: intent → DDL → done.
- Multi-region provisioning coordination.
- Worker-to-worker leader election for singleton intents (not
  needed — claim-via-UPDATE-SKIP-LOCKED gives fair distribution
  across workers).
