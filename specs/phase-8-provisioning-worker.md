# Phase 8 — Provisioning worker split

**Status:** ✅ implemented (Workstream F). The portal no longer provisions
inline: it emits intents to the `provision_intents` outbox and a dedicated
`provisioner-worker` binary runs all DDL. Worker + producer Prometheus metrics
(§8.8) are **wired** to `/metrics` sidecars on both sides. Genuinely **not-yet**:
the `aws-sm://`/`vault://` secret schemes, per-grant zero-knowledge result
encryption, multi-worker trust-boundary routing, and the
`worker_intent_retries_total` / `worker_master_connection_errors_total` counters
plus the `{instance_id}` / `{backend_type}` labels (flagged inline below).

> **As-built drift from the original draft** (corrected throughout this doc):
> the outbox columns are `backend_id` / `database` (not `instance_id` /
> `database_id`); the intent id is deterministic `ip-<16hex>` =
> `"ip-"+sha256(grant_id|kind)[:16]` (not a random UUID/ULID); `error_class`
> values are the closed enum in §8.4.2; ephemeral password is
> `base64url(seed[8:32])` = 24 bytes (the HMAC-SHA256 seed is only 32 bytes, so
> the original `seed[8:40]` was impossible); build the binary with
> `make provisioner-worker` (part of `make build`), and stand it up against the
> dev stack with **`make dev-worker`** (runs `docker compose … up -d --build
> provisioner-worker` — the dev portal's SQLite lives in a named volume, so the
> worker must run as a compose service on that volume, not a host-local binary).

Splits DDL authority off the portal process. A dedicated **worker**
service holds the master credentials for each managed instance and is
the only component that runs `CREATE USER` / `DROP USER` / `GRANT` /
`REVOKE` against the backend. The portal owns workflow, authz, audit,
and never touches master creds.

Supersedes `phase-7-validation-ui.md` §6.

## 8.0 As-built map

| Concern | Lands in |
|---|---|
| Outbox table + migration | `portal/internal/store/{postgres,sqlite}/migrations/0003_provision_intents.sql` |
| Worker-liveness table + migration | `portal/internal/store/{postgres,sqlite}/migrations/0004_provisioning_workers.sql` |
| `domain.WorkerHeartbeat` + `InstanceHealth` + `IsStale` | `portal/internal/domain/types.go` |
| Heartbeat store CRUD (Upsert / List / PruneStale) | `portal/internal/store/store.go` (+ pg/sqlite impls) |
| Worker heartbeat loop + per-instance probe | `portal/cmd/provisioner-worker/` (`-heartbeat-interval` / `-heartbeat-probe`) |
| Admin heartbeat endpoint + gauge + stale prune | `portal/internal/api/`, sweeper (`lifecycle`), `portal_provision_workers{state}` |
| `domain.Intent` + `IntentID` + status enum | `portal/internal/domain/types.go` |
| Store CRUD (Insert / ClaimPending / Heartbeat / Complete / Fail / GetIntent / GetLatest) | `portal/internal/store/store.go` (+ pg/sqlite impls) |
| Producer client (emit + wait-for-result, LISTEN/NOTIFY) | `portal/internal/provisioning/` (`intent.go`, `client.go`, `notify.go`, `metrics.go`) |
| Worker binary (claim → DDL → result) | `portal/cmd/provisioner-worker/` (`main.go`, `config.go`, `run.go`, `worker.go`, `metrics.go`) |
| Async `/claim` (200/202/422) + `/claim/status` | `portal/internal/api/grants_handler.go`, `router.go` |
| Orphan-sweep revoke emit + done-but-unclaimed reconciler | `portal/internal/ephemeral/sweep.go`, `portal/internal/lifecycle/reconciler.go` |

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
- **Worker authenticates to the outbox with a least-privilege role,
  not the portal's.** The portal connects to postgres with a role
  that holds SELECT/INSERT/UPDATE on `provision_intents` and the
  portal's own tables. The worker connects with a *separate* role
  that has SELECT/UPDATE on `provision_intents` and nothing else.
  Master DDL creds for managed backends are loaded from a secret
  store the portal's role cannot reach. A portal-RCE therefore reads
  the outbox but cannot impersonate the worker against the outbox
  (advisory locks / lease tokens) and cannot resolve master creds.
  Without this split, the trust boundary the worker is supposed to
  create is fictional.

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
  phase-7 §7). The intent's `requested_duration_seconds` is applied as a
  real DB-side expiry — Postgres `VALID UNTIL <ts>`, MySQL `PASSWORD EXPIRE
  INTERVAL <n> DAY` (coarse, day-granular) — so the account self-expires even
  if the portal/sweeper never revokes.
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

As-built (`0003_provision_intents.sql`, postgres shown; sqlite mirrors it with
`TEXT` ISO8601 timestamps and no FK):

```sql
CREATE TABLE provision_intents (
    id                         TEXT PRIMARY KEY,   -- deterministic: "ip-"+sha256(grant_id|kind)[:16]
    grant_id                   TEXT NOT NULL REFERENCES grants(id) ON DELETE CASCADE,
    kind                       TEXT NOT NULL CHECK (kind IN ('provision', 'revoke')),
    -- Routing context the worker needs to run DDL, frozen at emit time so a
    -- concurrent grant edit can't shift the ground under an in-flight worker.
    backend_id                 TEXT NOT NULL,        -- → backends.id (NOT "instance_id")
    database                   TEXT NOT NULL DEFAULT '',  -- target db name (NOT "database_id")
    role                       TEXT NOT NULL CHECK (role IN ('ro', 'app', 'dba')),
    requested_duration_seconds INTEGER NOT NULL DEFAULT 0,
    -- For revoke intents: the ephemeral username to drop. Empty on provision
    -- (worker derives the name deterministically from the intent id).
    target_username            TEXT NOT NULL DEFAULT '',
    -- Lifecycle.
    status                     TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'in_flight', 'done', 'failed')),
    worker_id                  TEXT NOT NULL DEFAULT '',
    lease_expires_at           TIMESTAMPTZ,
    -- Result (provision only). SecretBox-encrypted at rest by the portal's
    -- store.Encrypting decorator — both username and password (the username is
    -- itself sensitive infra detail). NOT zero-knowledge: the portal reads +
    -- decrypts on /claim. See §8.4.1.
    result_username            TEXT NOT NULL DEFAULT '',
    result_password            TEXT NOT NULL DEFAULT '',
    -- Error bookkeeping. error_class is a closed enum (§8.4.2); error_detail is
    -- a sanitised single-line summary safe to surface to the requester. Verbose
    -- driver output goes to the worker's structured log keyed by intent_id.
    error_class                TEXT NOT NULL DEFAULT '',
    error_detail               TEXT NOT NULL DEFAULT '',
    retry_count                INTEGER NOT NULL DEFAULT 0,
    created_at                 TIMESTAMPTZ NOT NULL,
    updated_at                 TIMESTAMPTZ NOT NULL,
    completed_at               TIMESTAMPTZ
);

-- Hot path: workers scan pending intents in age order.
CREATE INDEX idx_provision_intents_pending
    ON provision_intents(created_at) WHERE status = 'pending';

-- Catch-up path: workers reclaim stale in_flight intents by lease deadline.
CREATE INDEX idx_provision_intents_stale_lease
    ON provision_intents(lease_expires_at) WHERE status = 'in_flight';

-- Latest-intent-per-grant lookups (GetLatestIntentForGrant).
CREATE INDEX idx_provision_intents_grant
    ON provision_intents(grant_id, kind, created_at);
```

**Least-privilege worker DB role** (documented in the `0003` migration header;
the migration creates no role — provision it out-of-band per deployment, and
keep it in sync with that header):

```sql
GRANT SELECT, UPDATE ON provision_intents TO portal_worker;
GRANT SELECT           ON backends, grants TO portal_worker;
-- NO access to backend_accounts, oidc_sessions, audit.
```

The worker never INSERTs intents (the portal does) and never reads the shared
backend credentials (`backend_accounts`) or the session / audit tables — it
only claims rows, runs DDL with its **own** master creds (resolved from its
`-worker-config`, not the store), and writes results back. A portal-RCE can
read the outbox but cannot resolve master creds or impersonate the worker's
lease scope.

**Worker-liveness table** (`0004_provisioning_workers.sql`, both dialects;
heartbeat design in §8.8.1) — ONE row per worker PROCESS keyed by `worker_id`,
carrying a per-instance reachability map as JSON (not a per-techno or
per-instance table grain):

```sql
CREATE TABLE provisioning_workers (
    worker_id    TEXT PRIMARY KEY,
    instances    TEXT NOT NULL DEFAULT '[]',  -- JSON backend_ids served; [] = all
    health       TEXT NOT NULL DEFAULT '[]',  -- JSON [{backend_id, ok, last_ok_at, error_class}]
    version      TEXT NOT NULL DEFAULT '',
    started_at   TIMESTAMPTZ NOT NULL,        -- set once; uptime
    last_seen_at TIMESTAMPTZ NOT NULL         -- advances every beat; drives staleness
);
CREATE INDEX idx_provisioning_workers_last_seen ON provisioning_workers(last_seen_at);
```

The `0004` header extends the worker DB role from §8.4 / `0003`: on top of the
outbox grants the worker now also needs **`GRANT INSERT, UPDATE ON
provisioning_workers`** (upsert: INSERT first beat, UPDATE thereafter). DELETE
of stale rows is the **portal's** job (`PruneStaleWorkers`), so the worker role
does NOT get DELETE here. Still no access to `backend_accounts`,
`oidc_sessions`, or audit.

**Lease discipline**: worker sets `lease_expires_at = now + 60s` on
claim, heartbeats (`UPDATE … SET lease_expires_at = now + 60s`) while
working. DDL on any sane backend completes in <1s — 60s is slack for
network blips. Another worker seeing `status='in_flight' AND
lease_expires_at < now` takes over after a jittered delay.

**Idempotency**: the `id` is the deterministic `"ip-"+sha256(grant_id|kind)[:16]`
(`domain.IntentID`), stable for the whole intent lifetime. Portal retries on
`/claim` derive the same id, so re-emitting is a no-op (`INSERT ... ON CONFLICT
DO NOTHING`). Workers running DDL can use
`CREATE USER IF NOT EXISTS` (MySQL 8+) or a DO-block catching
"already exists" SQLSTATE (Postgres) to make re-execution safe.

**Deterministic ephemeral credentials**: both the username and the
password the worker provisions MUST be derived from the intent id, NOT
freshly randomised on each execution. Otherwise a lease takeover
(worker A killed after `CREATE USER` but before `UPDATE intent`,
worker B retries) sees `CREATE USER IF NOT EXISTS` succeed silently
on the existing row while writing a new password to the outbox — the
DB has password₁, the portal stores password₂, every subsequent
auth-remap fails. Derivation:

```
intent_secret_seed  = HMAC-SHA256(worker.key, intent.id)
ephemeral_username  = "ap_" || hex(seed[0:8])    // 16 hex chars, fits any engine
ephemeral_password  = base64url(seed[8:32])      // 24 bytes, RFC 4648 §5
```

`worker.key` is a 32-byte seed loaded once at boot from the worker's
secret backend. Same intent id → same username + password regardless
of how many workers attempted the row. Worker B then runs
`ALTER USER ... WITH PASSWORD '<deterministic>'` on every claim
(idempotent in all three engines), so even partial work from worker A
gets repaired to the canonical state.

The lease-takeover failure mode `CREATE USER IF NOT EXISTS` was
designed to mask is now actually safe — re-execution converges instead
of diverging.

## 8.4.1 Result column threat model

The schema's `result_username` / `result_password` columns are
SecretBox-encrypted with the portal's `SECRETBOX_KEY` (the same key
used elsewhere in `portal/internal/secrets`). This protects against:

- DB backup leaked / subpoenaed.
- Read-replica accessed by a non-portal operator.
- Hot-data exposure on a portal-DB compromise that doesn't also yield
  the keymat (key sits in env / secret store, not in the DB).

It does **not** protect against:

- A portal-RCE: the portal has the key and decrypts on `/claim`.
- A worker-RCE: the worker has the key (encrypts the result).
- A row dumped from inside the portal process's memory.

Zero-knowledge would require deriving the encryption key per-grant
from the requester's identity (e.g. `HKDF(grant.id, requester_pubkey)`)
so neither portal nor worker can passively read the row. That's
expensive — requires a client-side keypair per requester — and is
deferred. Phase 8 ships with shared-key encryption; document the
gap in the threat model rather than pretending the column is
worker-private.

## 8.4.2 `error_class` enum + log discipline

As-built closed enum (`worker.go` constants; the worker's `classify()` maps a
driver error onto one of these, defaulting unknown errors to
`transient_network` so the bounded retry gets a chance):

| `error_class`                 | When                                                                        | `error_detail` content                                |
|-------------------------------|-----------------------------------------------------------------------------|-------------------------------------------------------|
| `transient_network`           | dial / TCP / timeout / reset / EOF — retryable; also the unknown-error default | redacted one-liner (no host, no DDL keywords)        |
| `transient_exhausted`         | a `transient_network` op still failing after `maxTransientAttempts` (3)     | last redacted transient error                         |
| `terminal_permission`         | master creds lack the privilege (incl. `ephemeral.ErrNoDBACredential`)      | required-privilege summary, never the existing GRANTs |
| `terminal_syntax`             | DDL rejected for shape reasons (syntax / unsupported / password policy)     | one-line summary, no SQL fragment                     |
| `terminal_target_unreachable` | DNS / TLS / certificate / wrong-host — can the worker reach the backend at all? | generic error class, no host                      |
| `terminal_intent_invalid`     | intent points at a backend/role no longer resolvable, or unknown intent kind | empty                                                |

(Value strings: `transient_network`, `transient_exhausted`,
`terminal_permission`, `terminal_syntax`, `terminal_target_unreachable`,
`terminal_intent_invalid`.) The closed enum lets the UI surface a useful action
("retry later" vs. "contact admin") without parsing free text. The verbose
driver output (stack traces, SQL fragments, hostnames) goes to the worker's
structured log keyed by `intent_id`.

**Hygiene rule** (enforced by `redactDetail()` in `worker.go`): `error_detail`
is **single-line, ≤120 chars, no `\r`/`\n`, GRANT/REVOKE/CREATE/DROP/ALTER/
REASSIGN keywords stripped**, before it ever reaches the column.

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

## 8.5.1 `/claim` response shape — async semantics

The current `/claim` handler is synchronous: it provisions inline and
returns `{backend_user, backend_pass, portal_password, expires_at}` in
the same response. The phase-8 split breaks that — work now happens
on the worker, asynchronously. The handler needs a new shape.

**Decision**: return 202 + poll endpoint. Single endpoint, predictable
UX, no WebSocket pole-vault.

```
POST /api/v1/grants/{id}/claim
→ 202 Accepted
  Location: /api/v1/grants/{id}/claim/status
  Retry-After: 1
  { "intent_id": "ip-...", "state": "pending" }

GET /api/v1/grants/{id}/claim/status
→ 200 OK while pending/in_flight:
  { "intent_id": "ip-...", "state": "in_flight", "elapsed_ms": 42 }
→ 200 OK on done:
  { "intent_id": "ip-...", "state": "done",
    "backend_user": "...", "backend_pass": "...",
    "portal_password": "...", "expires_at": "..." }
→ 4xx/5xx on terminal failure:
  { "intent_id": "ip-...", "state": "failed",
    "error_class": "terminal_permission",
    "error_detail": "<sanitised>" }
```

**Short-circuit for the happy path**: the handler blocks up to
`claimShortCircuitWait = 2s` on the result before returning 202. If the result
lands within the window it returns 200 + creds directly — same shape the v1
handler did, no client churn on fast paths. `WaitForResult` parks on the shared
postgres result-listener (sub-ms wake) and falls back to a 200ms poll on
sqlite/memory; a wait timeout returns the still-pending intent (→ 202), only a
ctx cancellation surfaces an error.

**As-built status codes** (`grants_handler.go`):
- `200 OK` — done within 2s, or an idempotent re-claim of an already-ACTIVE
  grant (within TTL; `410 Gone` past TTL).
- `202 Accepted` + `Location: /api/v1/grants/{id}/claim/status` + `Retry-After: 1`
  — still pending/in_flight after 2s; body `{intent_id, state}`.
- `422 Unprocessable Entity` — worker reported a terminal failure; body
  `{state:"failed", error_class, error_detail}`.

`GET /api/v1/grants/{id}/claim/status` (same `ActionClaim` gate) mirrors that:
`200` + creds on done (propagates the result + flips APPROVED→ACTIVE), `422` on
failed, `200 {state, elapsed_ms}` while pending/in_flight, `409` if no intent
exists yet but the grant is still APPROVED ("POST /claim first").

**Idempotent re-claim**: re-issuing `POST /claim` for an already-ACTIVE
grant returns the same intent's result (status='done') without
emitting a new intent. The handler looks up the latest provision
intent for `(grant_id)` first, sees status='done', skips straight to
returning the decrypted result. Identical semantics to today's
idempotent re-claim, just routed through the outbox.

**SPA implication**: the `ClaimReveal` modal in
`portal/ui/src/components/ClaimReveal.tsx` already handles a single
API call returning creds. For phase 8 it gains a "Waiting for
provisioner…" spinner state and a polling loop bound to the
`Location` header. Cap retries at 30 (≈30s) before surfacing a
"provisioner slow / hard-down" message — workers should never be
that far behind.

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
- Re-execution converges to the same DB state because the ephemeral
  username + password are deterministic in the intent id (§8.4
  "Deterministic ephemeral credentials"). Worker B claims the row,
  runs `CREATE USER IF NOT EXISTS '<deterministic-user>'` (no-op
  if A already created it) + `ALTER USER ... WITH PASSWORD
  '<deterministic-pw>'` (canonicalises whatever state A left), writes
  the result, fires NOTIFY. Portal-side `/claim` sees `done` and
  serves creds.
- The pre-deterministic design had a race: worker A creates the user
  with password₁ then dies before persisting, worker B creates with
  password₂ which the engine ignores because the user exists,
  intent row records password₂ — every subsequent auth fails. The
  HMAC derivation removes the race by construction.
- If only one worker exists and it's hard-down: portal's `/claim`
  short-circuit times out, returns 202 + poll endpoint. The intent
  stays pending until the worker is back; the requester polls or
  retries `/claim` later (idempotent — same intent id).

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

Both sides ship snapshot-counter holders (`provisioning.Metrics` producer-side;
`workerMetrics` consumer-side), nil-safe so the hot paths run unchanged when
metrics aren't attached. Both are **wired**:

- **Portal**: provision metrics attach to the portal's existing obs sidecar
  (`/metrics`) when ephemeral provisioning is enabled.
- **Worker**: an OPTIONAL Prometheus `/metrics` + `/healthz` sidecar enabled via
  `-metrics-addr` / `WORKER_METRICS_ADDR` (empty disables). Infra-only — not a
  user/proxy API, so the §8.2 "no user-facing HTTP surface" invariant holds.

Structured logs correlated by `intent_id` on both sides complement the metrics.
Not-yet: the `{instance_id}`/`{backend_type}` labels and the
`worker_master_connection_errors_total` / `worker_intent_retries_total` counters
are not implemented.

**Portal-side series** (planned names, mirrored by `provisioning.Metrics`):
- `portal_provision_intents_emitted_total{kind}`
- `portal_provision_intents_pending` (gauge, best-effort queue depth)
- `portal_provision_intent_latency_seconds` (emit → result, summary `_count`/`_sum`)
- `portal_provision_claim_timeout_total` (WaitForResult gave up → 202)

**Worker-side series** (planned, mirrored by `workerMetrics`):
- `worker_provision_intents_processed_total{kind, result}`
- `worker_provision_ddl_latency_seconds`
- `worker_stale_leases_reclaimed_total`
- `worker_notify_missed_total` (intent found via catch-up, not NOTIFY —
  LISTEN connection-health indicator)

Alerts (endpoints are wired; these are the suggested rules):
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

## 8.8.1 Worker-liveness heartbeat

The outbox tells you work is flowing; it does **not** tell you a worker is alive
when the queue is empty — an idle worker and a dead worker look identical from
`provision_intents`. The liveness heartbeat closes that gap.

**Granularity decision — ONE row per worker PROCESS, with a per-instance health
map inside it.** Keyed by `worker_id` (`provisioning_workers`, §8.4). The
instance dimension lives in the JSON `health` array, NOT in the table grain:

- **Why not per-techno** (one row per mysql/pg/mongo): a worker can serve
  several *instances* of the same techno (two postgres clusters), and two
  workers can both serve mysql — a per-techno grain can express neither. It
  also can't answer "is THIS process alive", which is the primary question.
- **Why not per-instance row**: a worker serving N backends would write N rows
  per beat, the liveness signal ("process X is up") would be smeared across
  them, and reads would need a GROUP BY to recover the per-process view. The
  map is small, written atomically with the beat, and only ever read whole.
- **Distinct from the lease heartbeat**: `HeartbeatIntentLease` extends the
  lease on a *specific in-flight intent* so another worker doesn't steal it —
  it's per-work-item and only beats while there's work. The liveness heartbeat
  is per-process and beats on a fixed timer regardless of queue state.

**Worker side** — `-heartbeat-interval` / `WORKER_HEARTBEAT_INTERVAL` (default
`10s`) drives the beat; each beat calls `Store.UpsertWorkerHeartbeat` (INSERT
first, UPDATE after) with `last_seen_at=now`, preserving `started_at`.
`-heartbeat-probe` / `WORKER_HEARTBEAT_PROBE` (default `true`) actively dials
each served instance so `health[].ok` / `error_class` reflect *real*
reachability rather than just "process up"; with probe off the row still proves
liveness but the health map is best-effort. The set of instances beaten/probed
is the worker's whitelist when set, else every backend in its resolved config
(mirrors `ClaimPendingIntents`' empty-whitelist = all).

**Portal side**:
- `GET /api/v1/provisioning/workers` (admin-gated) lists every heartbeat row
  with a derived `stale` flag (`WorkerHeartbeat.IsStale`: `last_seen_at` strictly
  before `now − within`) plus the per-instance health map. Read-only operator
  visibility — not on the worker (which has no user-facing HTTP, §8.2).
- Gauge `portal_provision_workers{state}` (states: live / stale) for "how many
  workers does the portal currently see".
- The sweeper prunes rows via `Store.PruneStaleWorkers(cutoff)` so a
  decommissioned `worker_id` doesn't linger as a phantom forever. DELETE is the
  portal's job alone — the worker role has no DELETE on the table.

## 8.9 Phasing

**Phase 8A — the production milestone**: postgres outbox + worker
binary. ✅ **Done.**

- Schema: `provision_intents` shipped as its own migration
  `0003_provision_intents.sql` (postgres + sqlite mirror; sqlite is
  polling-only, no NOTIFY — accepted as the documented degraded mode).
- `portal/internal/provisioning/` package: `intent.go` (builders +
  freeze logic), `notify.go` (postgres LISTEN/NOTIFY + sqlite/memory
  no-op notifier), `client.go` (emit + bounded wait-for-result with a
  shared result-listener), `metrics.go` (producer counters, §8.8).
- `portal/cmd/provisioner-worker/` — the binary: LISTEN loop +
  catch-up ticker + startup drain (`run.go`), claim→DDL→result state
  machine with bounded transient retry + lease heartbeat (`worker.go`),
  config with secret-ref resolution (`config.go`), distroless non-root
  Dockerfile. Reuses `portal/internal/ephemeral/*` provisioners wired to
  a **config-backed** DBA lookup (`ephemeral.NewConfigDBALookup`), never
  the store.
- Portal `cmd/portal/main.go` loads **no** DBA creds: `/claim` emits an
  intent instead of calling `ephemeral.Manager.Provision()`.
- Secret-refs: `env://` and `file://` are implemented; **`aws-sm://` /
  `vault://` are not-yet.**
- Build: `make provisioner-worker` (part of `make build`). Dev standup:
  **`make dev-worker`** runs `docker compose -f dev/compose.yml up -d --build
  provisioner-worker`, starting the worker as a compose service on the same
  `portal_data` named volume the dev portal's SQLite lives in (a host-local
  `bin/provisioner-worker` can't reach that file). Run it after `dev/seed.sh`
  has written `dev/worker-config.json` with the real backend IDs.

**Phase 8B — sqlite compatibility**: ✅ **Done.** `provisioning.NewNotifier`
picks the real LISTEN/NOTIFY notifier for `postgres://` URLs and the no-op
poll-only notifier otherwise; `WaitForResult` and the worker's `listenLoop`
both degrade to their catch-up timers transparently. Same table, lease, and
idempotency; postgres just wakes sub-ms. Sqlite multi-process needs WAL — see
the caveat in `dev/compose.yml`'s `provisioner-worker` service.

**Phase 8C — hardening**: not-yet (futures):
- Multi-region / multi-trust-boundary worker topology, multi-worker
  instance routing beyond the per-worker whitelist (§8.10).
- Cross-portal shared workers (multi-tenant SaaS).
- Alerts + runbooks for worker outage (the `/metrics` endpoints they'd
  alert on are already wired — §8.8).
- The `worker_intent_retries_total` / `worker_master_connection_errors_total`
  counters and the `{instance_id}` / `{backend_type}` labels (§8.8).

## 8.10 Open questions

- **Multi-backend master routing**: ✅ resolved as designed — the
  **per-worker whitelist** is implemented. `-whitelist` /
  `WORKER_INSTANCE_WHITELIST` is a comma-separated list of `backend_id`s;
  empty ⇒ claim all. `ClaimPendingIntents` filters on it server-side.
  Per-channel NOTIFY and an explicit routing table remain **not-yet**
  (only needed past the whitelist's scale ceiling).
- **Master creds rotation without worker restart**: not-yet. `config.go`
  notes the re-resolve timer as future work; today creds resolve once at
  boot.
- **Worker DB role**: ✅ documented + shipped in the `0003` migration
  header (and §8.4): `SELECT, UPDATE` on `provision_intents`; `SELECT` on
  `backends`, `grants`; **no** access to `backend_accounts`,
  `oidc_sessions`, `audit`.
- **TLS to postgres**: worker connects with the same `-store` /
  `PORTAL_STORE` URL form as the portal and the same `SECRETBOX_KEY` for
  result encryption, so the portal can decrypt on `/claim`. TLS verification
  on the **DBA (master-cred) connection** is secure-by-default and only
  relaxed when `PORTAL_ALLOW_INSECURE_DBA_TLS=true` is set explicitly — any
  non-verifying override (pg `sslmode` in disable/allow/prefer/require, mysql/
  mongo TLS off) is otherwise ignored with a warning.
- **Deployment topology**: one worker per trust boundary. Single-worker
  per portal today; multi-worker fan-out is supported by the lease +
  whitelist but multi-trust-boundary topology is **not-yet** exercised.
- **Per-grant zero-knowledge result encryption** (§8.4.1): not-yet —
  ships with shared-key SecretBox.

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
