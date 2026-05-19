# Next session — phase-7 follow-ups + open design questions

Continuation of the validation-workflow rework. Items here were surfaced
in the current session but parked to keep the in-flight refactor focused.
Each section is self-contained: state of play, decision needed, and the
implementation sketch when applicable.

## Context recap (what landed this session)

- `is_operator` ⊥ `T2` split: `Principal.IsOperator()` is config authority
  only; `Principal.IsT2Eligible()` checks per-request `T2Subjects` set
  resolved from the backend's `t2_group_slug` group members.
- Per-backend T2 group: `backends.t2_group_slug TEXT`, populated by
  `entra-sync`, replaces the global `PORTAL_ADMIN_GROUP_SLUG`.
- `approval_mode` per backend: `dual_strict` (default), `dual_or`,
  `validator_only`. Handler dispatches; four-eyes guard binds
  `dual_strict`; on-behalf-of-T1 override at gate1 with reason ≥ 20 chars.
- T1/T2 vocab applied to schema + Go fields + JSON tags + audit log
  events: `t1_subject`, `t1_approved_by/at`, `t1_approved_on_behalf`,
  `t1_on_behalf_reason`, `t2_approved_by/at`. Action enum
  `ActionApproveT1` / `ActionApproveT2` with string values
  `approve_t1` / `approve_t2`.
- Notifier per-backend resolution: `T2Lookup func(ctx, backend) ([]string, error)`.
- `T2Mailbox` reachability fallback added (still here — see §1).

Spec sections updated: `§7.8.1 approval_mode`, `§7.8.7 four-eyes
preservation + override`, `§7.13 bridge state`.

## §1 — Drop `T2Mailbox` global fallback

**Why**: per-backend `t2_group_slug` is now the single source of truth
for gate2 recipients. Keeping a global mailbox alongside reintroduces
the bundling we just unwound and accumulates a "forgotten notifications
go here" address that nobody reads.

**Change set** (small):

- `portal/internal/config/config.go` — drop `Entra.T2Mailbox`, drop
  `-t2-mailbox` flag, drop `PORTAL_T2_MAILBOX` env.
- `portal/internal/config/config_test.go` — drop the validation case
  asserting "Entra needs reachability fallback".
- `portal/internal/config/config.go` `Validate()` — drop the
  `T2Mailbox == ""` check entirely; an Entra-wired portal with no
  per-backend `t2_group_slug` will simply log
  `entra_t2_recipients_empty` and skip the send.
- `portal/internal/notify/entra_mail.go` — drop `T2Mailbox` field on
  `EntraConfig` + `EntraMailNotifier`, drop the `add(n.t2Mailbox)`
  branch in `t2Recipients`.
- `portal/internal/notify/entra_mail_test.go` — replace the
  `TestEntraMail_OnValidatorApproved_UsesT2Mailbox` test with a
  `TestEntraMail_OnValidatorApproved_NoRecipientsSkipsSend` covering
  the empty-set warn-and-skip behaviour.
- `portal/internal/api/router.go` — drop `WithT2Mailbox`, drop
  `t2Mailbox` field on `routerOpts`, drop `T2Mailbox` from `RouterDeps`.
- `portal/cmd/portal/main.go` — drop the `api.WithT2Mailbox(...)` line.
- `README.md` — replace the "Gate2 reachability" subsection with a note
  that per-backend `t2_group_slug` is the only mechanism; misconfigured
  backend → `entra_t2_recipients_empty` warn → fix the backend.

**Observability backstop** (do at the same time):
add a Prometheus counter `portal_t2_recipients_empty_total{backend_id}`
incremented in `t2Recipients` when the resolved set is empty. Surfaces
misconfiguration as an alertable metric, replacing the silent-mailbox
fallback's role.

## §2 — Per-grant `approval_mode` override (mid-flight, operator-only)

**Why**: lets an operator (config-authority principal) downgrade a
specific grant from `dual_strict` to `dual_or` when the workflow has
stalled — typically the single-T2 org case where the lone T2 cleared
gate1 and the four-eyes guard now blocks them at gate2.

**Not at create time** (per user's clarification). The override is
specifically a *recovery* action on an in-flight grant; baking it into
create-time would conflate "I want a fast-path workflow" with "I'm
unblocking a stuck grant."

### Design decisions to settle

1. **Endpoint shape**:
   - **Option A**: `PATCH /api/v1/grants/{id}` accepts an
     `approval_mode_override` field. Reuses existing patch surface.
     Audit row written via the existing patch path.
   - **Option B**: dedicated `POST /api/v1/grants/{id}/escalate` (or
     `/relax`?) with required `{"approval_mode": "dual_or", "reason": "..."}`.
     Distinct from patch; clearly an exceptional action; metric +
     alert hook trivial.
   - **Recommend B**. The patch endpoint is for normal field edits;
     workflow-collapse is exceptional and deserves its own audit
     signal.

2. **Storage**: snapshot the override onto the grant row.
   - New columns on `grants`:
     - `approval_mode_override TEXT NOT NULL DEFAULT ''` — empty = use
       backend's mode; non-empty = override value (`dual_or` /
       `validator_only`; `dual_strict` is never an override since
       it's the default).
     - `approval_mode_override_by TEXT NOT NULL DEFAULT ''` — operator
       subject who set the override.
     - `approval_mode_override_at TIMESTAMPTZ` — when.
     - `approval_mode_override_reason TEXT NOT NULL DEFAULT ''` —
       free-text justification, ≥ 20 chars.
   - `handleApprove` reads `effectiveMode`: if
     `g.ApprovalModeOverride != ""` → use override; else use
     `backend.ApprovalMode`. Audit row already carries who/why.

3. **Eligibility**: operator-only (config authority). Does NOT require
   T2 membership — this is config action, not gate-clearing.

4. **Reverse direction allowed?** Operator can also re-tighten
   (`dual_or → dual_strict`)? Probably yes — reset the override field
   to empty. Less common but mirrors the affordance.

5. **Race with gate1**: if override flips
   `dual_strict → dual_or` while grant is at PENDING, the next
   `/approve` collapses to APPROVED in one call by any eligible
   approver. That's the intended behaviour — no race to guard against.

6. **Race with gate2**: if override flips while grant is at
   VALIDATOR_APPROVED, the four-eyes guard (which is `dual_strict`-
   only) no longer fires. Same actor who cleared gate1 can now clear
   gate2. That's the rescue case. Audit shows the override was
   declared between the two transitions.

### Implementation sketch

**Schema** (in-place edit of `0001_initial.sql` since pre-deploy):
```sql
-- in grants table:
approval_mode_override        TEXT NOT NULL DEFAULT '',
approval_mode_override_by     TEXT NOT NULL DEFAULT '',
approval_mode_override_at     TIMESTAMPTZ,
approval_mode_override_reason TEXT NOT NULL DEFAULT '',
```
Same in `sqlite/migrations/0001_initial.sql` with TEXT for the
timestamp (project convention).

**Domain**:
```go
// On Grant struct:
ApprovalModeOverride       ApprovalMode `json:"approval_mode_override,omitempty"`
ApprovalModeOverrideBy     string       `json:"approval_mode_override_by,omitempty"`
ApprovalModeOverrideAt     *time.Time   `json:"approval_mode_override_at,omitempty"`
ApprovalModeOverrideReason string       `json:"approval_mode_override_reason,omitempty"`
```

**Store roundtrip**: same shape as the t1_on_behalf fields — INSERT
list, UPDATE list, scanGrant, grantSelectSQL. Memory store: trivial
field copy.

**Handler**:
```go
// New endpoint:
mux.Handle("POST /api/v1/grants/{id}/escalate",
    operatorOnly(http.HandlerFunc(h.escalate)))

func (h *grantsHandler) escalate(w, r) {
    // body: {"approval_mode": "dual_or"|"validator_only"|"", "reason": "..."}
    // reason >=20 chars when mode != "" (clearing override doesn't need reason)
    // operator-only (the operatorOnly wrapper enforces it)
    // CAS-update grant row, write audit entry, log warn metric
    // 409 if grant is in a terminal state (DENIED/APPROVED/CLAIMED/EXPIRED/REVOKED).
}

// In handleApprove:
mode := backend.ApprovalMode
if g.ApprovalModeOverride != "" {
    mode = g.ApprovalModeOverride
}
if !mode.Valid() { mode = ApprovalDualStrict }
```

**Metric**: `portal_approval_mode_overrides_total{backend_id, from, to}`.

**Tests**:
- Operator successfully escalates `dual_strict` → `dual_or` on
  VALIDATOR_APPROVED, T2 who cleared gate1 can now clear gate2.
- Non-operator gets 403.
- Reason < 20 chars gets 400.
- Escalate on terminal grant gets 409.
- Tightening (`dual_or` → empty/`dual_strict`) flips the four-eyes
  guard back on for any future gate2 attempt.

## §3 — Backend = database vs server (open design question)

**Status**: open. Surfaced this session, no change made yet.

**The question**: today, a row in `backends` is `(host, port, type)` —
that's a *server*. `backends.databases` is a CSV of which database
names that server exposes for the proxy. Grants reference
`backend_id`, not a specific `(backend_id, database)` tuple — well,
`grants.database` is a column too, so it's actually
`(backend_id, database)`. Ambiguity in the model:

- A single MySQL server hosting `orders-db`, `inventory-db`,
  `analytics-db` could be:
  - **One backend row** with `databases = "orders-db,inventory-db,analytics-db"`,
    grants carry the `database` field. **Today's model.**
  - **Three backend rows**, one per database. Grants reference a
    specific backend.

**Why it matters now** (after the per-backend rework):
- `approval_mode` is per-backend — under the one-row model, all three
  databases on the same server share one workflow. Probably wrong:
  prod `orders-db` wants `dual_strict`, but dev-sandbox `analytics-db`
  on the same server wants `dual_or`.
- `t2_group_slug` is per-backend — DBA team for `orders-db`, data team
  for `analytics-db`, but if they share a backend row, they share a
  T2 group. Same problem.
- `backend_validator_groups` (when §7.3 lands) — same per-backend
  granularity question.

**Three viable models**:

1. **Backend = server, current model**: `backends` row = one
   `(host, port)`; per-database knobs live elsewhere.
   - Problem: forces splitting `approval_mode` / `t2_group_slug` into
     a junction table keyed on `(backend_id, database)`. Bigger
     schema change.

2. **Backend = (server, database)**: each `(host, port, database)`
   tuple is its own backend row. Grants pin to a specific backend.
   - Pro: the per-backend knobs we just added work naturally — each
     database on a shared server has its own workflow + T2 group.
   - Pro: matches operator mental model: "this DB has these admins".
   - Con: backend table grows quickly when many databases per server.
   - Con: connection pooling + proxy routing must collapse multiple
     backend rows that share `(host, port)` to one TCP target.

3. **Hybrid**: backend = server (top-level row), per-database
   overrides in a child table.
   - `backend_databases (backend_id, database, approval_mode,
     t2_group_slug, …)`.
   - Grant resolves effective mode + T2 group via the child row when
     present, falls back to backend defaults when not.
   - Pro: most flexible — defaults at server, overrides per database.
   - Con: more complexity, two-tier resolution.

**Decision needed before implementing the per-grant escalation (§2)
or the §7.3 schema rework**: pick the model. Otherwise we're piling
features onto an ambiguous foundation.

**Mutualised-DB scenario** (the user's specific concern):
- Today's MySQL/Postgres/Mongo proxies authenticate per-connection,
  the proxy's `auth-url` returns `allowed_dbs` per user. A user with
  a grant on `orders-db` connecting to a server hosting both
  `orders-db` and `payroll-db` is restricted at the proxy layer.
- But: who validates a grant request for `orders-db` on a shared
  server? Today the policy answers via `backend.id`. If both
  databases share one backend row, both have the same validators.
  That's **wrong** in real-world ops — payroll typically has stricter
  approval than orders.
- Conclusion: this question can't be deferred indefinitely. Probably
  resolves to model **(2)** or **(3)** depending on how often we
  expect database-level overrides vs. server-level uniformity.

**Recommend resolving this BEFORE §2** — per-grant override only
makes sense once we know what "the grant's backend" actually
references.

### Open sub-questions

- Connection-pool key: `(host, port)` regardless of model? Probably
  yes — pool is a transport-level concern, not a policy concern.
- Naming: if backend = `(server, database)`, what do we call the
  parent server abstraction? `backend_servers` table? Or just
  inline `(host, port)` triples and don't model the server
  explicitly?
- Migration impact for existing grants: under model (2) or (3),
  every existing grant needs to bind to the right
  `(server, database)` tuple. Trivial in pre-deploy state; needs a
  data migration once shipped.

### Proposed relationship model (brainstorm)

The user floated a richer data model tying these concerns together:

```
Instance (host, port, db)
  ─── allowed-to-request → Group (e.g. "ecommerce-team")
                              └── Member: User
User
  ─── validated-by → Peer/Manager
                       └── may differ per Role (ro / app / dba)
```

Two relationships to model:

1. **Instance ↔ Group** — "members of `ecommerce-team` may *request*
   access to `orders-db@prod-mysql`". Eligibility, not approval.
2. **User ↔ Validator, per role** — "Alice's validator for `ro` is
   Bob (peer); for `app` it's Carol (lead); for `dba` it's the
   DBA-team group". Adds a **role-type dimension** to T1 routing,
   new vs. today's single-validator-per-user.

This aligns with model **(2)** / **(3)** from above — it only makes
sense when "backend" is at least database-granular so the eligibility
and validator-routing rows have a meaningful anchor.

### Where does each piece of data live?

| Data | Home | Reasoning |
|---|---|---|
| Group membership (who is in a group) | **Entra → entra-sync → portal store** | Native Entra concept; entra-sync already mirrors it. Live Graph on the hot path = too slow + availability coupled. |
| User → manager / peer (the org chart) | **Entra → entra-sync → portal store** | Canonical in HR/IdP; portal mirrors. Today's pattern. |
| Instance ↔ Group eligibility ("X team may request orders-db") | **Portal DB, operator-managed** | Policy, not org structure. Entra knows nothing about your DB inventory; entra-sync would be wrong direction. Portal is source of truth. Operator API + admin SPA writes it. |
| Role-type validator routing (per-user / per-backend, per role) | **Portal DB** | Policy. May vary per backend (prod-pg's `dba` = senior-DBA group; sandbox's `dba` = peer suffices). |
| Config file as an alternative | **Only for portal-wide invariants / defaults** | E.g. "globally, `dba` always requires at least a lead-tier validator" — but per-backend overrides belong in DB. Config files are fine for compile-time invariants, terrible for evolving policy. |

**Live-loaded from Entra at decision time**: recommend against for
any of this data. Three reasons:
- **Hot-path latency**: every grant create/approve waits on Graph
  → multi-hundred-ms tail.
- **Availability coupling**: Graph hiccup = portal stops accepting
  grant requests.
- **Audit clarity**: "what was the validator set when this grant was
  filed?" needs a frozen snapshot, not a live re-query. §7.3's
  `grant_validators` snapshot table exists for exactly this reason.

**entra-sync cadence**: the mirror cron is the right rhythm for
group membership + org chart (typically 15-60 min is plenty — IdP
changes propagate in the same time frame as HR onboarding, which is
the natural authority). Instance/group eligibility + role routing
are admin-DB writes; no cron needed.

### Schema sketch for the relationship model

Extends §7.3's tables with a `role` column on each, defaulting to
`''` (any role). Existing rows keep working; operators opt into
per-role granularity only when they need it.

```sql
-- Eligibility: who may *request* a role on a backend.
-- role = '' means "any role"; narrower rows stack with the wildcard.
CREATE TABLE backend_request_groups (
    backend_id TEXT NOT NULL REFERENCES backends(id) ON DELETE CASCADE,
    group_id   TEXT NOT NULL REFERENCES groups(id)   ON DELETE CASCADE,
    role       TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (backend_id, group_id, role)
);
CREATE INDEX idx_backend_request_groups_group ON backend_request_groups(group_id);

-- Per-role T1 validator routing for a user.
-- role = '' applies to all roles. Specific-role rows override the wildcard.
CREATE TABLE user_validators (
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role         TEXT NOT NULL DEFAULT '',
    validator_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role, validator_id),
    CHECK (user_id <> validator_id)
);
CREATE INDEX idx_user_validators_validator ON user_validators(validator_id);

-- Per-backend, per-role T1 validator GROUPS
-- ("DBA team validates `dba` on prod-pg").
CREATE TABLE backend_validator_groups (
    backend_id TEXT NOT NULL REFERENCES backends(id) ON DELETE CASCADE,
    role       TEXT NOT NULL DEFAULT '',
    group_id   TEXT NOT NULL REFERENCES groups(id)   ON DELETE CASCADE,
    PRIMARY KEY (backend_id, role, group_id)
);
CREATE INDEX idx_backend_validator_groups_group ON backend_validator_groups(group_id);
```

Grant-creation logic:

1. **Eligibility check**: requester's group memberships ∩
   `backend_request_groups(backend, role)` ∪ `(backend, '')` must
   be non-empty. Otherwise 403 "not eligible to request this
   role on this backend".
2. **Snapshot T1 eligible set** into `grant_validators` from the
   union of:
   - `user_validators(user, role)` ∪ `(user, '')`
   - members of groups in `backend_validator_groups(backend, role)`
     ∪ `(backend, '')`
3. Grant moves to PENDING with the snapshot frozen.

### Sync fixture shape additions

`entra-sync` input gains (today's shape + these fields):

```json
{
  "users": [{
    "username": "alice", "external_id": "sub-alice",
    "validators": [
      { "role": "",    "validator_username": "bob" },
      { "role": "dba", "validator_username": "dba-lead" }
    ],
    "groups": ["ecommerce-team"]
  }],
  "groups": [{ "slug": "ecommerce-team", ... }]
}
```

Instance eligibility + backend-level validator groups are
**operator-admin surfaces**, not sync input — they live in the
portal's config domain, not the IdP's.

### Blast radius

- Schema: three new tables (or §7.3's existing two amended +
  `backend_request_groups` new).
- Authz: `ActionCreate` needs the eligibility check added (currently
  a no-op beyond session-binding).
- Create handler: snapshot the T1 set (§7.3 already plans this).
- SPA:
  - Per-user: "which validators for which roles" editable in the
    org view.
  - Per-backend: "which groups may request which roles" + "which
    groups validate which roles" in the backends view.
- entra-sync: extend fixture shape + reconciliation logic for
  `user_validators` rows.

### §3 resolution — committed model

User committed to this shape. Four-entity model:

```
instance (host:port)
   ├── master creds (portal-private; dedicated worker holds them)
   │
   └── database ("orders")
         ├── approval_mode, t2_group_slug, validators (policy)
         └── grant (user, role ∈ {ro, app, dba})
               └── ephemeral DB account ("portal_grant_<id>")
                     ├── GRANT <role defaults> ON <database>
                     └── TTL = grant TTL
```

Key rename: today's `backends` table → `instances`; add a new
`databases` child table; grants pin to `database_id` instead of
`backend_id`. Drops the CSV `databases` column on the current
`backends` row in favour of first-class rows.

Naming in code / schema going forward: `Instance`, `Database`,
`DatabaseAccount` (for the DBA-managed shared accounts, if kept —
see §7 below that argues for dropping them). Kill the word
"backend" — it has been ambiguous throughout.

Schema sketch in earlier §3 brainstorm above holds, with one
column to add on `instances` for the master credential itself:

```sql
CREATE TABLE instances (
    id                   TEXT PRIMARY KEY,
    name                 TEXT NOT NULL,
    type                 TEXT NOT NULL,  -- mysql / postgres / mongo
    host                 TEXT NOT NULL,
    port                 INTEGER NOT NULL,
    master_username      TEXT NOT NULL DEFAULT '',
    master_password      TEXT NOT NULL DEFAULT '',   -- SecretBox
    master_password_ref  TEXT NOT NULL DEFAULT '',   -- env/file/aws-sm/...
    created_at           TIMESTAMPTZ NOT NULL,
    updated_at           TIMESTAMPTZ NOT NULL,
    UNIQUE(host, port)
);

CREATE TABLE databases (
    id               TEXT PRIMARY KEY,
    instance_id      TEXT NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    name             TEXT NOT NULL,
    approval_mode    TEXT NOT NULL DEFAULT 'dual_strict'
        CHECK (approval_mode IN ('dual_strict', 'dual_or', 'validator_only')),
    t2_group_slug    TEXT NOT NULL DEFAULT '',
    created_at       TIMESTAMPTZ NOT NULL,
    updated_at       TIMESTAMPTZ NOT NULL,
    UNIQUE(instance_id, name)
);
```

`grants.backend_id` → `grants.database_id`. `database_request_groups`,
`user_validators`, `database_validator_groups` (renamed from the
earlier `backend_*` sketch) anchor on `database_id`.

**Master-vs-DBA credential split — DECIDED**: master lives on
`instances` (one per server, portal-private, never surfaced through
grants). `dba` is a role surfaced through grants alongside `ro`/`app` —
see §7 for whether shared `dba` creds exist at all.

## §6 — Dedicated provisioning worker

**Full design now lives in
[`specs/phase-8-provisioning-worker.md`](phase-8-provisioning-worker.md)**
— six transport options evaluated (PG LISTEN/NOTIFY, outbox-poll,
Redis streams, RabbitMQ/NATS, in-process, direct RPC), recommendation
is a pluggable transport interface with `pg` default on postgres
backends and `poll` default on sqlite, optional build-tag-gated
Redis / RMQ / NATS. Failure semantics, revocation path,
observability, phasing (8A→8D), open questions all captured there.

Summary of the invariant kept here for quick reference:

**Architectural invariant**: the portal process **never holds master
credentials**. A separate worker service owns the master secret and
is the only component that runs CREATE USER / DROP USER DDL against
the backend.

Why: reduces portal's blast radius. A compromised portal can
manipulate grant state (approve, revoke) but can't mint arbitrary DB
users or DROP existing ones. Security property survives any portal
CVE that yields code execution in the HTTP process.

Shape (TBD in detail):

- Portal emits provision / revoke *intents* to the worker via a
  queue or RPC (candidate transports: in-process channel for single-
  binary dev; NATS / SQS / gRPC for split deployment; postgres-backed
  outbox table for durability + replay).
- Worker holds master creds (sourced via `aws-sm://` / `vault://` /
  etc. — the secret-ref machinery already supports this).
- Worker is the only code that imports `portal/internal/ephemeral` +
  the protocol-specific connectors. Portal loses those deps entirely.
- Worker writes back to the portal (or to a shared store) with the
  provisioned credential so the portal can encrypt it on the grant
  row + reply to the `/claim` caller.

Things to settle before implementation:

- **Transport**: in-process channel (compiles to one binary still)
  vs. separate process vs. separate host. First step is probably
  "separate process, unix socket / HTTP on localhost" — gets the
  code separation without a queue dependency.
- **Failure semantics**: worker down at `/claim` time — 503 to
  caller, grant stays APPROVED, retry from caller? Or portal
  queues and returns "pending" + polls? The latter changes the
  `/claim` contract (currently synchronous).
- **Durability**: if portal crashes after submitting provision but
  before recording the result, the worker may have created a user
  the portal has forgotten. Outbox table + idempotent
  `intent_id` keyed operations covers this.
- **Revoke**: same channel. Portal emits intent, worker executes.
- **Observability**: worker's own metrics + logs; portal references
  worker intents by id.

Leave this as a separate phase (post-current spec). Decision needed:
ship "portal holds master creds" as the v1 reality, migrate to the
worker as a hardening phase? Or block v1 on worker? Probably the
former — worker is a pure security hardening, functional parity
throughout.

## §7 — Commit to ephemeral-only (drop `PolicyMode=permanent`)

**Decision**: every grant provisions its own DB user. No shared
`app_rw` / `dba_admin` credentials brokered through the portal.
`PolicyMode=permanent` goes away.

**Rationale** (from earlier discussion):

- One grant = one DB user = one audit primitive. Every query traces
  to a specific grant's requester via the DB username — no "which
  grant executed this?" ambiguity.
- Revocation is absolute: `DROP USER` severs access at the DB level,
  not just the proxy.
- Credential compromise blast radius = one grant's TTL, not "every
  app_rw user until rotation".
- No shared-credential rotation problem. Rotation happens naturally
  as grants churn.
- Matches §6 worker cleanly: every grant produces exactly one
  provision intent; no "shared credentials" path to maintain
  separately.

**Edge cases** reviewed, none justify keeping permanent:

| Scenario | Resolution |
|---|---|
| Long-running service daemon | Ephemeral with TTL=7d + pre-expiry refresh |
| CI/CD pipeline | One grant per run; TTL=minutes |
| Batch ETL (hours-days) | Ephemeral with TTL ≥ job duration |
| App replica sharing | Per-replica grant = per-replica user; if backend has per-user governor limits, that's a design choice the operator makes when issuing N grants. Portal stays honest. |
| Legacy `app_rw` accounts pre-dating the portal | Out of scope — portal doesn't manage them, they continue to exist outside the grant system |
| Pre-portal ETL pipelines with hard-coded creds | Same — portal's scope is portal-managed access; legacy creds coexist |
| Regulatory "who connected as app_rw" audit | Reversed: ephemeral *improves* attribution (username = grant id) |

**What goes away**:

- `PolicyMode` field on `grants` (always ephemeral now).
- `DatabaseAccount` / `BackendAccount` shared-credential rows for
  ro/app/dba — or kept purely as role-privilege templates (§3
  option (b) above). Recommend option (a): hardcoded protocol
  defaults in the provisioner, no table at all.
- Policy engine's "resolve backend account" branch.
- `store.BackendAccount*` interface methods (`UpsertBackendAccount`,
  `GetBackendAccount`, ...) — delete.
- Tests covering the permanent-mode fallback path.

**What stays**:

- `instances.master_*` — still needed for provisioning.
- Grant's `ephemeral_username` + `ephemeral_password` — the per-
  grant creds are the only creds now.
- Proxy's `/auth` response shape — unchanged from caller's POV;
  it always returns "the creds you should use" which happens to
  always be ephemeral.

**Role-privilege defaults** (§3 option (a)) baked into the
provisioner:

```go
// portal/internal/ephemeral/postgres.go
func (p *PostgresProvisioner) grantsFor(role domain.Role, db string) []string {
    switch role {
    case domain.RoleRO:
        return []string{
            fmt.Sprintf("GRANT CONNECT ON DATABASE %q TO %s", db, ephUser),
            fmt.Sprintf("GRANT USAGE ON SCHEMA public TO %s", ephUser),
            fmt.Sprintf("GRANT SELECT ON ALL TABLES IN SCHEMA public TO %s", ephUser),
        }
    case domain.RoleApp:
        // ... + INSERT, UPDATE, DELETE
    case domain.RoleDBA:
        // ... + CREATE, ALTER, DROP on schema objects (NOT user lifecycle)
    }
}
```

Mirror for MySQL + Mongo, per protocol idiom. No table, no config
knob — predictable behaviour operators read from one file per
protocol.

## §8 — Requester-chosen duration + operator-extension

Two related enhancements to the grant lifecycle. Both are about
**when the grant dies**; both today use fixed portal-wide values
from `config.Windows` (`Validation`, `Claim`, `CredentialTTL`).

### §8.1 Requester-chosen credential duration

**Today**: `ConnectionTTLSec` column exists on `grants` but is
populated from `config.Windows.CredentialTTL` at create time.
Every grant on the portal gets the same TTL regardless of role,
sensitivity, or requester intent.

**Desired**: the requester picks a duration at create time,
bounded by policy:

```json
POST /api/v1/grants
{
  "backend_addr": "prod-pg:5432",
  "database":     "orders",
  "role":         "ro",
  "reason":       "INC-1234 incident response",
  "requested_duration_seconds": 7200
}
```

Bounds live as policy knobs (per role, per database, or a global
default). For example:

| Role | Default TTL | Max TTL | Max TTL with extra approval |
|---|---|---|---|
| ro  | 1h | 7d  | 30d |
| app | 1h | 24h | 7d  |
| dba | 30m | 4h | 24h |

Shorter TTLs on more privileged roles — the usual pattern.

**Storage**: add `requested_duration_seconds` column (what the
requester asked for; survives claim). Rename `ConnectionTTLSec` to
`credential_duration_seconds` for clarity. At `/claim` time,
`ExpiresAt = claim_time + credential_duration_seconds`, same as
today — the value just comes from the grant row rather than global
config.

**Validation** on create:
- If requested > max allowed for (role, database), 400 with the
  max explained.
- If not provided, use the default for (role, database).
- If exceeds "max without extra approval", force `dual_strict`
  workflow regardless of the backend's `approval_mode` (adds a
  tier-2 review for long-duration asks). Probably §8's hardest
  design decision — leaving TBD.

**Policy knobs**: a new table `database_role_ttl_policies`:

```sql
CREATE TABLE database_role_ttl_policies (
    database_id  TEXT NOT NULL REFERENCES databases(id) ON DELETE CASCADE,
    role         TEXT NOT NULL CHECK (role IN ('ro', 'app', 'dba')),
    default_seconds        INTEGER NOT NULL DEFAULT 3600,
    max_seconds            INTEGER NOT NULL DEFAULT 86400,
    -- max_with_extra_approval_seconds: duration above this bumps
    -- the grant's workflow to dual_strict regardless of the
    -- backend's approval_mode. NULL = no "long ask" escalation.
    max_with_extra_seconds INTEGER,
    PRIMARY KEY (database_id, role)
);
```

Default values live in config as global fallbacks when no row
exists for a specific (database, role).

### §8.2 Operator-extension mid-flight

**Why**: grant is about to expire but the task isn't done. Today
the user has to re-request, re-approve, re-claim. That's fine for
"next-day continuation" but wrong for "incident-response, 15 mins
left, task takes 2 more hours".

**Endpoint** (operator-only):

```json
POST /api/v1/grants/{id}/extend
{
  "additional_seconds": 7200,
  "reason": "INC-1234 ongoing; 2h more needed for rollback"
}
```

Behavior:
- Only valid on ACTIVE grants (extend doesn't make sense on
  PENDING — approve first).
- Bounded by the same `max_with_extra_seconds` policy as §8.1 —
  operator can extend past `max_seconds` if the policy permits,
  not past `max_with_extra_seconds`.
- `ExpiresAt` bumps by `additional_seconds`.
- Audit row captures operator subject + reason + old/new
  expires_at. Metric `portal_grant_extensions_total{role}` for
  alerting on extension frequency.
- Reason required, ≥ 20 chars (same convention as on-behalf
  override in §2).

**Storage**: no new table; keep the extension history in the
existing audit stream. The grant row just shows the latest
`ExpiresAt`.

**Proxy visibility**: the proxy's mid-session revoke watcher
already polls `/status/{id}` — when it sees the new `ExpiresAt`,
it adjusts the connection keep-alive accordingly. No protocol
change needed.

### §8.3 Future doors this opens

Making duration first-class (per-grant column + policy-bounded
picker + extension endpoint) sets up:

- **Scheduled grants** (request now, credentials active at a
  future time). Adds `active_from` alongside `expires_at`. Not a
  v1 feature but the schema supports it naturally.
- **Per-role SLA tiers** ("emergency: 4h max", "standard: 24h
  default"). Already the shape above.
- **Early revocation without DROP USER** — set `expires_at = now`,
  sweeper + proxy watcher catch up within polling interval. For
  "graceful" revoke that lets in-flight queries finish.
- **Explicit request "I need this until tomorrow 6pm"** via a
  free-form duration picker in the SPA, instead of predefined
  chips.

### §8 blast radius

- Schema:
  - `database_role_ttl_policies` new table.
  - Grant column rename: `connection_ttl_seconds` →
    `credential_duration_seconds`. Add `requested_duration_seconds`
    (immutable snapshot of what the user asked for).
- Handler:
  - `create` parses optional `requested_duration_seconds`,
    validates against policy, stores.
  - `claim` uses `grant.credential_duration_seconds` (copied from
    `requested_duration_seconds` at create) to compute
    `expires_at`.
  - New `extend` endpoint (operator-only, reason required).
- Policy engine: new "resolve TTL policy for (database, role)"
  lookup, falls back to config defaults.
- SPA:
  - Request form: duration picker bounded by the policy for
    (database, role).
  - Operator SPA for ACTIVE grants: "extend" action with reason
    field.
- Tests: duration-exceeds-max rejection, policy-lookup-fallback,
  extend-past-max rejection, extend audit trail.

## Suggested order for next session

1. **§3 resolution** — ratify the four-entity model (instance /
   database / grant / ephemeral account). Design conversation, ~30
   min. The schema sketch above is the starting point.
2. **§1 — drop `T2Mailbox`** (~30 min implementation). Independent
   of everything, low risk.
3. **§7 — commit to ephemeral-only**, drop permanent-mode code.
   ~2-3 hours, mostly deletion + test cleanup. Unblocks a cleaner
   schema shape.
4. **§3 implementation** — `backends` → `instances` + `databases`
   split + per-database policy knobs. ~4-5 hours, mechanical rename
   + schema reshape, still pre-deploy so no migration.
5. **§2 — per-grant escalation endpoint**, now meaningful against
   the resolved grant→database shape. ~2-3 hours.
6. **§8 — requester-chosen duration + extension endpoint**. Natural
   follow-on to §2 (both are mid-flight operator levers). ~3-4
   hours for §8.1 + §8.2.
7. **§4 — role-typed validator routing** — schema + resolution
   logic, admin SPA surfaces. ~1-2 days.
8. **§6 — provisioning worker**, deferred to a separate phase as
   pure security hardening.
