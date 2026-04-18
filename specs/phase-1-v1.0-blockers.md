# Phase 1 — v1.0 blockers

These five items are what stops us from running the portal in production. Everything else can ship in 1.x minors.

**Goal:** operator can deploy the portal to a box, have it survive a restart, manage grants through a real approval workflow, keep audit history bounded, store backend secrets without them living in memory-only plaintext, and revoke access that takes effect on in-flight connections.

Estimated: **~10 dev-days**, split across the items below.

---

## 1.1 Persistent portal store

**Status:** ⬜

### Why
Today `portal/internal/store/memory.go` holds everything in RAM. Restart = lose every user, backend, grant, and audit entry. Not acceptable for any deployment beyond a demo.

### Scope
- New impl behind the existing `store.Store` interface.
- **SQLite first** (file-backed, single-binary, zero ops) → **Postgres** (multi-node) as a later drop-in.
- Schema migration tooling (goose, golang-migrate, or hand-rolled — pick one, document it).
- `portal/cmd/portal/main.go` picks the impl via a new `-store` flag / `PORTAL_STORE` env: `memory` (default for tests), `sqlite:///path/to.db`, `postgres://...`.

Out of scope:
- Redis / Dynamo / other KV backends.
- ORM abstraction — hand-written SQL is fine and matches the no-heavy-dep ethos.

### Design sketch
- `portal/internal/store/sqlite/` package, implements `store.Store` with `database/sql` + `modernc.org/sqlite` (CGO-free) or `mattn/go-sqlite3`.
- Migrations live in `portal/internal/store/sqlite/migrations/*.sql`, embedded with `//go:embed`.
- Same package skeleton reused for Postgres: `portal/internal/store/postgres/` with `jackc/pgx/v5/stdlib`.
- `store.NewFromURL(url string) (Store, error)` factory used by main.
- Preserve existing `ErrNotFound` / `ErrConflict` semantics — the API contract already covers it.

### Acceptance criteria
- `make test` passes against SQLite impl via testcontainers (or in-process file).
- Existing `portal/internal/api` tests run unchanged against `NewFromURL("sqlite::memory:")`.
- Portal binary restart recovers users, backends, grants, audit entries.
- HLD §6 status flips 🟡 → ✅.

### Rough effort
3 dev-days (SQLite). +1-2 dev-days later when Postgres impl is added.

---

## 1.2 Real approval workflow

**Status:** ⬜ (currently auto-approves on `POST /grants`)

### Why
`grants_handler.create` sets `Status=GrantApproved` + `ApprovedBy="scaffold"` synchronously. That defeats the portal's reason to exist — a four-eyes gate between "Alice wants access" and "Alice has access".

### Scope
- Grants created in `PENDING` state by default.
- New `POST /api/v1/grants/:id/approve` and `/deny` endpoints.
- Approver identity taken from OIDC session (see OIDC admin mapping in phase 2) — falls back to `"api-bearer"` when approved via static token.
- Optional webhook notification on `grant_requested` — simple POST to a configured URL so operators can wire Slack/email.

Out of scope:
- Approval policies (N-of-M reviewers, hierarchy, time-of-day rules) — not needed for v1.0.
- In-portal inbox UI — wait for web UI phase.

### Design sketch
- `domain.Grant.RequestedBy` added (subject from the creating session).
- `Grant.Status` lifecycle: `PENDING → APPROVED → (EXPIRED|REVOKED)` or `PENDING → DENIED`.
- Policy engine already filters on `Statuses: []GrantStatus{GrantApproved}` — unchanged.
- On `POST /grants` when PENDING → emit webhook if `PORTAL_APPROVAL_WEBHOOK_URL` set; hydrate body with user, backend, role, reason.
- Auto-approve stays available for bootstrapping demos behind `-auto-approve` / `PORTAL_AUTO_APPROVE=1`.

### Acceptance criteria
- New grant lands in `PENDING`; `/auth` denies access.
- `POST /:id/approve` as admin flips to `APPROVED`; next `/auth` succeeds.
- `POST /:id/deny` terminal; cannot be re-approved without new request.
- Webhook fires with correct payload when configured; absence doesn't break create.

### Rough effort
2 dev-days.

---

## 1.3 Audit retention + compaction

**Status:** ⬜

### Why
`Memory.audit` is an unbounded `[]domain.AuditEntry`. Once audit shipping is enabled (phase done), every query from every proxy lands here forever. OOM on week one.

### Scope
- Retention policy: keep N days OR M entries, whichever binds first.
- Persisted audit store (falls out naturally from 1.1 once that lands).
- Background sweeper goroutine in the portal binary.
- Metric exposing `audit_entries_total` and `audit_entries_pruned_total`.

Out of scope:
- Cold-storage export (S3 / archive).
- Per-tenant retention.

### Design sketch
- Config: `-audit-retention-days` (default 30), `-audit-max-entries` (default 10M), `-audit-sweep-interval` (default 1h).
- Sweeper uses a single `DELETE FROM audit WHERE timestamp < NOW() - interval $1 day` on SQL backends. In-memory impl slices-from-front.
- Reject writes that would push past the hard cap — audit shipper will log `non-retryable` and operators will see the portal complain.

### Acceptance criteria
- Fill the store past the cap in a test, assert sweeper trims to the expected window.
- Metric increments observed.
- Portal memory / disk stays bounded under 24h soak test (integration).

### Rough effort
1 dev-day on top of 1.1.

---

## 1.4 Backend password handling at rest

**Status:** ⬜ (plaintext in memory + DB column once 1.1 lands)

### Why
`BackendAccount.Password` is the one secret the portal has to remember in cleartext (the proxy needs it to authenticate to the backend). Storing it unencrypted in SQLite on disk = a file read = game over.

### Scope
- Pluggable `SecretProvider` interface: `Get(key string) (string, error)`.
- Three built-in providers: `env://` (reads env vars), `file://` (reads files), `inline://` (the current behaviour, marked unsafe in docs).
- Optional: `vault://` (HashiCorp Vault) + `awssm://` (AWS Secrets Manager) — gated by build tags so they don't leak deps into lean builds.
- Admin endpoint that stores backend account now takes a **key reference** instead of the raw password; portal resolves via provider at `/auth` lookup time.

Out of scope:
- Cert-based backend auth (separate spec if needed).
- Transparent rotation — manual for v1.0.

### Design sketch
- `internal/secrets` package with interface + registry + two built-in providers.
- `BackendAccount.PasswordRef` (new field) replaces `Password` on the wire for admin CRUD. Old `Password` field kept for backwards-compat but marked deprecated.
- Policy engine calls `secrets.Resolve(acct.PasswordRef)` inside `Engine.Resolve`.
- Fail-closed: resolution error → `ErrGrantExpired`-equivalent (log with cause, return generic denial).

### Acceptance criteria
- `POST /backends/:id/accounts` with `{"password_ref": "env://DB_APP_RW_PW"}` resolves via env at auth time.
- `file://` provider reads a file mode 0600 and refuses to read world-readable files.
- Auth flow still works end-to-end in e2e tests.

### Rough effort
2 dev-days (env + file providers). Vault + SM add ~1 day each later.

---

## 1.5 Mid-session grant revocation

**Status:** ⬜

### Why
Revoking a grant today only bites the next connect. Existing connections keep running until the client disconnects. Unacceptable for "instant revocation" (HLD design principle #3).

### Scope
- Connection TTL enforcement: proxy tracks per-conn `expires_at` from the portal's `connection_ttl_seconds`; closes client on expiry with a clean `ErrorResponse`/`ERR` packet.
- Revocation push or poll (poll is simpler, pick first):
  - Proxy polls `/api/v1/grants/:id` every N seconds for each active conn's grant.
  - On `Status != APPROVED` or past expiry, close the conn.
- Optional server-sent-events endpoint on the portal (`GET /api/v1/events`) for push-style — defer to phase 2 if latency of polling is tolerable.

Out of scope:
- Graceful query cancellation mid-flight — we cut the TCP connection; the client's driver handles retries.
- Per-query revocation (finer than per-connection).

### Design sketch
- New goroutine per client conn, named `proxy.revokeWatcher`. Ticks every `TTL/5` or every `30s`, whichever is shorter.
- On revocation signal, calls `client.Close()` + `backend.Close()`. Existing `CloseOnDone` pattern handles this cleanly.
- Portal: keep an in-memory `grant_id → subscribers` map for SSE push (phase 2 optimization).

### Acceptance criteria
- E2E test: connect → issue `DELETE /grants/:id` → proxy closes the conn within 30s.
- E2E test: grant with `connection_ttl_seconds=5` closes after 5s even without revocation.
- Race-clean under `go test -race`.

### Rough effort
2 dev-days (poll only). SSE push adds 1 day later.

---

## Done criteria for Phase 1

- Restart portal binary → state survives.
- Grant created → stays `PENDING` until admin approves.
- Audit sweeper empirically keeps usage bounded under load.
- Backend passwords never appear in plaintext on disk or in a DB dump.
- Revoking a grant closes in-flight connections within 30s.
- HLD §1 executive-summary footer flips 🟡 → ✅.
