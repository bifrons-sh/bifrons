# Phase 6 — future / nice-to-have

Items the POC doesn't need but every mature access-portal product eventually grows. Listed here so they don't get lost; expect to revisit priorities after v1.0 lands.

Estimated: **~10-15 dev-days** total if all shipped.

---

## 6.1 Proxy-to-backend connection pooling

**Status:** ⬜

### Why
Today every client connection opens a fresh backend connection. At scale this either:
- Exhausts the backend's `max_connections` — DB ops hates us.
- Wastes PBKDF2 cost on the backend (same role re-authenticates each time).

Pooling per-grant lets N client connections share a small pool of backend connections keyed by `backend_user`.

### Risks
- Transaction correctness: pinning a client conn to a backend conn until `COMMIT`/`ROLLBACK`.
- Prepared-statement state: MySQL / PG drivers create server-side prepared statements; sharing breaks them.
- Session state: `SET search_path`, `USE db`, session vars leak between tenants if we multiplex.

Approaches:
- **Session pooling (safest):** 1:1 for the connection lifetime; just amortise TCP handshake cost via pre-warming, not much to gain.
- **Transaction pooling (pgbouncer-style):** pin per-transaction. Most apps fit. Needs session-state-aware re-init.
- **Statement pooling (pgbouncer lowest mode):** pin per-statement. Breaks almost all driver features; not worth it.

### Scope
Transaction pooling only. Postgres first (the community has the most experience with it), then decide on MySQL/Mongo based on demand.

### Rough effort
5 dev-days for the PG case, easily double for making it rock-solid across drivers.

---

## 6.2 Portal web UI

**Status:** ⬜

### Why
Humans don't want to `curl -X POST /api/v1/grants`.

### Scope
- Lightweight HTMX + plain Go templates, *or* a small React SPA. Pick based on team taste — HTMX matches the "no heavy deps" ethos of the rest of the project.
- Pages:
  - Login (kicks OIDC flow).
  - Request grant (form).
  - Pending approvals (admin).
  - My active grants + revoke button.
  - Audit log browser (depends on 6.3).
- Admin pages for user / backend / backend-account CRUD.

Out of scope:
- Multi-tenancy UI.
- Theming / white-labelling.

### Rough effort
5-10 dev-days depending on stack choice.

---

## 6.3 Audit read API

**Status:** ⬜

### Why
`POST /api/v1/audit/query` ingests audit entries. There's no read side: operators can't browse what the portal stored.

### Scope
- `GET /api/v1/audit/query?user=&grant_id=&since=&until=&limit=` — filters directly map to `store.AuditFilter`.
- Admin-only (OIDC admin claim).
- Pagination via `?cursor=<timestamp+id>` rather than offset.

### Rough effort
0.5 dev-day.

---

## 6.4 `janusctl` CLI

**Status:** ⬜

### Why
The portal's API is fine for automation but humans using `curl` make mistakes (missing headers, wrong JSON). A small CLI would:
- Handle the OIDC flow (token file under `~/.config/janusctl/token.json`).
- Pretty-print grants, users, backends.
- Do common operator tasks: `janusctl grant list`, `janusctl grant approve <id>`, `janusctl grant revoke <id>`, `janusctl emergency-grant --user=alice --role=dba --backend=orders-db --duration=1h`.

### Scope
- `cmd/janusctl/main.go` with `cobra` or flag-based subcommands (flag-only keeps the dep tree lean).
- Embedded OIDC device-code flow if IdP supports it, else redirect-to-browser.
- Config file + per-command flags, standard 12-factor layering.

Out of scope:
- Tab completion (trivial to add later).
- TUI / interactive mode.

### Rough effort
1-2 dev-days.

---

## 6.5 Cold-storage audit export

**Status:** ⬜

### Why
Retention (phase 1.3) drops old audit entries. Compliance often wants them kept for years in cheaper storage.

### Scope
- Periodic export job: tail the audit table, write out as NDJSON or Parquet batches to S3 / GCS / local filesystem.
- Signed URLs + integrity hashes per batch.
- Read-side in the portal stays transparent — it only sees the hot window.

### Rough effort
2 dev-days.

---

## 6.6 Multi-backend routing from a single proxy

**Status:** ⬜

### Why
Today each proxy process serves one `-backend`. For a big fleet this means process-per-backend. Would be nicer: one proxy, multiple backends, routing via `backend_server` hint in the auth response.

### Scope
- Proxy reads a **list** of backends at startup.
- Auth lookup's response `backend_server` field steers the dial to the right one.
- All-SNI-style single-listener still works; clients don't change.

### Caveat
Major architectural change, touches the proxy framework's `dialBackend` closure. Consider whether the UX win justifies the complexity vs just running N processes.

### Rough effort
3-5 dev-days.

---

## 6.7 Cluster-mode portal with leader election

**Status:** ⬜

### Why
Approval workflows want atomic semantics (no two admins approve the same grant concurrently with different decisions). Background sweepers shouldn't run N times in parallel.

### Scope
- Lease-based leader election (etcd, Consul, or DB-row lease).
- Approval + sweepers gated on leadership.
- API serving is still multi-leader (reads + writes that are naturally idempotent).

### Rough effort
2-3 dev-days.

---

## Deliberately out-of-scope even for future

- Multi-region active-active — if needed, run one system per region with separate portals; federation is not on the roadmap.
- Custom DB auth beyond OIDC for portal users (SAML, LDAP direct, client certs).
- Proxy-side query rewriting (masking PII, adding tenant filters) — this is an ORM / policy-engine responsibility, not ours.
- Custom-built "replacement" for pgbouncer / ProxySQL. Our goal is access governance, not connection infrastructure.
