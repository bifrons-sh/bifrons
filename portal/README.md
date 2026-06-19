# Portal

Go HTTP service implementing the portal half of the HLD: credential lookup for proxies, grant lifecycle for users/admins, and audit ingestion.

**Status:** POC. Memory / SQLite / Postgres stores share one `store.Store`
interface, dual-gate approval workflow with on-behalf-of-T1 override, OIDC
session-cookie auth (with static-bearer fallback for automation), at-rest
encryption via SECRETBOX_KEY, audit ingestion + retention sweeper, and an
embedded React operator SPA under `/ui`. Not production-ready — see the
roadmap at the bottom of this file for the open gaps.

---

## Endpoints

### Proxy-facing (shared-secret via `X-Portal-Token`)

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/v1/auth` | Resolve `(username, proxy_type, backend_server)` → `AuthResponse` |
| POST | `/api/v1/audit/query` | Append batched query audit entries |

### User / admin (OIDC session cookie or static bearer token)

Grants:

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/grants` | List grants (filter: `user_id`, `backend_id`, `status`) |
| POST | `/api/v1/grants` | Create grant (lands PENDING unless `-auto-approve` is set) |
| GET | `/api/v1/grants/{id}` | Read grant |
| PATCH | `/api/v1/grants/{id}` | Update mutable fields (`reason` only — status changes are rejected here) — operator |
| DELETE | `/api/v1/grants/{id}` | Revoke grant — operator |
| POST | `/api/v1/grants/{id}/approve` | Approve (validator gate1 / operator gate2; dispatched by `approval_mode`) |
| POST | `/api/v1/grants/{id}/deny` | Deny grant |
| POST | `/api/v1/grants/{id}/claim` | Claim approved grant. Permanent → 200 creds. Ephemeral → emits a provision intent, waits ≤2s: 200 creds, else 202 + `Location` poll header (422 on worker failure). |
| GET | `/api/v1/grants/{id}/claim/status` | Poll the async ephemeral claim after a 202: 200 `{state, elapsed_ms}` while working, 200 creds on done, 422 on failure |
| GET | `/api/v1/provisioning/workers` | Admin: list provisioner-worker liveness heartbeats — one row per worker process (`worker_id`) with a per-backend-instance health map + `stale` flag |

Users & backends:

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/users` | List users |
| GET | `/api/v1/users/{id}` | Read user |
| POST | `/api/v1/users` | Create user — operator |
| PATCH | `/api/v1/users/{id}` | Update user — operator |
| GET | `/api/v1/backends` | List backends |
| POST | `/api/v1/backends` | Register backend — operator |
| POST | `/api/v1/backends/{id}/accounts` | Upsert backend account — operator |

Org hierarchy (validators, groups, memberships):

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/users/{id}/validator` | Read a user's validator |
| PUT | `/api/v1/users/{id}/validator` | Set validator — operator |
| DELETE | `/api/v1/users/{id}/validator` | Clear validator — operator |
| GET | `/api/v1/users/{id}/groups` | List a user's groups |
| GET | `/api/v1/groups` | List groups |
| POST | `/api/v1/groups` | Upsert group — operator |
| GET | `/api/v1/groups/{id}` | Read group |
| DELETE | `/api/v1/groups/{id}` | Delete group — operator |
| GET | `/api/v1/groups/{id}/members` | List group members |
| POST | `/api/v1/groups/{id}/members/{userId}` | Add member — operator |
| DELETE | `/api/v1/groups/{id}/members/{userId}` | Remove member — operator |

Session:

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/session` | Current session principal + IdP account URL for the SPA |

### Observability sidecar

`/healthz`, `/metrics`, `/version` on `--metrics-addr` (default `127.0.0.1:9095`).

---

## Configuration

| Flag | Default | Purpose |
|---|---|---|
| `-listen` | `127.0.0.1:8080` | API listen address |
| `-metrics-addr` | `127.0.0.1:9095` | Obs sidecar |
| `-proxy-token` | empty | Shared secret required on proxy endpoints (empty = no guard) |
| `-user-token` | empty | Bearer token for user endpoints (empty = no guard) |
| `-read-header-timeout` | 5s | HTTP hardening |
| `-read-timeout` | 10s | HTTP hardening |
| `-write-timeout` | 10s | HTTP hardening |
| `-shutdown-grace` | 10s | SIGTERM drain window |

---

## Bootstrap a working scenario

For the full demo (mysql + postgres + mongo + Keycloak + portal + proxies),
use the compose stack at the repo root:

```bash
docker compose -f dev/compose.yml up -d --build
bash dev/seed.sh
```

The raw-curl walkthrough below remains useful for a portal-only debug
session against an existing backend.

```bash
# Start portal
./bin/portal -listen 127.0.0.1:8080 -metrics-addr 127.0.0.1:9095

# Register a user
curl -X POST http://127.0.0.1:8080/api/v1/users \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice"}'
# → { "id": "u-...", ... }

# Register a backend (must match the proxy's -backend flag)
curl -X POST http://127.0.0.1:8080/api/v1/backends \
  -H 'Content-Type: application/json' \
  -d '{"name":"mongo-prod-01","type":"mongo","host":"127.0.0.1","port":27017}'
# → { "id": "b-...", ... }

# Upsert the shared backend account
curl -X POST http://127.0.0.1:8080/api/v1/backends/b-.../accounts \
  -H 'Content-Type: application/json' \
  -d '{"role":"app","username":"backendadmin","password":"backendSecret"}'

# Grant alice access (lands PENDING; pass -auto-approve on the portal for one-shot demos)
curl -X POST http://127.0.0.1:8080/api/v1/grants \
  -H 'Content-Type: application/json' \
  -d '{"user_id":"u-...","backend_addr":"127.0.0.1:27017","role":"app","database":"orders","credential_ttl":"4h","portal_password":"alicePassword"}'
# → { "id": "g-...", "portal_password" is NOT echoed (stripped) ... }

# Point the mongo proxy at the portal:
./bin/mongo-proxy -listen 127.0.0.1:37017 -backend 127.0.0.1:27017 \
  -auth-url http://127.0.0.1:8080/api/v1/auth

# Connect with alice / alicePassword
mongosh "mongodb://alice:alicePassword@127.0.0.1:37017/?authSource=admin"
```

---

## Gaps (roadmap)

Done since v0.1:
- SQLite + Postgres stores behind `store.Store` (memory still default).
- OIDC session-cookie auth (`/oidc/login`, `/oidc/callback`, `/oidc/logout`)
  with static-bearer fallback for automation.
- Tri-phase approval workflow (PENDING → VALIDATOR_APPROVED → APPROVED →
  ACTIVE) with per-backend `approval_mode` (`dual_strict` / `dual_or` /
  `validator_only`) and on-behalf-of-T1 override.
- React/Mantine operator SPA under `/ui` (see [`ui/`](ui/)).
- Auth-rate limiting per IP + per user (`PORTAL_AUTH_RATE_PER_IP/USER`).
- Audit retention + sweep (`PORTAL_AUDIT_RETENTION_DAYS`,
  `PORTAL_AUDIT_MAX_ENTRIES`, `PORTAL_AUDIT_SWEEP_INTERVAL`).
- At-rest encryption (XSalsa20-Poly1305 via SECRETBOX_KEY).
- Provisioning-worker split (`-ephemeral-accounts`): the portal emits
  `provision_intents` to its store and a separate `provisioner-worker`
  binary (the only holder of master/DBA creds) runs the DDL. Async `/claim`
  (200/202 + `/claim/status`); done-but-unclaimed grants are reconciled to
  ACTIVE by the sweeper; revoke/expire/orphan-sweep emit revoke intents.
  See [`../specs/phase-8-provisioning-worker.md`](../specs/phase-8-provisioning-worker.md).
- Worker liveness heartbeat: each worker beats one `provisioning_workers` row
  per process (`-heartbeat-interval` / `WORKER_HEARTBEAT_INTERVAL`, default 10s;
  `-heartbeat-probe` / `WORKER_HEARTBEAT_PROBE`, default true) carrying a
  per-backend-instance health map (distinct from the per-intent lease
  heartbeat). The portal surfaces them at `GET /api/v1/provisioning/workers`
  (admin), exposes a `portal_provision_workers{state}` gauge, and prunes stale
  rows in the sweeper. Worker DB role gains `INSERT, UPDATE on
  provisioning_workers`. Run the dev workers with `make dev-worker`.

Still open:
- `aws-sm://` / `vault://` secret-ref schemes for the worker (`env://`/`file://` shipped).
- Per-grant zero-knowledge encryption of the ephemeral result columns
  (ships with shared-key SecretBox).
- Policy enforcement on the proxy hot path (`allowed_dbs`, per-role command
  allow-lists).
- TLS on the API (+ mTLS from proxies — auth client doesn't yet send
  `X-Portal-Token`, see HLD §8 known limitation).
- Cluster mode + leader election for the sweeper.
- SPA test coverage (Vitest + RTL — deferred until UI surface stabilizes).
- Audit log compaction beyond row-count cap.
