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

### User / admin (bearer token)

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/grants` | List grants (filter: `user_id`, `backend_id`, `status`) |
| POST | `/api/v1/grants` | Create grant (lands PENDING unless `-auto-approve` is set) |
| GET | `/api/v1/grants/:id` | Read grant |
| PATCH | `/api/v1/grants/:id` | Update status (`APPROVED`, `DENIED`, `REVOKED`) |
| DELETE | `/api/v1/grants/:id` | Revoke grant |
| POST | `/api/v1/users` | Admin: create user |
| POST | `/api/v1/backends` | Admin: register backend |
| POST | `/api/v1/backends/{id}/accounts` | Admin: upsert backend account |

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

Still open:
- Policy enforcement on the proxy hot path (`allowed_dbs`, per-role command
  allow-lists).
- TLS on the API (+ mTLS from proxies — auth client doesn't yet send
  `X-Portal-Token`, see HLD §8 known limitation).
- Cluster mode + leader election for the sweeper.
- SPA test coverage (Vitest + RTL — deferred until UI surface stabilizes).
- Audit log compaction beyond row-count cap.
