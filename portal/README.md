# Portal (scaffold)

Go HTTP service implementing the portal half of the HLD: credential lookup for proxies, grant lifecycle for users/admins, and audit ingestion.

**Status:** scaffold. In-memory store, minimal policy engine, single static bearer token for user endpoints. Not production-ready.

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
| POST | `/api/v1/grants` | Create grant (scaffold auto-approves) |
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

# Grant alice access (scaffold auto-approves)
curl -X POST http://127.0.0.1:8080/api/v1/grants \
  -H 'Content-Type: application/json' \
  -d '{"user_id":"u-...","backend_addr":"127.0.0.1:27017","role":"app","database":"orders","requested_duration":"4h","portal_password":"alicePassword"}'
# → { "id": "g-...", "portal_password" is NOT echoed (stripped) ... }

# Point the mongo proxy at the portal:
./bin/mongo-proxy -listen 127.0.0.1:37017 -backend 127.0.0.1:27017 \
  -auth-url http://127.0.0.1:8080/api/v1/auth

# Connect with alice / alicePassword
mongosh "mongodb://alice:alicePassword@127.0.0.1:37017/?authSource=admin"
```

---

## Gaps (roadmap)

- Persistent store (SQLite, then Postgres) behind the same `store.Store` interface
- Real user auth (session cookies, JWT, OIDC)
- Policy enforcement (`allowed_dbs`, per-role command allow-lists)
- TLS on the API (+ mTLS from proxies)
- Rate limiting / lockout on auth failures
- Grant approval workflow (request → pending → approve/deny)
- Web UI
- Audit log retention + compaction
- Cluster mode + leader election for grant state
