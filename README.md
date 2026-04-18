# access-portal / poc-proxies

Protocol-aware proxies (MySQL, PostgreSQL, MongoDB) that sit between database clients and backend servers, authenticate users against a central **portal**, and re-map connections to shared backend accounts.

See [`HLD.md`](HLD.md) for the full design. Implementation status is tracked there per section.

---

## Layout

```
.
├── cmd/
│   ├── mysql-proxy/       # MySQL protocol proxy
│   ├── postgres-proxy/    # PostgreSQL protocol proxy
│   └── mongo-proxy/       # MongoDB protocol proxy
├── internal/
│   ├── auth/              # Portal client (Lookup + SCRAM helpers) — shared by proxies and portal
│   ├── config/            # Shared flag registration
│   ├── obs/               # /healthz, /metrics, /version sidecar
│   ├── proxy/             # Generic accept / conn-cap / graceful drain / relay helpers
│   ├── protocol/{mysql,postgres,mongo}/  # Protocol handlers
│   └── tlsutil/           # Server + client TLS config builders
├── portal/
│   ├── cmd/portal/        # Portal binary
│   ├── portal.go          # Public factory (NewHandler/NewMemoryStore) for embedders
│   ├── internal/
│   │   ├── api/           # HTTP handlers + middleware
│   │   ├── config/        # Flags
│   │   ├── domain/        # User, Backend, Grant, AuditEntry types
│   │   ├── policy/        # LookupRequest → AuthResponse resolver
│   │   └── store/         # Store interface + in-memory impl
│   └── README.md
├── e2e/                   # testcontainers-backed end-to-end tests (incl. real portal + real mongo)
├── HLD.md                 # High-level design (§ status table up-to-date)
└── Makefile
```

---

## Getting started

### Prerequisites

- Go 1.26+ (`go.mod` pins `1.26.2`)
- Docker (for e2e tests)

### Build

```bash
make build           # all binaries land in bin/  (proxies + portal)
make proxies         # just the 3 proxies
make portal          # just the portal
```

### Test

```bash
make test            # unit
make race            # unit with race detector
make e2e             # testcontainers-backed end-to-end
make cover           # merged unit + e2e coverage (requires gocovmerge)
```

### Run a proxy locally

Each proxy accepts the same core flags. Example against a local MySQL:

```bash
./bin/mysql-proxy \
  -listen 127.0.0.1:13306 \
  -backend 127.0.0.1:3306 \
  -max-conns 1024 \
  -handshake-timeout 15s \
  -idle-timeout 5m \
  -metrics-addr 127.0.0.1:9091
```

Then connect with any MySQL client to `127.0.0.1:13306`.

### Auth re-mapping

All three proxies share the same pattern: pass `-auth-url` pointing at a portal that implements `POST /api/v1/auth`, and the proxy will authenticate clients against portal-issued credentials before opening a backend connection with the mapped role.

```bash
# Mongo
./bin/mongo-proxy -listen 127.0.0.1:37017 -backend 127.0.0.1:27017 \
  -auth-url http://127.0.0.1:8080/api/v1/auth

# MySQL (mysql_native_password both directions)
./bin/mysql-proxy -listen 127.0.0.1:13306 -backend 127.0.0.1:3306 \
  -auth-url http://127.0.0.1:8080/api/v1/auth

# PostgreSQL (SCRAM-SHA-256 by default; cleartext for legacy clients)
./bin/postgres-proxy -listen 127.0.0.1:15432 -backend 127.0.0.1:5432 \
  -auth-url http://127.0.0.1:8080/api/v1/auth \
  -client-auth-method scram      # or cleartext
```

Per-protocol auth methods:

| Proxy | Client ↔ Proxy | Proxy ↔ Backend | Notes |
|---|---|---|---|
| mongo | SCRAM-SHA-256 | SCRAM-SHA-256 | `speculativeAuthenticate` stripped from hello |
| mysql | `mysql_native_password` | `mysql_native_password` | **Backend role must be provisioned with `IDENTIFIED WITH mysql_native_password`** — the proxy does not speak `caching_sha2_password` on the backend side |
| postgres | SCRAM-SHA-256 (default) or cleartext | SCRAM-SHA-256 (or immediate AuthenticationOk for `trust`/peer HBA) | Cleartext safe only over TLS |

The portal returns `{password, backend_user, backend_pass, ...}`; the proxy authenticates the client against `password`, then opens a backend session with `backend_user`/`backend_pass`. **Database-level authorization (what the role may read/write/create) is the backend's responsibility via `GRANT`/`REVOKE`; the proxy does not inspect SQL or command targets for access control.**

---

## Operational flags

| Flag | Default | Purpose |
|---|---|---|
| `-listen` | proto-default | proxy listen address |
| `-backend` | proto-default | backend DB address |
| `-client-tls`, `-client-tls-cert`, `-client-tls-key` | off | terminate TLS from clients |
| `-client-tls-ca`, `-client-tls-required` | — | optional mTLS from clients |
| `-backend-tls`, `-backend-tls-ca`, `-backend-tls-cert`, `-backend-tls-key`, `-backend-tls-insecure` | off | TLS to backend |
| `-max-conns` | 1024 | global connection cap (0 = unlimited) |
| `-handshake-timeout` | 15s | deadline for auth/handshake phase |
| `-idle-timeout` | 5m | rolling read deadline during relay |
| `-backend-dial-timeout` | 5s | backend dial deadline |
| `-shutdown-grace-period` | 30s | graceful drain window on SIGINT/SIGTERM |
| `-metrics-addr` | 127.0.0.1:9091 | sidecar for `/healthz` + `/metrics` + `/version` |
| `-auth-url` (all 3 proxies) | empty | portal URL; enables auth re-mapping |
| `-client-auth-method` (postgres only) | `scram` | `scram` (default) or `cleartext` for legacy clients |

---

## Observability

Each proxy exposes a sidecar on `-metrics-addr`:

- `GET /healthz` — returns 200 once listener is ready, 503 before
- `GET /metrics` — Prometheus text format
  - `proxy_uptime_seconds`
  - `proxy_connections_accepted_total`
  - `proxy_connections_rejected_total`
  - `proxy_connections_active`
  - `proxy_build_info{version,commit,built,builder}`
- `GET /version` — plain-text build metadata

Build-time metadata is injected via `-ldflags -X main.Version=...` (see `Makefile`).

---

## Security notes

- **Secrets in logs** — `auth.AuthResponse` redacts password fields via `slog.LogValuer`; Mongo `saslStart`/`saslContinue`/`createUser`/`updateUser` bodies are redacted in query logs.
- **TLS** — TLS 1.2 minimum on both directions; `-backend-tls-insecure` exists but is explicitly user-gated.
- **mTLS** — listener can require and verify client certs via `-client-tls-ca -client-tls-required`.
- **Auth caps** — SCRAM / auth-phase relay loops are bounded to prevent compromised backends from spinning the proxy.
- **Redaction contract** — the proxy NEVER logs the plaintext of `payload` fields in SCRAM exchanges.

---

## Portal

The portal is under [`portal/`](portal/README.md) and ships as `bin/portal`. It implements the HLD §5.1 contract:

- `POST /api/v1/auth` — credential lookup keyed by `(username, proxy_type, backend_server)`; returns `password, backend_user, backend_pass, grant_id, role, allowed_dbs, expires_at, connection_ttl_seconds`
- `POST /api/v1/audit/query` — batched query audit ingestion (202 on accept)
- `GET/POST/PATCH/DELETE /api/v1/grants` — grant lifecycle
- `POST /api/v1/users`, `POST /api/v1/backends`, `POST /api/v1/backends/{id}/accounts` — admin seed endpoints

Storage is in-memory. Grant auto-approval on `POST /api/v1/grants` is a scaffold shortcut — real portal needs an approval workflow. See `portal/README.md` for the roadmap.

The portal also exposes a Go API (`portal.NewHandler`, `portal.NewMemoryStore`) for embedding in tests or other processes. `e2e/portal_mongo_test.go` uses this to run the full chain (real MongoDB ↔ real proxy ↔ real portal) in a single test.

---

## Contributing

- Keep comments to *why*, not *what* — see `CLAUDE.md` if present.
- `make race` must pass before committing.
- E2E changes must pass against fresh containers (`make e2e`).
