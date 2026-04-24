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
│   ├── audit/             # Proxy-side audit batch shipper
│   ├── auth/              # Portal client (Lookup + SCRAM helpers, RSA+caching_sha2 helpers)
│   ├── config/            # Proxy-side flag registration
│   ├── logging/           # slog setup (TTY-aware)
│   ├── metrics/           # Prometheus registry (histograms + counters)
│   ├── obs/               # /healthz, /metrics, /version sidecar
│   ├── protocol/{mysql,postgres,mongo}/  # Protocol handlers
│   ├── proxy/             # Accept / conn-cap / graceful drain / relay / revoke poller
│   ├── ratelimit/         # Token-bucket primitives
│   └── tlsutil/           # TLS config builders + hot cert reloader
├── portal/
│   ├── cmd/portal/        # Portal binary + Dockerfile
│   ├── portal.go          # Public factory for embedders (NewHandler, WrapEncrypting, …)
│   ├── internal/
│   │   ├── api/           # HTTP handlers + middleware + SPA mount
│   │   ├── api/ui/        # Operator SPA (vanilla TS, strict CSP)
│   │   ├── authz/         # Principal + Authorize rulebook (per-action gate)
│   │   ├── config/        # Grouped Config sub-structs + flag registration
│   │   ├── domain/        # User, Backend, Grant, AuditEntry types + predicates
│   │   ├── entra/         # Graph API client (real + fake)
│   │   ├── ephemeral/     # Per-grant DB user provisioner (pg/mysql/mongo)
│   │   ├── lifecycle/     # Sweeper (grant expiry + session prune + orphan reap)
│   │   ├── notify/        # Notifier interface + webhook + Entra mail impls
│   │   ├── oidc/          # Provider + session stores (memory + SQL-backed)
│   │   ├── policy/        # Auth resolver + Entra trio policy
│   │   ├── secrets/       # env://, file:// secret refs + SecretBox cipher
│   │   ├── secrets/secretbox/  # XSalsa20-Poly1305 envelope (AAAB prefix)
│   │   └── store/         # Store interface + memory/sqlite/postgres impls + Encrypting decorator
│   └── README.md
├── e2e/                   # testcontainers-backed end-to-end tests
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
| mongo | SCRAM-SHA-256 | SCRAM-SHA-256 | `speculativeAuthenticate` stripped from hello. **Replica sets: clients MUST set `directConnection=true` on the URI.** The proxy fronts a single backend address and does NOT rewrite the `hosts`/`primary`/`me` fields in `hello` responses, so a driver in auto-discovery mode will try to dial the backend's real hostnames and bypass (or fail to reach) the proxy. Full topology proxying is planned, not implemented — see [`specs/phase-4-protocol-gaps.md`](specs/phase-4-protocol-gaps.md) §4.3b. Same applies to `readPreference=secondary`/`secondaryPreferred`: the proxy only fronts the primary. |
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
| `-client-tls-cb-required` (postgres only) | `false` | force SCRAM-SHA-256-PLUS (channel binding) on TLS client conns; rejects plain SCRAM |

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
- `POST /api/v1/grants/:id/approve|deny|claim` — dual-gate + claim
- `POST /api/v1/users`, `POST /api/v1/backends`, `POST /api/v1/backends/{id}/accounts` — admin seed endpoints

Storage is in-memory by default; sqlite + postgres impls also ship. Grant auto-approval on `POST /api/v1/grants` is a scaffold shortcut — real portal needs an approval workflow. See `portal/README.md` for the roadmap.

### Access request lifecycle

Grants now walk a tri-phase deadline:

```
PENDING ── validator-approve ─▶ VALIDATOR_APPROVED ── admin-approve ─▶ APPROVED ── /claim ─▶ ACTIVE ── ttl ─▶ EXPIRED
   │                                  │                                                                    ▲
   └─────────── deny / revoke ────────┴──────── unclaimed sweeper (validation/claim windows lapse) ────────┘
```

- **Phase 1 (validation window)** — `RequestExpiresAt` set at create. PENDING / VALIDATOR_APPROVED grants past this window are EXPIRED by the sweeper. Default 24h, override with `-validation-window` / `PORTAL_VALIDATION_WINDOW`.
- **Phase 2 (claim window)** — `ClaimExpiresAt` set when the second (admin) gate fires. APPROVED grants past this window are EXPIRED. Default 1h, override with `-claim-window` / `PORTAL_CLAIM_WINDOW`.
- **Phase 3 (credential TTL)** — `ExpiresAt` set at `/claim` time. ACTIVE grants past this are EXPIRED + ephemeral creds revoked. Default 1h, override with `-credential-ttl` / `PORTAL_CREDENTIAL_TTL`.

The `POST /api/v1/grants/:id/claim` endpoint returns the credentials once: `{backend_user, backend_pass, portal_password, expires_at}`. Re-claims within ACTIVE return the same payload idempotently; after `ExpiresAt` it's 410 Gone. Owner-only (the requester) with admin override.

### Gate2 (T2-tier) reachability

When Entra is enabled the portal needs a way to notify gate2-eligible
approvers once gate1 (T1 / validator) fires. Recipients are resolved
**per backend** from `backends.t2_group_slug` — the slug of a portal-
internal group whose members are notified and authorised to clear
gate2 for that backend. The group is populated by `entra-sync`; members
are resolved at notify-time via the local store, no live Graph call.

A reachability fallback mailbox is appended to every gate2 send
regardless of the backend's group, as a safety net for misconfigured
backends:

- `-t2-mailbox` / `PORTAL_T2_MAILBOX` — single mailbox appended to every
  gate2 notification.

Without this fallback, the portal exits 2 at boot when Entra is enabled.

Per-backend rather than global because different backends typically have
different admin tiers (DBA team for prod, platform team for staging,
etc.). See specs/phase-7-validation-ui.md §7.8.1 for the full model.

### Static bearer vs dual-gate

The `-user-token` / `PORTAL_USER_TOKEN` static bearer is a privileged operator credential. Its behaviour depends on whether Entra is wired:

- **Entra not configured** (bootstrap / automation mode): the static bearer satisfies BOTH gates of `/approve`, so a single scripted call can walk PENDING → VALIDATOR_APPROVED → APPROVED. This preserves pre-dual-gate automation paths.
- **Entra configured and the grant carries a `ValidatorSubject`**: the static bearer is demoted to the admin half only. The validator half MUST come from an OIDC session whose `sub` equals `ValidatorSubject`. This keeps the four-eyes guarantee even if a single bearer token is shared across tooling.

Deployments that want a strict two-actor gate regardless of automation posture should set `-user-token=""` and rely exclusively on OIDC admin + validator sessions.

### At-rest secret encryption

Backend-account passwords and per-grant portal / ephemeral passwords are encrypted at rest when `-secretbox-key-env` (default `SECRETBOX_KEY`) points to an env var holding a base64-encoded 32-byte key. The envelope is XSalsa20-Poly1305 via libsodium (`crypto_secretbox`), prefixed with a 3-byte version tag `0x00 0x00 0x01` whose base64 form is the recognisable `AAAB` prefix on every stored value.

```bash
# Generate a key once per environment (keep safe!).
head -c 32 /dev/urandom | base64
# Set it before starting the portal.
export SECRETBOX_KEY='…base64 32 bytes…'
./bin/portal -store postgres://...
```

Without a key the portal refuses to boot. The only way to start without encryption is to set `-secretbox-key-env=""` explicitly, which logs a loud `at_rest_encryption_disabled` warning and stores those secrets in plaintext — acceptable for local dev, **not** for shared environments. A read that finds a column without the SecretBox version header fails closed: operators rotating or swapping keys must re-encrypt existing rows, not silently return plaintext.

### Proxy ↔ portal trust boundary (known limitation)

The three proxies authenticate to the portal with a single shared `-proxy-token`. A leaked proxy-token lets any network-reachable caller query `/api/v1/auth` for any `(username, backend)` and harvest the portal-side password. Engine-level cross-checks catch obvious mismatches (`req.ProxyType` must equal `backend.Type`), but token possession is the only binding.

For production: front the portal with mTLS and pin a per-proxy client cert, or split the single proxy-token into per-proxy-type tokens. This is tracked as a deferred hardening for the POC and is called out here so operators don't rely on the shared token in shared-trust topologies.

The portal also exposes a Go API (`portal.NewHandler`, `portal.NewMemoryStore`) for embedding in tests or other processes. `e2e/portal_mongo_test.go` uses this to run the full chain (real MongoDB ↔ real proxy ↔ real portal) in a single test.

---

## Contributing

- Keep comments to *why*, not *what* — see `CLAUDE.md` if present.
- `make race` must pass before committing.
- E2E changes must pass against fresh containers (`make e2e`).
