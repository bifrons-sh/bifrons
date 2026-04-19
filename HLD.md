---

# Database Access Portal -- High-Level Design Document

**Version:** 1.2
**Date:** 2026-04-18
**Status:** Draft — partial implementation in-tree
**Authors:** Engineering

---

## Implementation Status (2026-04-18)

Sections are annotated below with ✅ / 🟡 / ⬜ meaning:

- ✅ **Implemented** — shipped in this tree and covered by tests
- 🟡 **Partial** — some code in place; gaps called out inline
- ⬜ **Planned** — designed but not yet built

| Section | Status | Notes |
|---|---|---|
| §1 Executive Summary | 🟡 | All 3 proxies now do auth re-mapping; portal still scaffold |
| §2 System Context | ✅ | |
| §3 Component Architecture — proxies | ✅ | Mongo + MySQL + PostgreSQL: auth re-mapping + query logging |
| §3 Component Architecture — portal | 🟡 | Scaffolded: `/api/v1/auth`, `/api/v1/audit/query`, grant CRUD, in-memory store |
| §4 Authentication Flow — Mongo | ✅ | SCRAM-SHA-256 client + backend; speculativeAuth stripped. **Replica sets: clients must set `directConnection=true`; full topology proxying (rewriting `hosts`/`primary`/`me` in `hello`) is planned, not implemented — see [`specs/phase-4-protocol-gaps.md`](specs/phase-4-protocol-gaps.md) §4.3b.** |
| §4 Authentication Flow — MySQL | ✅ | mysql_native_password client; backend supports mysql_native_password and caching_sha2_password (fast-auth + RSA full-auth fallback, TLS short-circuit); AuthSwitch forced if client prefers another plugin |
| §4 Authentication Flow — PostgreSQL | ✅ | SCRAM-SHA-256 client (cleartext fallback for legacy clients) + SCRAM backend; `CancelRequest` handled |
| §4b DB restriction enforcement | — | **Out of proxy scope.** Enforced backend-side via role `GRANT`/`REVOKE` (see note below) |
| §5 Portal API — `POST /api/v1/auth` | ✅ | Request body matches contract; response fields optional via `omitempty` |
| §5 Portal API — `POST /api/v1/audit/query` | 🟡 | Portal endpoint stubbed; proxy-side shipping not yet wired |
| §5 Portal API — Grant CRUD | 🟡 | In-memory store; no auth on user-facing endpoints yet |
| §6 Data Model | 🟡 | In-memory implementation; Postgres persistence planned |
| §7 Deployment Architecture | ⬜ | No Dockerfile / Helm / systemd committed |
| §8 Security Considerations — TLS/mTLS | ✅ | Client + backend TLS, optional mTLS |
| §8 Security Considerations — secret handling | ✅ | `AuthResponse.LogValue` redacts; SASL bodies redacted in Mongo logs; MySQL/PG auth paths never log plaintext |
| §8 Security Considerations — rate limiting | ⬜ | Only global `MaxConns` cap today |
| §9 Failure Modes | 🟡 | Deadlines, graceful shutdown, backend close-on-done, retry w/ jitter — yes; circuit breaker — no |
| §10 Observability | 🟡 | `/healthz`, `/metrics`, `/version` on obs sidecar; no OTel, no latency histograms |
| §11 Open Questions | n/a | |

### Auth rate ceiling

Client-side SCRAM-SHA-256 (MongoDB + PostgreSQL) derives stored credentials via PBKDF2 at `auth.DefaultSCRAMIters` (15 000) on every new connection. On commodity x86 this is ~8–10 ms of CPU per auth. A single proxy process is therefore effectively capped at ~100 auths/sec/core for the SCRAM paths; sustained heavy connect churn (CI, flaky app pools) needs either horizontal scaling or front-loaded connection pooling. The mysql_native_password path is not affected (cost ≈ two SHA-1s).

### §4b note — DB restriction is backend-side

Earlier drafts described proxy-side inspection of `COM_INIT_DB`/`USE`, PG startup `database`, and Mongo `$db` to restrict which logical databases a session could touch. This has been dropped: the portal declares a specific backend role to each session (optionally one role per logical DB). The database itself enforces privileges against that role via `GRANT`/`REVOKE`. The proxy is an **identity gateway**; the backend is the **authorization gate**. Rotating access = rotating grants on the role, no proxy change needed.

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [System Context](#2-system-context)
3. [Component Architecture](#3-component-architecture)
4. [Authentication Flow](#4-authentication-flow)
5. [Portal API Contract](#5-portal-api-contract)
6. [Data Model](#6-data-model)
7. [Deployment Architecture](#7-deployment-architecture)
8. [Security Considerations](#8-security-considerations)
9. [Failure Modes and Resilience](#9-failure-modes-and-resilience)
10. [Observability](#10-observability)
11. [Open Questions and Future Work](#11-open-questions-and-future-work)

---

## 1. Executive Summary

The Database Access Portal is a system that provides controlled, audited, time-bound access to database servers (MySQL, PostgreSQL, MongoDB). It decouples user identity from backend database credentials via protocol-aware proxies that authenticate users against a central portal and transparently remap connections to shared backend accounts.

**Design principles:**

- **Zero standing access.** Users have no database credentials by default. Access is granted on request, scoped by role and database, and expires automatically.
- **Stateless enforcement.** Proxies hold no user configuration. Every connection is authorized in real time via the portal API.
- **Instant revocation.** Removing a grant in the portal takes effect on the next connection attempt -- no proxy restart, no config push.
- **Full auditability.** Every query passes through a proxy that logs it in structured JSON. Every grant/revoke action is recorded in the portal.

**Current state (2026-04-18):** Three protocol-specific proxies (MySQL, PostgreSQL, MongoDB) exist as working POC code in Go under `cmd/*-proxy`. The MongoDB proxy has full auth-remapping implemented and end-to-end tested. MySQL and PostgreSQL proxies currently operate in pass-through mode (relay handshake to backend) and need auth-remapping added. The portal component is scaffolded under `portal/` with in-memory storage and the proxy-facing API implemented; web UI and persistent storage remain to be built.

---

## 2. System Context

```
+------------------------------------------------------------------+
|                         OPERATORS / ADMINS                        |
|   (approve grants, configure policies, view audit logs)          |
+------------------------------+-----------------------------------+
                               |
                          HTTPS (UI/API)
                               |
                               v
+------------------------------------------------------------------+
|                                                                  |
|                       ACCESS PORTAL                              |
|                                                                  |
|  HTTP API + Web UI + Grant Store + Audit Log + Policy Engine     |
|                                                                  |
+------+------------------+-------------------+--------------------+
       |                  |                   |
   POST /auth         POST /auth          POST /auth
   (internal)         (internal)          (internal)
       |                  |                   |
       v                  v                   v
 +-----------+     +-------------+     +------------+
 |  MySQL    |     | PostgreSQL  |     |  MongoDB   |
 |  Proxy    |     |   Proxy     |     |   Proxy    |
 +-----------+     +-------------+     +------------+
       |                  |                   |
   MySQL wire         PG wire            MongoDB wire
   protocol           protocol           protocol
       |                  |                   |
       v                  v                   v
 +-----------+     +-------------+     +------------+
 |  MySQL    |     | PostgreSQL  |     |  MongoDB   |
 |  Server   |     |   Server    |     |   Server   |
 +-----------+     +-------------+     +------------+
       ^                  ^                   ^
       |                  |                   |
+------+------------------+-------------------+--------------------+
|                                                                  |
|                      DATABASE USERS                              |
|  (connect via native DB clients: mysql, psql, mongosh, ORMs)    |
|                                                                  |
+------------------------------------------------------------------+
```

**Actors:**

| Actor | Interaction | Protocol |
|---|---|---|
| Database User | Connects to proxy with portal-issued credentials using standard DB clients | MySQL/PG/Mongo wire protocol |
| Admin/Operator | Approves/denies grants, views audit logs, manages policies | HTTPS (Portal UI/API) |
| Automated Systems | Request access programmatically, integrate with CI/CD | HTTPS (Portal API) |

**External systems:**

| System | Integration | Purpose |
|---|---|---|
| Identity Provider (future) | OIDC/SAML via Portal | User identity verification |
| SIEM/Log aggregator | Structured JSON logs from proxies + portal | Audit trail |
| Alerting system | Prometheus metrics from proxies + portal | Operational monitoring |

---

## 3. Component Architecture

```
+=========================================================================+
|                            ACCESS PORTAL                                 |
|                                                                          |
|  +------------------+  +------------------+  +---------------------+     |
|  |   HTTP API       |  |   Web UI         |  |  Background Jobs   |     |
|  |                  |  |  (SPA or SSR)    |  |                    |     |
|  |  /auth (proxy)   |  |                  |  |  - Grant expiry    |     |
|  |  /grants (CRUD)  |  |  Grant requests  |  |  - Audit rotation  |     |
|  |  /audit (read)   |  |  Approvals       |  |  - Metrics export  |     |
|  |  /users (CRUD)   |  |  Audit viewer    |  |                    |     |
|  |  /backends (CRUD)|  |  Backend mgmt    |  |                    |     |
|  |  /health         |  |                  |  |                    |     |
|  +--------+---------+  +------------------+  +---------------------+     |
|           |                                                              |
|  +--------v-----------------------------------------------------------+  |
|  |                       SERVICE LAYER                                |  |
|  |                                                                    |  |
|  |  GrantService    AuthService    AuditService    BackendService     |  |
|  +--------+-----------------------------------------------------------+  |
|           |                                                              |
|  +--------v-----------------------------------------------------------+  |
|  |                     PERSISTENCE (SQLite / PostgreSQL)              |  |
|  |                                                                    |  |
|  |  users | grants | audit_log | backend_servers | backend_accounts  |  |
|  +--------+-----------------------------------------------------------+  |
+=========================================================================+

+=========================================================================+
|                     PROXY (one per DB type)                              |
|                                                                          |
|  +------------------+  +-------------------+  +--------------------+     |
|  | TCP Listener     |  | Protocol Handler  |  | Auth Client        |     |
|  |                  |  |                   |  |                    |     |
|  | - Accept conn    |  | - Wire protocol   |  | - POST /auth      |     |
|  | - Client TLS     |  | - Auth intercept  |  | - Cache (optional)|     |
|  | - Graceful       |  | - Query parsing   |  | - Retry/timeout   |     |
|  |   shutdown       |  | - DB restriction  |  |                    |     |
|  +--------+---------+  +---------+---------+  +---------+----------+     |
|           |                      |                      |                |
|  +--------v----------------------v----------------------v-----------+    |
|  |                         RELAY ENGINE                              |   |
|  |                                                                   |   |
|  |  - Bidirectional byte relay                                       |   |
|  |  - Client->backend: parse + inspect + log + forward               |   |
|  |  - Backend->client: passthrough                                   |   |
|  |  - Connection TTL enforcement                                     |   |
|  |  - Half-close propagation                                         |   |
|  +-------------------------------------------------------------------+   |
+=========================================================================+
```

### 3.1 Component Responsibilities

**Portal:**

| Sub-component | Responsibility |
|---|---|
| HTTP API (`/auth`) | Internal endpoint called by proxies. Returns backend credentials or 401. |
| HTTP API (`/grants`) | CRUD for access grants. Supports request/approve/deny workflow. |
| HTTP API (`/audit`) | Read-only access to audit log. Supports filtering by user, database, time range. |
| HTTP API (`/backends`) | CRUD for backend database servers and their well-known accounts. |
| HTTP API (`/users`) | User management. Initially simple local users; later OIDC integration. |
| Web UI | Human interface for requesting access, approving grants, viewing audit logs. |
| Grant Expiry Job | Periodically marks expired grants as inactive. |
| Policy Engine (future) | Auto-approve rules based on user attributes, time-of-day, etc. |

**Proxy (per DB type):**

| Sub-component | Responsibility | POC status |
|---|---|---|
| TCP Listener (`proxy.Server`) | Accepts TCP connections, optional client-facing TLS, graceful shutdown with drain timeout. | Implemented |
| Protocol Handler (`{mysql,postgres,mongo}.Handler`) | Protocol-specific wire parsing, auth interception, query logging. | Implemented (auth remap in Mongo only) |
| Auth Client (`auth.Client`) | HTTP client to portal `/auth` endpoint. 5s timeout. | Implemented |
| TLS Util (`tlsutil`) | Builds TLS configs for both listener-side and dialer-side connections. | Implemented |
| Relay Engine (`proxy.Relay`) | Bidirectional byte copy with optional per-chunk inspection callback. | Implemented |
| Config (`config.Config`) | CLI flags for listen addr, backend addr, client TLS, backend TLS. | Implemented |

### 3.2 Interfaces

```
+----------+         POST /auth              +---------+
|  Proxy   | ----------------------------->  | Portal  |
|          | <-----------------------------  |         |
+----------+  {password, backend_user,       +---------+
              backend_pass, allowed_dbs}
              or 401

+----------+     DB wire protocol            +---------+
|  Client  | ----------------------------->  |  Proxy  |
|  (mysql, | <-----------------------------  |         |
|  psql,   |     (relayed from backend)      |         |
|  mongosh)|                                 +---------+

+----------+     DB wire protocol            +---------+
|  Proxy   | ----------------------------->  | Backend |
|          | <-----------------------------  |   DB    |
+----------+   (backend creds from portal)   +---------+

+----------+     HTTPS                       +---------+
|  Admin   | ----------------------------->  | Portal  |
|  / User  | <-----------------------------  | (UI/API)|
+----------+                                 +---------+
```

---

## 4. Authentication Flow

### 4.1 Grant Lifecycle

```
  User                 Portal                  Admin
   |                     |                       |
   |  POST /grants       |                       |
   |  {db: "prod-orders",|                       |
   |   role: "app"}      |                       |
   |-------------------->|                       |
   |                     |  Grant created        |
   |                     |  status: PENDING      |
   |                     |                       |
   |                     |  Notification ------->|
   |                     |                       |
   |                     |  PATCH /grants/:id    |
   |                     |  {status: APPROVED,   |
   |                     |   expires: +4h}       |
   |                     |<----------------------|
   |                     |                       |
   |  Grant approved     |                       |
   |  (notification)     |                       |
   |<--------------------|                       |
   |                     |                       |
   |  Can now connect    |                       |
   |  to proxy           |                       |
```

### 4.2 Connection Auth Flow (per connection)

```
  DB Client           Proxy                Portal             Backend DB
     |                  |                    |                    |
     |  TCP connect     |                    |                    |
     |----------------->|                    |                    |
     |                  |                    |                    |
     |  [Protocol-specific client auth begins]                   |
     |                  |                    |                    |
     |  (MySQL: proxy sends handshake, receives auth response)   |
     |  (PG: proxy receives startup, handles SSLRequest)         |
     |  (Mongo: proxy intercepts saslStart in SCRAM exchange)    |
     |                  |                    |                    |
     |  Username +      |                    |                    |
     |  password        |                    |                    |
     |  extracted       |                    |                    |
     |                  |                    |                    |
     |                  | POST /auth         |                    |
     |                  | {username: "alice"} |                    |
     |                  |------------------->|                    |
     |                  |                    |                    |
     |                  |    200 OK          |                    |
     |                  |    {password:       |                    |
     |                  |     "alicePass",   |                    |
     |                  |     backend_user:   |                    |
     |                  |     "app_user",    |                    |
     |                  |     backend_pass:   |                    |
     |                  |     "backendS3cr", |                    |
     |                  |     allowed_dbs:    |                    |
     |                  |     ["orders"]}    |                    |
     |                  |<-------------------|                    |
     |                  |                    |                    |
     |  Proxy verifies  |                    |                    |
     |  client password |                    |                    |
     |  matches portal  |                    |                    |
     |  password        |                    |                    |
     |                  |                    |                    |
     |  [If match: complete client auth successfully]             |
     |  [If mismatch: reject client with auth error]             |
     |                  |                    |                    |
     |                  | TCP connect + auth |                    |
     |                  | (backend_user /    |                    |
     |                  |  backend_pass)     |                    |
     |                  |------------------------------------------->|
     |                  |<-------------------------------------------|
     |                  |                    |                    |
     |  Auth success    |                    |                    |
     |<-----------------|                    |                    |
     |                  |                    |                    |
     |  SQL / commands  |                    |                    |
     |----------------->| [log + enforce     |                    |
     |                  |  allowed_dbs]      |                    |
     |                  |------------------------------------------->|
     |                  |<-------------------------------------------|
     |  Results         |                    |                    |
     |<-----------------|                    |                    |
```

### 4.3 Protocol-Specific Auth Mechanisms

**MySQL proxy auth remapping (to implement):**

1. Proxy opens a connection to backend, receives backend's handshake packet (containing auth plugin name, salt/scramble).
2. Instead of relaying this to the client, the proxy generates its own handshake packet with `mysql_native_password` plugin and a fresh 20-byte salt.
3. Client responds with `mysql_native_password` auth data (SHA1-based scramble of password + proxy salt).
4. Proxy calls `POST /auth` with extracted username, receives portal password.
5. Proxy computes the expected auth response from the portal password + the salt it sent, and compares.
6. On match: proxy authenticates to backend using `backend_user`/`backend_pass` with the backend's original salt. If the backend advertises `caching_sha2_password` (MySQL 8.0+ default, mandatory on 8.4+), the proxy runs the caching_sha2 handshake: SHA-256 fast-auth scramble, then — only if the server demands full-auth — either sends cleartext over an already-TLS-wrapped backend conn, or requests the server's RSA public key and sends RSA-OAEP-SHA1(`password||NUL` XOR nonce). `mysql_native_password` remains the compatibility fallback.
7. On mismatch: proxy sends ERR packet to client.

**PostgreSQL proxy auth remapping (to implement):**

1. Client sends StartupMessage (possibly preceded by SSLRequest).
2. Proxy extracts username from startup parameters.
3. Proxy calls `POST /auth` with username, receives portal password and backend creds.
4. Proxy acts as PG server to client: sends AuthenticationCleartextPassword (or runs SCRAM-SHA-256 exchange).
5. Client responds with password; proxy verifies against portal password.
6. On match: proxy opens connection to backend with `backend_user`/`backend_pass`, completes backend auth (SCRAM-SHA-256 or MD5 per backend config).
7. Proxy relays ReadyForQuery to client.

**MongoDB proxy auth remapping (implemented in POC):**

1. Client sends `hello`/`ismaster`; proxy forwards to backend and patches response to advertise `SCRAM-SHA-256`.
2. Client sends `saslStart` with `SCRAM-SHA-256` mechanism.
3. Proxy extracts username from SCRAM client-first-message.
4. Proxy calls `POST /auth`, receives portal password and backend creds.
5. Proxy computes SCRAM stored credentials from portal password and runs full SCRAM-SHA-256 server conversation with client.
6. On success: proxy runs SCRAM-SHA-256 client conversation with backend using `backend_user`/`backend_pass`.
7. Post-auth: traffic is relayed bidirectionally with command inspection.

---

## 5. Portal API Contract

### 5.1 Internal API (proxy-facing)

These endpoints are called by proxies. They must be on an internal network or protected by mTLS/shared secret.

#### `POST /api/v1/auth`

Called by proxy on every new client connection.

**Request:**
```json
{
  "username": "alice",
  "source_ip": "10.0.1.42",
  "proxy_type": "mysql",
  "backend_server": "mysql-prod-01:3306"
}
```

**Response 200 (access granted):**
```json
{
  "password": "alice-portal-password-2026",
  "backend_user": "app_user",
  "backend_pass": "j8Kz!mN2pQ...",
  "allowed_dbs": ["orders", "inventory"],
  "role": "app",
  "grant_id": "g-abc123",
  "expires_at": "2026-03-26T22:00:00Z",
  "connection_ttl_seconds": 3600
}
```

**Response 401 (access denied):**
```json
{
  "error": "no active grant for user 'alice' on backend 'mysql-prod-01:3306'"
}
```

**Response 403 (grant expired or revoked):**
```json
{
  "error": "grant g-abc123 expired at 2026-03-26T18:00:00Z"
}
```

#### `POST /api/v1/audit/query`

Called by proxies to ship query logs in batches. This is a **third-party historization** channel — the portal stores audit records independently from the observability stack, ensuring query history survives OTel backend retention policies or infrastructure changes.

Proxies emit telemetry via **three complementary channels** (see §10 Observability):
1. **Local structured JSON logs** (slog → stdout) — always available, zero deps
2. **OpenTelemetry** (traces + metrics + logs) — rich context, distributed tracing
3. **Portal audit API** (this endpoint) — durable audit trail under portal's control

The portal channel is **async and best-effort**: proxies buffer and batch-send in the background. A failing portal does not block or slow query relay.

**Request:**
```json
{
  "entries": [
    {
      "timestamp": "2026-03-26T14:23:01.123Z",
      "grant_id": "g-abc123",
      "username": "alice",
      "proxy_type": "mysql",
      "backend_server": "mysql-prod-01:3306",
      "database": "orders",
      "query": "SELECT * FROM orders WHERE id = 42",
      "truncated": false,
      "source_ip": "10.0.1.42",
      "duration_ms": 12,
      "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736"
    }
  ]
}
```

`trace_id` links the audit entry to the OTel trace for drill-down in Grafana/Tempo.

**Response 202:**
```json
{
  "accepted": 1
}
```

### 5.2 External API (user/admin-facing)

All endpoints require authentication (session cookie or Bearer token).

#### Grants

| Method | Path | Description | Authz |
|---|---|---|---|
| `POST` | `/api/v1/grants` | Request a new grant | Any authenticated user |
| `GET` | `/api/v1/grants` | List grants (filtered) | User sees own; admin sees all |
| `GET` | `/api/v1/grants/:id` | Get grant details | Owner or admin |
| `PATCH` | `/api/v1/grants/:id` | Approve/deny/revoke grant | Admin only |
| `DELETE` | `/api/v1/grants/:id` | Revoke grant (soft delete) | Admin or owner |

**Create grant request:**
```json
{
  "backend_server": "mysql-prod-01",
  "database": "orders",
  "role": "app",
  "reason": "Investigating order #12345 latency",
  "requested_duration": "4h"
}
```

**Grant object:**
```json
{
  "id": "g-abc123",
  "user_id": "u-alice",
  "username": "alice",
  "backend_server_id": "bs-mysql-prod-01",
  "backend_server_name": "mysql-prod-01",
  "database": "orders",
  "role": "app",
  "status": "APPROVED",
  "reason": "Investigating order #12345 latency",
  "requested_at": "2026-03-26T14:00:00Z",
  "approved_at": "2026-03-26T14:05:00Z",
  "approved_by": "u-bob",
  "expires_at": "2026-03-26T18:05:00Z",
  "revoked_at": null
}
```

#### Users

| Method | Path | Description | Authz |
|---|---|---|---|
| `POST` | `/api/v1/users` | Create user | Admin |
| `GET` | `/api/v1/users` | List users | Admin |
| `GET` | `/api/v1/users/:id` | Get user | Self or admin |
| `PATCH` | `/api/v1/users/:id` | Update user (password, status) | Self (password) or admin |
| `DELETE` | `/api/v1/users/:id` | Deactivate user | Admin |

#### Backend Servers

| Method | Path | Description | Authz |
|---|---|---|---|
| `POST` | `/api/v1/backends` | Register backend server | Admin |
| `GET` | `/api/v1/backends` | List backend servers | Admin |
| `GET` | `/api/v1/backends/:id` | Get backend details | Admin |
| `PATCH` | `/api/v1/backends/:id` | Update backend config | Admin |
| `DELETE` | `/api/v1/backends/:id` | Deregister backend | Admin |

**Backend server object:**
```json
{
  "id": "bs-mysql-prod-01",
  "name": "mysql-prod-01",
  "type": "mysql",
  "host": "mysql-prod-01.internal",
  "port": 3306,
  "databases": ["orders", "inventory", "analytics"],
  "accounts": {
    "app": {
      "username": "app_user",
      "password": "***"
    },
    "dba": {
      "username": "dba_user",
      "password": "***"
    }
  }
}
```

#### Audit Log

| Method | Path | Description | Authz |
|---|---|---|---|
| `GET` | `/api/v1/audit` | Query audit log | Admin |
| `GET` | `/api/v1/audit/grants` | Grant lifecycle events | Admin |
| `GET` | `/api/v1/audit/queries` | Query log (from proxies) | Admin |

**Query parameters:** `user`, `backend`, `database`, `from`, `to`, `grant_id`, `limit`, `offset`.

#### System

| Method | Path | Description | Authz |
|---|---|---|---|
| `GET` | `/healthz` | Liveness probe | None |
| `GET` | `/readyz` | Readiness probe (DB connectivity) | None |
| `GET` | `/metrics` | Prometheus metrics | None (or restricted) |

---

## 6. Data Model

### 6.1 Entity-Relationship Diagram

```
+------------------+       +--------------------+       +---------------------+
|     users        |       |      grants        |       |  backend_servers    |
+------------------+       +--------------------+       +---------------------+
| id          PK   |<------| user_id        FK  |  +--->| id             PK  |
| username  UNIQUE |       | id             PK  |  |    | name        UNIQUE |
| password_hash    |       | backend_server_id -+--+    | type (mysql/pg/    |
| display_name     |       | database           |       |       mongo)       |
| email            |       | role (app/dba)     |       | host               |
| is_admin         |       | status             |       | port               |
| status           |       | reason             |       | databases (JSON)   |
| created_at       |       | requested_at       |       | created_at         |
| updated_at       |       | approved_at        |       | updated_at         |
+------------------+       | approved_by     FK |       +---------------------+
                           | expires_at         |              |
                           | revoked_at         |              |
                           | created_at         |       +---------------------+
                           | updated_at         |       | backend_accounts    |
                           +--------------------+       +---------------------+
                                                        | id             PK  |
+------------------+                                    | server_id      FK  |
|  audit_events    |                                    | role (app/dba)     |
+------------------+                                    | username           |
| id          PK   |                                    | password_enc       |
| event_type       |                                    | created_at         |
| actor_id    FK   |                                    | updated_at         |
| grant_id    FK   |                                    +---------------------+
| detail (JSON)    |
| source_ip        |
| timestamp        |
+------------------+

+------------------+
|  query_log       |
+------------------+
| id          PK   |
| grant_id    FK   |
| username         |
| proxy_type       |
| backend_server   |
| database         |
| query            |
| truncated        |
| source_ip        |
| trace_id         |
| duration_ms      |
| timestamp        |
+------------------+
```

### 6.2 Table Definitions

**users:**

| Column | Type | Constraints | Notes |
|---|---|---|---|
| `id` | TEXT | PK | Prefixed: `u-{ulid}` |
| `username` | TEXT | UNIQUE, NOT NULL | Login identifier |
| `password_hash` | TEXT | NOT NULL | bcrypt or argon2id hash |
| `display_name` | TEXT | | Human-readable name |
| `email` | TEXT | | For notifications |
| `is_admin` | BOOLEAN | NOT NULL, DEFAULT FALSE | |
| `status` | TEXT | NOT NULL, DEFAULT 'active' | `active`, `disabled` |
| `created_at` | TIMESTAMP | NOT NULL | |
| `updated_at` | TIMESTAMP | NOT NULL | |

**grants:**

| Column | Type | Constraints | Notes |
|---|---|---|---|
| `id` | TEXT | PK | Prefixed: `g-{ulid}` |
| `user_id` | TEXT | FK -> users.id, NOT NULL | |
| `backend_server_id` | TEXT | FK -> backend_servers.id, NOT NULL | |
| `database` | TEXT | NOT NULL | Target database name |
| `role` | TEXT | NOT NULL | `app` or `dba` |
| `status` | TEXT | NOT NULL | `PENDING`, `APPROVED`, `DENIED`, `EXPIRED`, `REVOKED` |
| `reason` | TEXT | | Justification for access |
| `requested_at` | TIMESTAMP | NOT NULL | |
| `approved_at` | TIMESTAMP | | |
| `approved_by` | TEXT | FK -> users.id | Admin who approved |
| `expires_at` | TIMESTAMP | | NULL means indefinite (discouraged) |
| `revoked_at` | TIMESTAMP | | Explicit revocation timestamp |
| `created_at` | TIMESTAMP | NOT NULL | |
| `updated_at` | TIMESTAMP | NOT NULL | |

**Grant status transitions:**
```
PENDING --[admin approves]--> APPROVED --[time passes]--> EXPIRED
   |                             |
   +--[admin denies]---> DENIED  +--[admin/user revokes]--> REVOKED
```

**backend_servers:**

| Column | Type | Constraints | Notes |
|---|---|---|---|
| `id` | TEXT | PK | Prefixed: `bs-{ulid}` |
| `name` | TEXT | UNIQUE, NOT NULL | Human-readable (e.g., `mysql-prod-01`) |
| `type` | TEXT | NOT NULL | `mysql`, `postgres`, `mongodb` |
| `host` | TEXT | NOT NULL | Hostname or IP |
| `port` | INTEGER | NOT NULL | |
| `databases` | TEXT (JSON) | | JSON array of known database names |
| `created_at` | TIMESTAMP | NOT NULL | |
| `updated_at` | TIMESTAMP | NOT NULL | |

**backend_accounts:**

| Column | Type | Constraints | Notes |
|---|---|---|---|
| `id` | TEXT | PK | |
| `server_id` | TEXT | FK -> backend_servers.id, NOT NULL | |
| `role` | TEXT | NOT NULL | `app` or `dba` |
| `username` | TEXT | NOT NULL | Backend DB username |
| `password_enc` | TEXT | NOT NULL | Encrypted at rest (AES-256-GCM with portal key) |
| `created_at` | TIMESTAMP | NOT NULL | |
| `updated_at` | TIMESTAMP | NOT NULL | |

UNIQUE constraint on `(server_id, role)` -- exactly one app account and one dba account per backend server.

**audit_events:**

| Column | Type | Constraints | Notes |
|---|---|---|---|
| `id` | TEXT | PK | |
| `event_type` | TEXT | NOT NULL | `grant_requested`, `grant_approved`, `grant_denied`, `grant_revoked`, `grant_expired`, `user_created`, `user_disabled`, `backend_added` |
| `actor_id` | TEXT | FK -> users.id | Who performed the action |
| `grant_id` | TEXT | FK -> grants.id | If related to a grant |
| `detail` | TEXT (JSON) | | Arbitrary structured detail |
| `source_ip` | TEXT | | |
| `timestamp` | TIMESTAMP | NOT NULL | |

**query_log (third-party historization):**

| Column | Type | Constraints | Notes |
|---|---|---|---|
| `id` | TEXT | PK | |
| `grant_id` | TEXT | | Links to the grant that authorized this query |
| `username` | TEXT | NOT NULL | |
| `proxy_type` | TEXT | NOT NULL | `mysql`, `postgres`, `mongodb` |
| `backend_server` | TEXT | NOT NULL | |
| `database` | TEXT | | |
| `query` | TEXT | | Truncated at 4096 chars |
| `truncated` | BOOLEAN | | |
| `source_ip` | TEXT | | |
| `trace_id` | TEXT | | Links to OTel trace for drill-down |
| `duration_ms` | INTEGER | | |
| `timestamp` | TIMESTAMP | NOT NULL | |

This table is the **durable audit trail** owned by the portal, independent of OTel backend retention. Proxies push logs async via `POST /api/v1/audit/query`. For high-volume deployments, partition by month or offload old records to object storage.

### 6.3 Auth Resolution Query (hot path)

When a proxy calls `POST /api/v1/auth`, the portal must resolve:

```sql
SELECT
    g.id AS grant_id,
    g.database,
    g.role,
    g.expires_at,
    u.password_hash,
    ba.username AS backend_user,
    ba.password_enc AS backend_pass
FROM grants g
JOIN users u ON u.id = g.user_id
JOIN backend_servers bs ON bs.id = g.backend_server_id
JOIN backend_accounts ba ON ba.server_id = bs.id AND ba.role = g.role
WHERE u.username = ?
  AND u.status = 'active'
  AND bs.name = ?             -- or matched by proxy_type + host:port
  AND g.status = 'APPROVED'
  AND (g.expires_at IS NULL OR g.expires_at > NOW())
```

This returns one row per active grant. If the user has multiple grants on the same backend (e.g., `app` on `orders` and `app` on `inventory`), the portal aggregates `allowed_dbs` from all matching grants and returns the appropriate backend credentials.

Index recommendations: `(username, status)` on users, `(user_id, backend_server_id, status)` on grants.

---

## 7. Deployment Architecture

### 7.1 Minimal Deployment (single host or small team)

```
+---------------------------------------------------------------+
|                        Single Host                             |
|                                                                |
|  +-----------+  +-----------+  +-----------+  +----------+    |
|  | mysql-    |  | postgres- |  | mongo-    |  | portal   |    |
|  | proxy     |  | proxy     |  | proxy     |  | (API+UI) |    |
|  | :13306    |  | :15432    |  | :37017    |  | :8443    |    |
|  +-----------+  +-----------+  +-----------+  +----------+    |
|       |              |              |              |           |
|       +--------------+--------------+   SQLite     |           |
|       |      portal :8080 (internal)|   file       |           |
|       +-----------------------------+--------------+           |
+---------------------------------------------------------------+
          |              |              |
     to MySQL       to PostgreSQL   to MongoDB
     backends       backends        backends
```

- Portal runs on port 8443 (external HTTPS for UI/API) and 8080 (internal HTTP for proxy auth calls).
- Proxies run on the same host, connecting to portal via localhost:8080.
- SQLite as the portal database for simplicity. Suitable for small deployments.
- Single binary per component, deployed as systemd services or in containers.

### 7.2 Production Deployment (Kubernetes)

```
+------------------------------------------------------------------+
|                     Kubernetes Cluster                             |
|                                                                   |
|  +--------------------+  +--------------------+                   |
|  | Namespace: db-portal                       |                   |
|  |                                            |                   |
|  | +---------------+  +------------------+    |                   |
|  | | portal        |  | portal-db        |    |                   |
|  | | Deployment    |  | StatefulSet      |    |                   |
|  | | replicas: 2   |  | (PostgreSQL)     |    |                   |
|  | | :8443 (ext)   |  | replicas: 1      |    |                   |
|  | | :8080 (int)   |  +------------------+    |                   |
|  | +---------------+                          |                   |
|  |                                            |                   |
|  | +---------------+ +---------------+ +------+--------+          |
|  | | mysql-proxy   | | pg-proxy      | | mongo-proxy   |          |
|  | | DaemonSet or  | | DaemonSet or  | | DaemonSet or  |          |
|  | | Deployment    | | Deployment    | | Deployment    |          |
|  | | :13306        | | :15432        | | :37017        |          |
|  | +---------------+ +---------------+ +---------------+          |
|  |                                                                |
|  +----------------------------------------------------------------+
|                                                                   |
|  Ingress / LoadBalancer:                                          |
|    portal.example.com:443 -> portal :8443                         |
|    mysql.example.com:13306 -> mysql-proxy :13306 (TCP LB)         |
|    pg.example.com:15432 -> pg-proxy :15432 (TCP LB)               |
|    mongo.example.com:37017 -> mongo-proxy :37017 (TCP LB)         |
+-------------------------------------------------------------------+
```

**Notes:**
- Portal is horizontally scalable (stateless HTTP, shared database).
- Proxies are horizontally scalable (completely stateless, no affinity needed).
- Database protocol load balancing requires L4 (TCP) load balancers, not L7/HTTP.
- Portal internal endpoint (`:8080`) is exposed only as a ClusterIP service.
- Backend database credentials are stored in portal DB encrypted, with the encryption key from a Kubernetes Secret or external KMS.

### 7.3 Configuration

**Proxy configuration (all via CLI flags or environment variables):**

| Parameter | Flag | Env | Default | Description |
|---|---|---|---|---|
| Listen address | `--listen` | `LISTEN_ADDR` | Per-protocol default | Address to bind |
| Backend address | `--backend` | `BACKEND_ADDR` | Per-protocol default | Target DB server |
| Auth URL | `--auth-url` | `AUTH_URL` | (none) | Portal auth endpoint |
| Connection TTL | `--conn-ttl` | `CONN_TTL` | `1h` | Max connection duration |
| Client TLS | `--client-tls` | `CLIENT_TLS` | `false` | Enable client-facing TLS |
| Client TLS cert | `--client-tls-cert` | `CLIENT_TLS_CERT` | | Certificate file |
| Client TLS key | `--client-tls-key` | `CLIENT_TLS_KEY` | | Key file |
| Backend TLS | `--backend-tls` | `BACKEND_TLS` | `false` | Enable backend TLS |
| Backend TLS CA | `--backend-tls-ca` | `BACKEND_TLS_CA` | | CA certificate |
| Backend TLS insecure | `--backend-tls-insecure` | `BACKEND_TLS_INSECURE` | `false` | Skip backend cert verify |
| Log level | `--log-level` | `LOG_LEVEL` | `info` | Logging verbosity |

**Portal configuration:**

| Parameter | Env | Default | Description |
|---|---|---|---|
| Listen (external) | `PORTAL_LISTEN` | `:8443` | External HTTPS for UI/API |
| Listen (internal) | `PORTAL_INTERNAL_LISTEN` | `:8080` | Internal HTTP for proxy auth |
| Database DSN | `PORTAL_DB_DSN` | `sqlite://portal.db` | Portal database connection |
| Encryption key | `PORTAL_ENCRYPTION_KEY` | (required) | For encrypting backend passwords |
| Session secret | `PORTAL_SESSION_SECRET` | (required) | For signing session cookies |
| Default grant TTL | `PORTAL_DEFAULT_GRANT_TTL` | `4h` | Default access duration |
| Max grant TTL | `PORTAL_MAX_GRANT_TTL` | `24h` | Maximum access duration |
| Connection TTL | `PORTAL_CONNECTION_TTL` | `1h` | Returned to proxies |

---

## 8. Security Considerations

### 8.1 Threat Model

| Threat | Mitigation |
|---|---|
| **Stolen portal credentials** | Time-bound grants limit blast radius. Connection TTL forces re-auth. Immediate revocation via portal. |
| **Compromised proxy** | Proxy is stateless -- it never stores credentials persistently. Backend passwords are fetched per-connection and held only in memory for the duration of auth. |
| **Portal API abuse** | Internal auth endpoint is network-isolated (not exposed externally). External API requires authenticated sessions. Rate limiting on auth endpoints. |
| **Man-in-the-middle (client to proxy)** | TLS on client-facing listener. SSLRequest handling for PostgreSQL. |
| **Man-in-the-middle (proxy to backend)** | TLS with CA verification for backend connections. mTLS optional. |
| **Man-in-the-middle (proxy to portal)** | Internal network or mTLS between proxy and portal. |
| **SQL/command injection via proxy** | Proxy logs but does not modify queries. DB restriction enforcement operates at connection/database level, not query level. Backend accounts have limited privileges. |
| **Backend credential exposure** | Stored encrypted (AES-256-GCM) in portal DB. Decrypted only at auth-time, transmitted over internal network. |
| **Excessive privilege** | Two roles (`app`/`dba`) with distinct backend accounts. `app` accounts have only CRUD privileges. `dba` accounts have DDL. |

### 8.2 Credential Lifecycle

```
Portal password (user-facing):
  - Generated by portal when user account is created (or set by user)
  - Stored as hash (argon2id) in portal DB
  - Returned as plaintext ONLY via POST /auth to proxies (internal network)
  - Used by user to connect to proxies via DB clients

Backend password (system):
  - Configured by admin when registering a backend server
  - Stored encrypted (AES-256-GCM) in portal DB
  - Decrypted at auth-time and returned to proxy via POST /auth
  - Used by proxy to authenticate to actual DB server
  - Shared across all users with the same role on the same backend
  - Rotated by admin via PATCH /backends/:id
```

### 8.3 Network Security

```
                         DMZ / External
                            |
                     +------+------+
                     | TLS term.   |
                     | (Ingress)   |
                     +------+------+
                            |
              +-------------+-------------+
              |                           |
        +-----+-----+              +-----+-----+
        | Portal    |              | Proxies   |
        | :8443 ext |              | :13306    |
        | :8080 int |              | :15432    |
        +-----+-----+              | :37017    |
              |                    +-----+-----+
              |                          |
       Internal network only      Internal network
              |                          |
        +-----+-----+              +-----+-----+
        | Portal DB |              | Backend   |
        | (PG/SQLite)|             | Databases |
        +-----------+              +-----------+
```

**Key network rules:**

- Portal `:8080` (internal auth API) is reachable only from proxy pods/hosts. Not exposed to users.
- Portal `:8443` (external UI/API) is exposed via TLS-terminating ingress.
- Proxy listen ports are exposed via L4 (TCP) load balancers. No HTTP termination.
- Backend databases are reachable only from proxy hosts. Not directly accessible by users.

### 8.4 Password Handling in Auth Remapping

A critical security property: the proxy must verify the client's password without ever receiving the password in plaintext from protocols that use challenge-response (MySQL `mysql_native_password`, MongoDB SCRAM, PostgreSQL SCRAM).

**How this works:**

- The portal returns the **plaintext** portal password to the proxy via the internal `/auth` API.
- The proxy uses this plaintext to compute the expected challenge-response for the protocol's auth mechanism:
  - MySQL: compute `SHA1(password) XOR SHA1(salt + SHA1(SHA1(password)))` and compare
  - MongoDB: compute SCRAM stored credentials from password, run server-side SCRAM
  - PostgreSQL: compute SCRAM stored credentials from password, or verify cleartext

- The plaintext password is in memory only during the auth phase of a single connection and is discarded after.

### 8.5 Database Restriction Enforcement (backend-side)

See the §4b amendment at the top of this document. Database-level authorization is **not** enforced by the proxy. The portal nominates a specific backend role for each session (optionally one role per logical DB via `AllowedDBs`), and the database enforces privileges against that role via `GRANT`/`REVOKE`. The proxy is the identity gateway; the backend is the authorization gate.

**Why this changed:** Protocol-level enforcement is a moving target (new MySQL commands, PG `SET search_path`, Mongo `$db` quirks) and duplicates work the database already does correctly via roles. Rotating or revoking access = rotating the backend role's grants — no proxy change, no restart.

---

## 9. Failure Modes and Resilience

### 9.1 Failure Scenarios

| Failure | Impact | Behavior | Recovery |
|---|---|---|---|
| **Portal down** | New connections fail. Existing connections unaffected. | Proxy receives connection error on `POST /auth`, returns auth failure to client. | Portal restart. Proxies retry on next connection. No state to recover. |
| **Portal DB down** | Portal cannot resolve grants. Same as portal down for auth. | Portal returns 503 to proxies. UI/API return 503. | DB restart. Portal reconnects automatically. |
| **Proxy crash** | Active connections on that proxy are dropped. | TCP connections broken. Clients reconnect (typically automatic for connection pools). | Proxy restarts. No state to recover -- fully stateless. |
| **Backend DB down** | Proxy cannot establish backend connection. | Proxy returns backend error to client after auth succeeds but dial fails. | Backend recovery. Client retries. |
| **Network partition (proxy <-> portal)** | Same as portal down from proxy's perspective. | New connections fail auth. Existing connections continue (already authenticated). | Network recovery. |
| **Network partition (proxy <-> backend)** | Active connections break. New connections fail at dial. | Both existing relay and new dials fail. | Network recovery. |

### 9.2 Resilience Mechanisms

**Proxy statelessness.** The single most important resilience property. A proxy can be killed and restarted at any time with zero data loss. There is no state to replicate, no consensus to maintain, no cache to warm.

**Connection draining.** On SIGTERM/SIGINT, proxies stop accepting new connections and wait up to 30 seconds (configurable) for active connections to complete before exiting. This is already implemented in the POC via `proxy.Server.Serve()`.

**Auth timeout.** The auth client uses a 5-second HTTP timeout (already implemented). A hung portal does not block proxy resources indefinitely.

**Connection TTL.** Proxies enforce a maximum connection duration. When the TTL expires, the proxy closes the connection, forcing the client to reconnect (and re-authenticate). This ensures revocations take effect within the TTL window even for long-lived connections.

**Portal high availability.** The portal is a stateless HTTP service backed by a database. Running 2+ replicas behind a load balancer provides HA. The database is the single point of failure and should use standard DB HA (streaming replication for PostgreSQL, or managed DB service).

### 9.3 Optional: Auth Response Caching

For environments where the portal may be briefly unavailable, proxies could cache the last successful auth response per user with a short TTL (e.g., 30-60 seconds). This trades consistency (a revoked grant might be honored for up to TTL seconds) for availability. This is deliberately **not** in the initial design to keep the security model simple. It can be added later as an opt-in feature with an explicit `--auth-cache-ttl` flag.

---

## 10. Observability

### 10.1 Structured Logging

All components emit structured JSON logs (already the pattern in the POC, using `log/slog` with `slog.NewJSONHandler`).

**Proxy log events:**

| Event | Level | Fields | When |
|---|---|---|---|
| `connect` | INFO | `client` (remote addr), `proxy` (type) | New TCP connection accepted |
| `auth_lookup` | INFO | `username`, `grant_id`, `role`, `allowed_dbs` | Successful portal auth |
| `auth_denied` | WARN | `username`, `reason` | Portal returned 401/403 |
| `auth_error` | ERROR | `username`, `err` | Portal unreachable or 5xx |
| `authenticated` | INFO | `username`, `backend_user` | Client + backend auth complete |
| `query` | INFO | `query`, `truncated`, `database` | SQL/command executed |
| `prepare` | INFO | `query`, `truncated` | Prepared statement |
| `use_db` | INFO | `database` | Database change |
| `db_denied` | WARN | `database`, `allowed_dbs` | Client tried disallowed DB |
| `command` | INFO | `command`, `collection`, `doc`, `truncated` | MongoDB command |
| `disconnect` | INFO | `duration` | Connection closed |
| `dial_backend` | ERROR | `err` | Backend connection failed |

**Portal log events:**

| Event | Level | Fields | When |
|---|---|---|---|
| `grant_requested` | INFO | `user`, `backend`, `database`, `role` | Grant created |
| `grant_approved` | INFO | `grant_id`, `approved_by`, `expires_at` | Grant approved |
| `grant_denied` | INFO | `grant_id`, `denied_by` | Grant denied |
| `grant_revoked` | INFO | `grant_id`, `revoked_by` | Grant revoked |
| `grant_expired` | INFO | `grant_id` | Grant expired (background job) |
| `auth_served` | INFO | `username`, `backend`, `grant_id` | Auth request from proxy served |
| `auth_rejected` | WARN | `username`, `backend`, `reason` | Auth request rejected |

### 10.2 OpenTelemetry

All components are instrumented with OpenTelemetry, exported via OTLP. OTel is the primary telemetry channel; local logs are the fallback.

#### 10.2.1 Traces

Each proxy connection produces a trace with the following span hierarchy:

```
proxy.connection                          (root span, entire session lifetime)
├── proxy.auth                            (auth phase)
│   ├── proxy.auth.portal_lookup          (HTTP call to POST /auth)
│   ├── proxy.auth.client_verify          (protocol-specific client auth)
│   └── proxy.auth.backend_login          (protocol-specific backend auth)
├── proxy.query                           (one per query/command)
│   └── ... repeated per query
├── proxy.query
└── proxy.disconnect
```

**Span attributes (on root `proxy.connection` span):**

| Attribute | Type | Example |
|---|---|---|
| `proxy.type` | string | `mysql`, `postgres`, `mongodb` |
| `proxy.client.addr` | string | `10.0.1.42:54321` |
| `proxy.backend.addr` | string | `mysql-prod-01:3306` |
| `proxy.user` | string | `alice` |
| `proxy.grant_id` | string | `g-abc123` |
| `proxy.role` | string | `app` |
| `proxy.allowed_dbs` | string[] | `["orders", "inventory"]` |
| `proxy.backend_user` | string | `app_user` |
| `proxy.tls.client` | bool | `true` |
| `proxy.tls.backend` | bool | `true` |

**Span attributes (on `proxy.query` spans):**

| Attribute | Type | Example |
|---|---|---|
| `db.system` | string | `mysql` (follows OTel semantic conventions) |
| `db.statement` | string | `SELECT * FROM orders WHERE id = 42` (truncated at 4KB) |
| `db.statement.truncated` | bool | `false` |
| `db.name` | string | `orders` |
| `db.operation` | string | `SELECT` / `INSERT` / `find` / `insert` |

**Span events:**

| Event | When | Attributes |
|---|---|---|
| `auth.denied` | Portal rejected the user | `proxy.user`, `error.message` |

(A `db.denied` span event existed in an earlier draft; dropped along with proxy-side DB restriction — see §4b.)

This enables querying the trace backend for full audit:
- "Show all queries by alice in the last hour" → filter spans by `proxy.user=alice`, span name `proxy.query`
- "Show all denied access attempts" → filter by event `auth.denied`
- "Show the full session for grant g-abc123" → filter by `proxy.grant_id`

#### 10.2.2 Metrics (via OTel)

Exported via OTLP and optionally scraped via Prometheus (OTel SDK supports both).

**Proxy metrics:**

| Metric | Type | Labels | Description |
|---|---|---|---|
| `proxy.connections` | Counter | `proxy.type`, `status` | Total connections (success/auth_denied/error) |
| `proxy.connections.active` | UpDownCounter | `proxy.type` | Currently active connections |
| `proxy.connection.duration` | Histogram | `proxy.type` | Connection duration (seconds) |
| `proxy.queries` | Counter | `proxy.type`, `db.operation` | Queries relayed |
| `proxy.auth.duration` | Histogram | `proxy.type` | Auth phase latency (portal call + protocol auth) |
| `proxy.auth.requests` | Counter | `proxy.type`, `status` | Auth API calls |
| `proxy.bytes` | Counter | `proxy.type`, `direction` | Bytes relayed |

**Portal metrics:**

| Metric | Type | Labels | Description |
|---|---|---|---|
| `portal.http.requests` | Counter | `method`, `route`, `status` | HTTP requests |
| `portal.http.duration` | Histogram | `method`, `route` | HTTP latency |
| `portal.grants.active` | UpDownCounter | `role`, `backend_type` | Active grants |
| `portal.auth.lookups` | Counter | `result` | Auth lookups from proxies |

#### 10.2.3 Logs (slog → OTel bridge)

Proxies use Go's `slog` for structured logging. The OTel log bridge (`go.opentelemetry.io/contrib/bridges/otelslog`) attaches logs to the active trace span, enabling correlation:

```
┌─────────┐     slog.Info("query", ...)     ┌──────────────┐
│  Proxy   │ ───────────────────────────────>│ slog Handler │
│  code    │                                 │  (multiplex) │
└─────────┘                                  └──────┬───────┘
                                                    │
                                      ┌─────────────┼─────────────┐
                                      │             │             │
                                      v             v             v
                                 ┌─────────┐  ┌─────────┐  ┌──────────┐
                                 │ JSON    │  │  OTel   │  │ (future) │
                                 │ stdout  │  │  Log    │  │ syslog   │
                                 │ (local) │  │ Exporter│  │ etc.     │
                                 └─────────┘  └─────────┘  └──────────┘
```

- **Local JSON (stdout)**: always enabled, zero dependencies. Collected by node-level agent (Fluentbit, Vector, filebeat) or just `journald`.
- **OTel Log Exporter**: enabled via `--otel-endpoint`. Logs carry `trace_id` and `span_id` for correlation with traces.
- Both run simultaneously. Local logs are the fallback if OTel collector is unavailable.

#### 10.2.4 Configuration

| Flag | Env | Default | Description |
|---|---|---|---|
| `--otel-endpoint` | `OTEL_EXPORTER_OTLP_ENDPOINT` | (disabled) | OTel collector OTLP endpoint (e.g., `otel-collector:4317`) |
| `--otel-insecure` | `OTEL_EXPORTER_OTLP_INSECURE` | `false` | Use plaintext gRPC (for local collector) |
| `--otel-service-name` | `OTEL_SERVICE_NAME` | `mysql-proxy` / `pg-proxy` / `mongo-proxy` | Service name in traces |

When `--otel-endpoint` is not set, OTel is completely disabled — no SDK overhead, local logs only. This keeps the POC simple while making production observability opt-in.

#### 10.2.5 Collection Architecture

```
                     ┌──────────────────────────────────┐
                     │         Observability Stack       │
                     │                                   │
                     │  ┌───────────┐  ┌─────────────┐  │
                     │  │   Tempo   │  │    Loki     │  │
                     │  │  (traces) │  │   (logs)    │  │
                     │  └─────┬─────┘  └──────┬──────┘  │
                     │        │               │         │
                     │  ┌─────┴───────────────┴──────┐  │
                     │  │      Grafana               │  │
                     │  │  (dashboards + explore)    │  │
                     │  └────────────────────────────┘  │
                     │        ^               ^         │
                     └────────┼───────────────┼─────────┘
                              │               │
                     ┌────────┴───────────────┴─────────┐
                     │       OTel Collector              │
                     │  (receives OTLP, fans out to     │
                     │   Tempo for traces, Loki for     │
                     │   logs, Prometheus for metrics)   │
                     └────────^───────────────^─────────┘
                              │               │
                 OTLP (gRPC)  │               │  OTLP (gRPC)
                              │               │
                     ┌────────┴──┐    ┌───────┴───┐
                     │  Proxies  │    │  Portal   │
                     │ (3 types) │    │           │
                     └───────────┘    └───────────┘
```

**Three-channel telemetry — each serves a different purpose:**

| Channel | Purpose | Availability | Retention |
|---|---|---|---|
| **Local JSON logs** | Debugging, node-level collection | Always (zero deps) | Node disk / log rotation |
| **OTel (Tempo/Loki)** | Rich traces, cross-service correlation, dashboards | When OTel collector is up | Observability stack policy |
| **Portal audit API** | Durable compliance/audit trail | When portal is up (async, best-effort) | Portal DB (unlimited, partitioned) |

The portal's audit UI queries **both** its own `query_log` table (for the durable record) and the OTel backend (for trace drill-down via `trace_id`). If the OTel stack is down, the audit trail is still intact in the portal DB. If the portal is down, traces and local logs still capture everything.

### 10.3 Health Checks

Each component exposes an HTTP admin port (separate from the protocol-specific listener) for health and metrics:

**Proxy admin port** (e.g., `:9090`, configured via `--admin-port`):

| Endpoint | Check | Response |
|---|---|---|
| `GET /healthz` | Process running, TCP listener active | 200 `ok` |
| `GET /readyz` | Portal reachable (HEAD to portal /healthz) | 200 or 503 |
| `GET /metrics` | Prometheus scrape (from OTel SDK) | Prometheus exposition format |

**Portal:**

| Endpoint | Check | Response |
|---|---|---|
| `GET /healthz` | Process is running | 200 `{"status": "ok"}` |
| `GET /readyz` | DB connection OK, migrations applied | 200 or 503 `{"status": "not_ready", "reason": "..."}` |
| `GET /metrics` | Prometheus scrape | Prometheus exposition format |

---

## 11. Open Questions and Future Work

### 11.1 Design Decisions to Finalize

| Decision | Options | Recommendation |
|---|---|---|
| Portal database | SQLite vs PostgreSQL | Start with SQLite for single-node. Add PostgreSQL support for production/HA. Use database/sql + migration tool (goose or golang-migrate) to support both. |
| Portal framework | net/http stdlib vs chi vs gin | net/http with Go 1.22+ routing (matches proxy's stdlib approach). chi for middleware if needed. |
| User authentication to portal | Local passwords vs OIDC | Local passwords first. OIDC integration as phase 2. |
| Portal-proxy trust | Shared secret (API key) vs mTLS | Shared secret header (`X-Proxy-Token`) for simplicity. mTLS as hardened option. |
| Query log storage | Three channels: local logs + OTel + portal audit API | Local JSON always on. OTel for traces/dashboards. Portal `query_log` table for durable compliance trail. All three run simultaneously. |
| MySQL auth plugin | `mysql_native_password` only vs `caching_sha2_password` | `mysql_native_password` first (simpler, widely supported). `caching_sha2_password` as enhancement. |

### 11.2 Implementation Phases

**Phase 1: Portal MVP + Auth Remapping for All Proxies**
- Build portal with local user auth, grant CRUD, `/auth` endpoint, SQLite backend.
- Add auth remapping to MySQL proxy (`mysql_native_password` server-side auth).
- Add auth remapping to PostgreSQL proxy (cleartext password server-side auth, SCRAM client-side to backend).
- Add `allowed_dbs` enforcement to all three proxies.
- Add `connection_ttl` enforcement.

**Phase 2: Observability + Production Hardening**
- OTel instrumentation on all proxies (traces, metrics, logs via slog bridge).
- Admin HTTP port on proxies (`/healthz`, `/readyz`, `/metrics`).
- OTel Collector + Loki + Tempo + Grafana deployment.
- Portal audit UI querying Loki/Tempo for query history.
- Portal HA (PostgreSQL backend, multi-replica).
- mTLS between proxies and portal.
- Backend password encryption at rest.
- Admin notification (email/webhook) on grant requests.

**Phase 3: Advanced Features**
- OIDC/SAML integration for portal login.
- Policy engine (auto-approve based on rules).
- SCRAM-SHA-256 server-side auth for PostgreSQL proxy.
- `caching_sha2_password` support for MySQL proxy.
- Session recording / replay for DBA sessions.

### 11.3 POC Gap Analysis

The following table maps the current POC implementation to required production capabilities.

| Capability | POC Status | Work Required |
|---|---|---|
| TCP listener with TLS | Done (`proxy.Server`, `tlsutil`) | None |
| MySQL wire protocol parsing + query logging | Done | None |
| PostgreSQL wire protocol parsing + query logging | Done | None |
| MongoDB wire protocol parsing + query logging | Done | None |
| MongoDB SCRAM auth remapping | Done (`mongo/auth.go`) | None |
| MongoDB `speculativeAuthenticate` stripping | Done | None |
| PostgreSQL `CancelRequest` (plain + post-TLS) | Done | None |
| Auth API client | Done (`auth.Client`) — includes HLD-spec response fields as optional, retry with jittered backoff, `ErrAccessDenied` sentinel | None |
| MySQL auth remapping | Not done (pass-through) | Implement proxy-side `caching_sha2_password` / `mysql_native_password` server + client |
| PostgreSQL auth remapping | Not done (pass-through) | Implement proxy-side SCRAM/MD5/cleartext server + client |
| Database restriction enforcement | Not done | Use `AuthResponse.AllowedDBs`; add per-protocol filtering (COM_INIT_DB, startup db, `$db` field) |
| Connection TTL | Not done | Use `AuthResponse.ConnectionTTLSeconds`; add deadline/timer in `HandleConn` |
| Portal (entire component) | Scaffold (`portal/`) — in-memory store, proxy+user+admin endpoints, token guards | Persistent store (SQLite → Postgres), approval workflow, TLS+mTLS on API, real user auth (session/JWT/OIDC), web UI |
| Audit shipping (`POST /api/v1/audit/query`) | Portal endpoint exists; proxy-side shipping not wired | Add async batched client in proxy; drop-on-overflow with counter |
| Metrics endpoint | Done (`internal/obs` sidecar: `/healthz`, `/metrics`, `/version` on every binary including portal) | Add latency histograms; consider OTel |
| Health check endpoint | Done (`/healthz` on obs sidecar) | None |
| Config via env vars | Not done (CLI flags only) | Add env var fallback in `config.RegisterFlags` |
| Graceful shutdown + mid-query conn closure | Done (ctx cancel → `proxy.CloseOnDone` closes backend; grace + force window) | None |
| Connection cap + backoff on accept errors | Done | Consider per-source-IP cap |
| Panic recovery on every goroutine boundary | Done (`proxy.SafeGo`) | None |

---

### Critical Files for Implementation

- `internal/auth/auth.go` — Auth client shared by all proxies. Carries the full HLD §5.1 response shape (`password`, `backend_user`, `backend_pass`, plus optional `grant_id`, `role`, `allowed_dbs`, `expires_at`, `connection_ttl_seconds`). Retries jittered backoff on 5xx; never retries 401/403.
- `internal/protocol/mongo/auth.go` — Reference auth-remapping implementation. Pattern: intercept protocol auth → call portal → run server-side SCRAM with portal password → run client-side SCRAM to backend. Strips driver-side `speculativeAuthenticate` from hello.
- `internal/protocol/mysql/mysql.go` — Pass-through. Needs remapping: generate own server handshake, intercept client auth (including caching_sha2_password fast/full paths), verify via portal, authenticate to backend independently.
- `internal/protocol/postgres/postgres.go` — Pass-through on auth; `CancelRequest` and startup/SSL handling done. Needs remapping: act as PG server to client (SASL-SCRAM preferred) and PG client to backend independently.
- `internal/proxy/proxy.go` — Core server. Graceful shutdown + `CloseOnDone` + `SafeGo` + conn cap + accept backoff all in place. Connection TTL (from `AuthResponse.ConnectionTTLSeconds`) still to add: spawn a per-conn deadline goroutine triggered post-auth.
- `portal/portal.go` — Public factory (`NewHandler`, `NewMemoryStore`) used by the portal binary and by `e2e/portal_mongo_test.go` to embed the portal in-process.
- `portal/internal/policy/engine.go` — Grant resolution: `(username, proxy_type, backend_server)` → active grant → backend account → `AuthResponse`. Denies on missing user, proxy-type mismatch, expired, revoked, or disabled user.
- `portal/internal/store/` — `Store` interface + `Memory` impl. Replace with Postgres-backed impl for persistence without touching handlers.
