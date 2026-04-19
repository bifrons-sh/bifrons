# Phase 2 — hardening

Security and scale polish. Not strictly blocking v1.0 but anyone running this in anger will want all five before trusting it with real traffic.

Estimated: **~5 dev-days** total.

---

## 2.1 Rate limiting on sensitive endpoints

**Status:** ✅

### Why
Currently the only backpressure is `-max-conns` (global proxy cap) and the HTTP server's own timeouts on the portal. A compromised client or leaked portal token can flood `/api/v1/auth` with brute-force lookups; there's no lockout, no budget, no spotlight. Rate limiting makes the cost of being noisy visible.

### Scope
- Per-username + per-source-IP token bucket on `/api/v1/auth`.
- Per-source-IP bucket on each proxy's accept loop (pre-handshake, before PBKDF2 runs — cheap defence against compute-DoS).
- Per-user creation budget on `POST /api/v1/grants`.
- Metric + log emitted when a bucket empties ("rate_limited" events tagged with the offending dimension).

Out of scope:
- Distributed rate limiting across portal replicas (needs cluster sessions — phase-2.4).
- Per-backend ratelimits.

### Design sketch
- `internal/ratelimit` package with a simple in-memory token-bucket keyed by string. Bucket config: `rate int`, `burst int`, `ttl time.Duration`.
- Middleware `requireAuthRateLimit(buckets, keyFn, next)` for HTTP paths.
- Proxy integration: in `Server.Serve`, after accept but before handler dispatch, reject at `sem`-equivalent point with a sleep-then-close.
- Config flags: `-auth-rate-per-ip`, `-auth-rate-per-user`, defaults `60/min` per IP, `30/min` per user.

### Acceptance criteria
- Exceeding the bucket returns 429 (portal) or closes with a bounded delay (proxy).
- Table test proves replenishment over time.
- No lock contention measurable at 1k req/s.

### Rough effort
1 dev-day.

---

## 2.2 PBKDF2 stored-credentials cache

**Status:** ✅

### Why
Mongo + PG SCRAM paths call `auth.SCRAMStoredCredentials(password, 15000)` on **every new connection** (~8–10ms of CPU). At 100 conn/s on a single core the proxy stops accepting. See HLD "Auth rate ceiling" note.

### Scope
- Bounded LRU cache keyed by `(username, sha256(password), salt_hex, iters)` → `scram.StoredCredentials`.
- TTL on entries (5m default) to bound how long a leaked DB mapping would help an attacker.
- Apply inside `protocol/mongo/auth.go:handleSASLExchange` and `protocol/postgres/auth.go:authClientSCRAM`.

Out of scope:
- Sharing the cache across proxy instances.
- Pre-computing stored creds when the portal creates the grant (separate spec, bigger change — see discussion below).

### Design sketch
- `internal/auth/scramcache.go` — minimal LRU using `container/list` + map, sized by count (`-scram-cache-size`, default 1024).
- Cache key: hex(sha256(password || "\x00" || salt || fmt(iters))) so length is fixed.
- Metrics: hit/miss/evict counters exported on the sidecar.

### Alternative worth noting
A bigger win is **computing stored creds when the grant is created** (plaintext password goes in, only stored-creds come out of the portal). That removes PBKDF2 from the hot auth path entirely. Trade-off: portal can never rotate the SCRAM iter count without regrants. Defer to post-v1.0.

### Acceptance criteria
- Micro-bench: hot path ~100x faster on cache hit.
- Race-clean, no goroutine contention visible under `-race`.
- Eviction triggers when size cap hit; verified in test.

### Rough effort
0.5 dev-day.

---

## 2.3 OIDC: real IdP e2e + admin mapping

**Status:** ✅ — Keycloak e2e covers the full login flow; `Session.IsAdmin` and the new dual-gate / trio-policy paths consume the OIDC subject as the load-bearing identity.

### Scope
- Keycloak testcontainer-backed e2e (`e2e/oidc_keycloak_test.go`): seed a realm + client + user with known groups, walk login→callback→grants-CRUD end-to-end.
- Map `Session.IsAdmin` → `domain.User.IsAdmin` on first-login: look up or create the portal user by `Subject` claim.
- Admin-only endpoints guarded (today everything is admin): `POST /users`, `POST /backends`, `POST /backends/:id/accounts`, `POST /grants/:id/approve`.
- Non-admin session can still read their own grants + request new ones.

Out of scope:
- SAML, LDAP, or any non-OIDC federation.
- Fine-grained RBAC beyond admin / non-admin.

### Design sketch
- `portal/internal/api/middleware.go` gains `requireAdmin(next)` that asserts `SessionFromContext(ctx).IsAdmin || staticBearerWasUsed`.
- `grants_handler.create` scopes `user_id` to `session.PortalUserID` for non-admins (admins can create for anyone).
- First-login user provisioning: `oidc/handlers.go:handleCallback` calls `store.GetUserByExternalID(sub)`; creates with defaults if missing.

### Acceptance criteria
- Keycloak container boots, admin user logs in, can CRUD; non-admin user logs in, can list own grants only.
- Unit test still passes (mock IdP unchanged).

### Rough effort
1-2 dev-days.

---

## 2.4 Cluster-safe session store

**Status:** ✅

### Why
`oidc.NewMemoryStore` on a single portal node doesn't survive horizontal scale — a session minted on node A is invisible on node B, so HTTP LB round-robin breaks user sessions.

### Scope
- New `oidc.SessionStore` implementation backed by the same persistence layer introduced in phase 1.1 (SQLite / Postgres).
- Redis is an option later if session volume outgrows the primary store.

Out of scope:
- Session pinning in the LB — we want stateless scaling.
- Cross-region session replication.

### Design sketch
- Table `oidc_sessions(id, subject, email, name, is_admin, expires_at)`.
- Cache layer on top: in-memory LRU with TTL ≤ 30s to keep the happy path single-query free.
- Sweeper: reuse the same background goroutine pattern as audit retention.

### Acceptance criteria
- Spin up two portal processes sharing a SQLite file; login on process A, call a guarded endpoint on process B → success.
- Existing memory store retained as `oidc.NewMemoryStore` for tests.

### Rough effort
1 dev-day after phase 1.1 lands.

---

## 2.5 mTLS cert rotation

**Status:** ✅

### Why
Client + backend TLS certs are loaded once at boot. Rotating them requires a restart, which drops all active connections. In any serious TLS estate certs rotate monthly.

### Scope
- File-watch on `-client-tls-cert`, `-client-tls-key`, `-backend-tls-cert`, `-backend-tls-key`, `-client-tls-ca`, `-backend-tls-ca`.
- On change: re-parse + hot-swap the `*tls.Config.GetCertificate`/`VerifyPeerCertificate` hooks.
- Existing connections keep the old cert (TLS session stays valid); new handshakes use the new cert.

Out of scope:
- Cert issuance (ACME, Vault PKI) — operator's responsibility, we just reload what they write.

### Design sketch
- `internal/tlsutil/reloader.go` with `type Reloader struct { current atomic.Pointer[tls.Certificate] }`.
- `tls.Config.GetCertificate = reloader.Get` — called per handshake, so the pointer swap takes effect at the next connection.
- File-watch via `fsnotify`; fallback to polling every 30s for filesystems without inotify.
- Log `cert_reloaded` + cert's `NotAfter` on every swap.

### Acceptance criteria
- Swap the cert file on disk mid-run → new connections present the new cert, verified with `openssl s_client` scraping.
- Malformed new cert → log `cert_reload_failed`, keep the old cert in place (no service disruption).

### Rough effort
1 dev-day.

---

## Done criteria for Phase 2

- `/api/v1/auth` shrugs off brute-force floods.
- Auth throughput per core is ~10× higher on cache hits.
- Admins and non-admins see the same OIDC flow but different capabilities.
- Two portal nodes behind a round-robin LB share sessions correctly.
- Rotating a TLS cert doesn't require a restart.
