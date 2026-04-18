# Phase 4 — protocol gaps

Known wire-protocol limits we chose not to hit during the POC. Each one is "current impl works for the happy path, fails on this specific production-y case".

Estimated: **~5-6 dev-days** total.

---

## 4.1 MySQL caching_sha2_password on the backend

**Status:** ⬜

### Why
The proxy speaks `mysql_native_password` on both directions. MySQL 8.0.34+ deprecates native; 8.4+ removes it from the default plugin set. Once ops tries to point the proxy at a modern MySQL without opting `mysql_native_password` back in, it breaks with the explicit error we added in `authenticateBackend` (which is helpful, but still a hard limit).

### Scope
- Implement `caching_sha2_password` on the **backend side only** (proxy → backend).
- Keep `mysql_native_password` on the **client side** — clients still need to send cleartext over TLS or a scramble, and our `AuthSwitchRequest` path handles both.

Out of scope:
- `sha256_password` (superseded by caching_sha2).
- `caching_sha2_password` on the client side — the proxy doesn't need it; it's the server of that side.

### Design sketch
- `internal/auth/mysql_sha2.go`: fast-auth SHA-256 digest + full-auth RSA-encrypted password.
- Server sends initial `AuthMoreData 0x03` (fast-auth OK) or `0x04` (perform full auth).
- Full auth: client requests pubkey (`0x02` request), server returns PEM-encoded pubkey, client sends RSA-OAEP-encrypted password XOR'd with the scramble.
- Needs TLS to skip the RSA dance (TLS already encrypts the password) — auto-detect TLS state on the backend conn.

### Acceptance criteria
- E2E: MySQL 8.4 container (default `caching_sha2_password`) works through the proxy without `ALTER USER ... IDENTIFIED WITH mysql_native_password`.
- E2E: TLS-to-backend short-circuits full-auth RSA dance.
- Error message from `AuthMoreData` path (our current helpful-hint) becomes unreachable — delete it.

### Rough effort
2 dev-days.

---

## 4.2 PostgreSQL SCRAM-SHA-256-PLUS (channel binding)

**Status:** ⬜

### Why
Some PG clients (notably `psycopg3` in strict mode, newer `pgx` with channel-binding required) refuse plain `SCRAM-SHA-256` over TLS and demand `SCRAM-SHA-256-PLUS` — the variant where the authentication binds to the TLS session. We currently advertise SCRAM-SHA-256 only; strict clients reject the connection.

### Scope
- Advertise both mechanisms when the client conn is TLS-wrapped.
- Implement the PLUS variant on the client side only (proxy-as-server) — forward to backend as regular SCRAM-SHA-256 (backend side stays simple).
- `xdg-go/scram` supports channel binding via `scram.Client.WithChannelBinding` / server equivalent.

Out of scope:
- Channel binding on the backend side (our proxy-initiated SCRAM to the backend doesn't benefit from it for the auth-remap use case).

### Design sketch
- In `authClientSCRAM`, when `client` is a `*tls.Conn`, advertise `SCRAM-SHA-256-PLUS,SCRAM-SHA-256` mech list and pick based on client selection.
- `tls.Conn.ConnectionState().TLSUnique` → used as the channel-binding value. Need to verify `xdg-go/scram` exposes the right hook; if not, a thin wrapper layer.
- `-client-tls-cb-required` flag to force PLUS and reject plain SCRAM on TLS conns (for strict-mode deployments).

### Acceptance criteria
- E2E: psql 16 with `channel_binding=require` connects through the proxy over TLS.
- Clients that don't support PLUS still work when not forced.

### Rough effort
1 dev-day.

---

## 4.3 MongoDB replica set handling

**Status:** ⬜

### Why
We advertise one backend IP. The mongo driver treats it as either a mongos or a `directConnection` target. For a real replica set we need to:
1. Proxy the `hello` / `isMaster` response so the driver sees the primary/secondary topology as-if the proxy IPs were the real hosts.
2. Re-route each driver-initiated connection (the driver dials each replica) through the proxy.

This is genuinely hard. Scope creep risk is high.

### Scope
- **Phase 4.3a (must):** document + test `directConnection=true` as the supported mode for replica sets — current behaviour; just make it explicit in docs.
- **Phase 4.3b (optional, defer):** implement replica-set rewriting. Needs a port-per-replica on the proxy + rewriting `hosts`, `primary`, `me` fields in `hello`.

Out of scope:
- Sharded cluster routing (mongos replacement).

### Design sketch (for 4.3b, if/when we do it)
- Proxy listens on N ports (one per replica), each configured with a backend.
- `forwardHelloWithMechOverride` rewrites `hosts`, `primary`, `me`, `setName`, etc. in the response doc to reference the proxy's own addresses.
- Config: `-backend` becomes repeatable or a list: `-backend primary:27017,sec1:27017,sec2:27017` mapped to three listener ports.

### Acceptance criteria (for 4.3a)
- README note added to the Mongo section: "For replica sets, set `directConnection=true` on the URI; full topology proxying is planned, not implemented."
- HLD §4 Mongo row updated with the same caveat.
- E2E test covering `directConnection=true` against a `mongo:7` replica-set container.

### Rough effort
- 4.3a: 0.5 dev-day (mostly docs + e2e).
- 4.3b: 2-3 dev-days.

---

## 4.4 PostgreSQL LISTEN/NOTIFY passthrough

**Status:** ⬜ (believed to work, not verified)

### Why
Our PG relay is byte-transparent after auth, so the async `NotificationResponse` ('A' message type) frames should pass through fine. But we've never tested long-lived connections with backend-initiated traffic, and `idle-timeout` may kill them prematurely.

### Scope
- E2E test: client `LISTEN foo;` then another conn `NOTIFY foo, 'hello';` — first conn sees the message.
- Verify `idle-timeout` doesn't close a `LISTEN`-ing connection (the client isn't sending, only receiving).

### Design sketch
- `proxy.Relay(client, backend, ...)` sets read deadline on `src` (backend). If no traffic flows client→backend for `idleTimeout`, the read dies on `client`, closing the tunnel. LISTEN clients fail.
- Fix: apply the deadline only to the client→backend direction (backend-initiated LISTEN traffic is the explicit reason to keep conn alive on the client side).
- Alternative: configurable `-listen-idle-ok` that disables idle timeout for the backend→client direction once a `LISTEN` query is seen.

### Acceptance criteria
- E2E test passes with a 60s-idle LISTEN connection receiving a NOTIFY.
- Default behaviour unchanged for non-LISTEN connections.

### Rough effort
0.5 dev-day (assuming bug found) or 1 dev-day (if framing turns out to need inspection).

---

## Done criteria for Phase 4

- MySQL 8.4 works without plugin override.
- Strict-channel-binding PG clients connect over TLS.
- Mongo replica-set limitation is clearly documented and tested.
- LISTEN/NOTIFY stays connected for the expected duration.
