# Phase 3 — observability

What the sidecar emits today is enough to prove the process is alive, not enough to debug *why it's slow* or *where a specific user's query went*. This phase closes that gap.

Estimated: **~3 dev-days**.

---

## 3.1 Latency histograms

**Status:** ✅ (*required for v1.0*)

### Why
`/metrics` today exposes `proxy_uptime_seconds`, `proxy_connections_{accepted,rejected,active}`, and `proxy_build_info`. All gauges or counters, zero latency visibility. When someone reports "connections are slow", we can't answer with data.

### Scope
- Histograms for:
  - `proxy_auth_lookup_duration_seconds` (portal HTTP call)
  - `proxy_backend_dial_duration_seconds`
  - `proxy_handshake_duration_seconds` (auth phase end-to-end)
  - `proxy_connection_duration_seconds` (full lifecycle, at disconnect)
  - `portal_request_duration_seconds{path,status}` on the portal side
- Swap the hand-rolled `fmt.Fprintf` in `internal/obs/sidecar.go` for `github.com/prometheus/client_golang/prometheus/promhttp`.

Out of scope:
- Per-query latency — that's the tracing spec (3.2) territory.

### Design sketch
- `internal/metrics` package with a registry shared by proxy + portal; expose `RegisterOn(mux *http.ServeMux)`.
- Protocol handlers get a `metrics.Observer` field (nil-safe) to record durations.
- Buckets: default Prom histogram buckets are fine for dial+lookup; connection duration needs longer tail (`60m, 4h, 24h`).
- Keep `proxy_build_info` exactly as-is — existing alerts key off that.

### Acceptance criteria
- Curl `/metrics` after running e2e returns well-formed Prom text with histograms.
- `promtool check metrics` passes.
- Grafana sample dashboard JSON committed under `specs/assets/grafana-proxy.json` (optional but nice).

### Rough effort
1 dev-day.

---

## 3.2 OpenTelemetry tracing

**Status:** ✅

### Why
HLD §10.2 is entirely ⬜. Spans that follow one connection from `accept` → `auth` → `backend dial` → `relay queries` are the difference between "works on my machine" debugging and being able to answer "where did Alice's query spend the 4 seconds?"

### Scope
- OTel SDK init in every main, configurable via the standard OTel env vars (`OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_SERVICE_NAME`, etc.) so there's nothing proprietary to document.
- Spans:
  - `proxy.accept` (root) — client conn, source IP tag, protocol
  - `proxy.auth` — portal HTTP call inside
  - `proxy.backend_dial`
  - `proxy.relay` — long-lived, ends at disconnect; carries query-count + byte-count attributes
  - `portal.auth_lookup`, `portal.audit_ingest`, `portal.grant_create`, etc.
- Trace ID propagation:
  - Proxy mints the root trace for a client conn.
  - Injected into `auth.LookupRequest` via new `TraceID` field; portal continues the trace.
  - Audit entries carry `trace_id` — already a field on `domain.AuditEntry`, just populate it.

Out of scope:
- Span-to-log correlation UI (that's the exporter's concern).
- Span sampling policy beyond parent-based.

### Design sketch
- `internal/tracing` wrapper that sets up an `OTLP/http` exporter, no-ops if `OTEL_EXPORTER_OTLP_ENDPOINT` is empty.
- Handler signatures don't need to change — use `context.Context` propagation throughout (already threaded).
- Keep trace-ID logging alongside existing slog fields: `log.With("trace_id", traceID)`.

### Acceptance criteria
- With Jaeger (testcontainer), a full client connection produces a single trace with the expected span tree.
- `trace_id` appears in audit entries stored at the portal.
- Disabled by default (no OTLP endpoint) → zero allocations in the hot path (use `otel.Tracer("noop")`).

### Rough effort
2 dev-days.

---

## 3.3 Audit-shipper metrics

**Status:** ⬜

### Why
`internal/audit.Client.Stats()` returns `sent / failed / dropped`. Already collected, not yet exposed. Ops can't see if the shipper is silently dropping under pressure.

### Scope
- Register shipper metrics on the same sidecar registry:
  - `proxy_audit_sent_total`
  - `proxy_audit_failed_total`
  - `proxy_audit_dropped_total`
  - `proxy_audit_queue_depth` (new — requires exposing `len(c.ch)`)
- Same for portal side: `portal_audit_entries_total`, `portal_audit_batches_accepted_total`.

### Acceptance criteria
- Forcing drops in a test (saturate buffer with slow server) increments `proxy_audit_dropped_total`.
- Metrics survive `go test -race`.

### Rough effort
0.5 dev-day.

---

## Done criteria for Phase 3

- SRE can open `/metrics` and answer "p99 auth latency", "backend dial success rate", "audit shipper health".
- One client connection yields one root trace visible in Jaeger.
- Audit backlog / drops are not silent.
