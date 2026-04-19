# Phase 5 — ops / deployment

HLD §7 is entirely ⬜ today. This phase closes that section and produces the artefacts ops teams expect to see before they'll deploy something.

Estimated: **~3 dev-days**.

---

## 5.1 Dockerfile per binary

**Status:** ✅ (*required for v1.0*)

### Why
Four binaries (`mysql-proxy`, `postgres-proxy`, `mongo-proxy`, `portal`) → four Dockerfiles. Trying to share one with build args is more pain than copy-paste.

### Scope
- `Dockerfile.mysql-proxy`, `Dockerfile.postgres-proxy`, `Dockerfile.mongo-proxy`, `Dockerfile.portal` (or per-binary `cmd/*/Dockerfile` — pick one layout, document).
- Multi-stage: `golang:1.26-bookworm` builder → `gcr.io/distroless/static-debian12:nonroot` runtime.
- OCI labels (`org.opencontainers.image.{source,created,version,revision}`) wired from the same `-ldflags -X` values the Makefile already injects.
- `CGO_ENABLED=0` everywhere (no surprise glibc dependence).
- `.dockerignore` excluding `bin/`, `.git/`, `.claude/`, `e2e/` (tests don't belong in the image).

Out of scope:
- Alpine variants.
- ARM builds (trivial once Docker buildx is wired — defer to 5.3 CI).

### Design sketch
- Templates via the `dockerfile-init` skill.
- Make targets: `make docker-build-mysql-proxy` etc., or one loop over the binary list.
- `EXPOSE` the default listen port for each protocol + the `9091/9095` sidecar ports.
- `USER nonroot:nonroot` at runtime (distroless provides it).

### Acceptance criteria
- `docker build -f Dockerfile.postgres-proxy .` produces an image under 20 MB.
- `docker inspect` shows the OCI labels with the build metadata.
- `docker run` with the same flags as a host binary behaves identically in the e2e suite.

### Rough effort
0.5 dev-day (with the skill).

---

## 5.2 Helm chart (or Kustomize)

**Status:** ⬜

### Why
One chart for the whole system. Operators deploy proxies + portal together with a single `helm install`.

### Scope
- `deploy/helm/janusgate/` (or whatever name lands from the earlier discussion).
- Sub-charts or templates for each proxy + the portal.
- ConfigMap + Secret for: `PORTAL_PROXY_TOKEN`, `PORTAL_USER_TOKEN`, `PORTAL_OIDC_*`, `PROXY_AUTH_URL`, `PROXY_AUDIT_URL`, `PROXY_PORTAL_TOKEN`.
- NetworkPolicy templates (deny-all default, explicit allow for proxy→portal, proxy→backend, client→proxy).
- Sensible defaults that boot a working demo against an embedded portal + an externally-configured backend address.

Out of scope:
- Operator (CRD) — Helm is sufficient for v1.0.
- Service-mesh specifics (Istio VirtualService, Linkerd, etc.) — document a recipe, don't ship templates.

### Acceptance criteria
- `helm template deploy/helm/janusgate/ | kubectl apply --dry-run=server -f -` passes on a recent k8s.
- Default values produce a portal reachable by the proxies out of the box.
- Secrets never land in the ConfigMap (`values.yaml` has a `proxyToken: ""` default; the chart refuses to start if unset in non-dev mode).

### Rough effort
1 dev-day.

---

## 5.3 CI pipeline

**Status:** ⬜

### Why
Right now everything is run by hand. We need something that runs `vet`, `lint`, `test -race`, `e2e`, builds Docker images, and publishes them.

### Scope
- GitHub Actions workflow (single file, matrix on Go version for future-proofing).
- Jobs:
  1. `lint` — `golangci-lint run --tests=false` and `run ./...`.
  2. `test` — `go test -race -count=1 ./...`.
  3. `e2e` — `go test -tags=e2e -timeout=600s -count=1 ./e2e/...` (needs Docker in Actions runner).
  4. `build` — matrix over `{mysql,postgres,mongo}-proxy + portal` × `{linux/amd64, linux/arm64}`.
  5. `docker-publish` — only on tag events, pushes to ghcr.io.
- Dependabot config for Go modules + GitHub Actions.

Out of scope:
- GitLab CI — can be added as a second file if/when needed.
- Release notes automation (`goreleaser`) — nice-to-have, defer.

### Design sketch
- `.github/workflows/ci.yml` orchestrates the above.
- `.github/workflows/release.yml` fires on `v*.*.*` tags.
- Use `golangci/golangci-lint-action@v6` pinned, `actions/setup-go@v5`.
- Cache: `~/go/pkg/mod`, `~/.cache/go-build`, keyed by `go.sum`.

### Acceptance criteria
- A PR opening from a clone runs the full pipeline green.
- `git tag v0.1.0 && git push --tags` publishes four images to ghcr.io.

### Rough effort
1 dev-day.

---

## 5.4 Runbook

**Status:** ⬜

### Why
"What do I do at 3 am when the pager goes off?" should not be answered by reading the HLD.

### Scope
- `docs/runbook.md` (separate from `specs/` because it's perma-doc, not a future task).
- Sections:
  - Architecture cheat-sheet (1 paragraph + 1 diagram).
  - Alerts we emit and what each means.
  - Top incidents and recovery steps:
    - Portal unreachable → proxies reject all new auths; clients see 401. Restore portal, no proxy restart needed.
    - Backend down → proxy connects fail with "backend connection failed" logs. Swap backend DNS, portal doesn't need update.
    - Leaked portal token → rotate via `-proxy-token` on portal + redeploy proxies with the new `PROXY_PORTAL_TOKEN`.
    - Audit backlog growing → check shipper metrics; portal probably unreachable or slow.
    - OIDC IdP down → proxies unaffected (they use the portal-token path); user-facing CRUD is blocked. Fall back to static bearer.
  - How to do common operator tasks: create an emergency grant, revoke a grant, rotate a backend password, force-drain a proxy.

Out of scope:
- Generic SRE 101 (assume the reader knows their on-call platform).

### Acceptance criteria
- Each alert emitted by the proxy or portal has a corresponding runbook entry.
- A fresh on-caller can resolve a "portal unreachable" page without paging the team lead.

### Rough effort
0.5 dev-day.

---

## 5.5 ADRs (Architectural Decision Records)

**Status:** ⬜

### Why
Several non-obvious decisions are scattered across inline comments (`CLIENT_DEPRECATE_EOF` drop, proxy-side DB restriction drop, PBKDF2 ceiling, OIDC-and-bearer dual guard, allow-list of PG startup params). Without ADRs these rot or get re-litigated by every new contributor.

### Scope
- `docs/adr/0001-drop-db-restriction-in-proxy.md`
- `docs/adr/0002-disable-mysql-deprecate-eof.md`
- `docs/adr/0003-pbkdf2-iter-count-and-caching-strategy.md`
- `docs/adr/0004-dual-guard-oidc-and-static-bearer.md`
- `docs/adr/0005-pg-startup-param-allow-list.md`
- Each ADR follows the standard template: *Context → Decision → Consequences → Status*.
- Use the `adr-create` skill where possible.

### Acceptance criteria
- Every inline "// Why this oddity…" comment longer than three lines links to an ADR.
- `docs/adr/README.md` lists the ADRs in order.

### Rough effort
0.5 dev-day.

---

## Done criteria for Phase 5

- `docker run ghcr.io/<org>/janusgate-portal` Just Works.
- `helm install` produces a ready-to-use stack.
- CI on every PR catches regressions before review.
- On-call has a runbook; architects have ADRs.
