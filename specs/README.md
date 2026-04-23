# Specs — post-POC roadmap

This folder tracks everything that's **not yet done** but is on the table. The POC itself (3 proxies + portal + auth remap + audit shipping + OIDC scaffold) is complete and lives in the main tree — see [HLD.md](../HLD.md) for design, [README.md](../README.md) for ops.

Each file below describes one **phase**: a coherent batch of work with its own goals, scope, design sketch, and acceptance criteria. Phases are loosely ordered by dependency and risk, not strictly sequential — some items can land in parallel.

## Phases

| # | File | Theme | Estimated effort |
|---|---|---|---|
| 1 | [phase-1-v1.0-blockers.md](phase-1-v1.0-blockers.md) | Persistence, approval flow, audit retention, secret handling, mid-session revocation | ~10 dev-days |
| 2 | [phase-2-hardening.md](phase-2-hardening.md) | Rate limit, PBKDF2 cache, OIDC admin mapping, cluster-safe sessions, mTLS rotation | ~5 dev-days |
| 3 | [phase-3-observability.md](phase-3-observability.md) | Latency histograms, OTel tracing, audit-shipper metrics | ~3 dev-days |
| 4 | [phase-4-protocol-gaps.md](phase-4-protocol-gaps.md) | MySQL caching_sha2, PG SCRAM-PLUS, Mongo replica set, PG LISTEN/NOTIFY | ~5-6 dev-days |
| 5 | [phase-5-ops.md](phase-5-ops.md) | Dockerfile, Helm, CI, runbook, ADRs | ~3 dev-days |
| 6 | [phase-6-future.md](phase-6-future.md) | Backend pooling, web UI, audit-read API, CLI | ~10-15 dev-days |
| 7 | [phase-7-validation-ui.md](phase-7-validation-ui.md) | Grant requests views (requester / DB-derived validator / admin) | ~4 dev-days |

## Minimum viable v1.0

If we need to cut a v1.0 soon, the smallest coherent set is **all of phase 1** + **phase 5** (ops/deployment) + the observability items marked *required-for-v1.0* in phase 3. Everything else can ship in 1.x minors.

## How to use this folder

- **Before starting an item**, read its spec. If the design sketch no longer matches reality (code drifted, dependencies changed), update the spec first, then code.
- **When finishing an item**, mark it ✅ in the phase file's checklist. Move notes about surprises into an [ADR](phase-5-ops.md#adrs).
- **When an item turns out to be the wrong idea**, strike it through and add a one-line "why not" — don't delete, the reasoning is useful later.

## Out of scope for these phases

- Full authorization engine (per-query policy eval) — the design choice is "backend enforces via role GRANTs", see HLD §4b.
- Multi-region / active-active portal — single-region is the v1 target.
- Custom identity federation — OIDC is the only planned human-auth path.
