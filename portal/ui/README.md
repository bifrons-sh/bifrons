# Portal UI

Operator-facing SPA served under `/ui/*` by the portal Go binary.

## TL;DR

```sh
pnpm -C portal/ui install
pnpm -C portal/ui build     # writes to portal/internal/api/ui/dist/
go build ./...              # Go embed picks up the freshly-built assets
```

(Use `npm` interchangeably if pnpm isn't available.)

## Stack

- Plain TypeScript, no framework. Hash-based router.
- Vite for dev + production bundling.
- Target bundle: ≤ 50 KB gzipped.

## Dev loop

```sh
pnpm -C portal/ui dev
```

Runs `vite dev` on `http://127.0.0.1:5173`. API + OIDC calls are proxied
to `http://127.0.0.1:8080` (see `vite.config.ts`). Start the portal there
with OIDC disabled **or** configured to accept `127.0.0.1:5173` as an
allowed redirect URL for end-to-end auth testing.

## Production build

Use `make ui` from the repo root rather than `pnpm build` directly: it
prunes stale outputs first while preserving the tracked `dist/.gitkeep`
stub, then runs Vite. The build emits hashed JS/CSS and an `index.html`
into `../internal/api/ui/dist/`, embedded into the Go binary via
`//go:embed all:dist`. Run `go build ./...` afterwards to refresh the
binary.

If you never run the frontend build, the Go binary still ships — it
embeds the static placeholder under `../internal/api/ui/placeholder/`,
which points operators at this README. The portal logs a single
`ui_bundle_missing` warning at startup so the degraded mode is visible
in production logs.

## CSP

The portal serves the SPA behind:

```
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';
```

That forbids inline `<script>` and `onclick=` handlers — wire events via
`addEventListener` only. Styles may still be inline (Vite injects some).

## Tests

```sh
pnpm -C portal/ui typecheck    # tsc --noEmit
```

Go-side: `go test ./portal/internal/api/ui/...` covers the embed,
security headers, and SPA fallback.
