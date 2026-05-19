# Portal UI

Operator-facing SPA served under `/ui/*` by the portal Go binary.

## TL;DR

```sh
pnpm -C portal/ui install --ignore-scripts
pnpm -C portal/ui build     # writes to portal/internal/api/ui/dist/
go build ./...              # Go embed picks up the freshly-built assets
```

`--ignore-scripts` is recommended permanently: none of the SPA deps need
build-time native compilation, and it shuts down the obvious npm
supply-chain attack vector (compromised maintainer ships malicious
`postinstall`). The demo Dockerfile (`dev/portal.Dockerfile`) carries the
same flag.

## Stack

- React 18 + TypeScript + Vite 5
- [Mantine 7](https://mantine.dev/) for UI primitives + form/notification stacks
- [TanStack Query](https://tanstack.com/query) for server-state, cache, mutations
- [react-router-dom 6](https://reactrouter.com/) with `BrowserRouter basename="/ui"`
- [Tabler Icons](https://tabler.io/icons)

The compiled bundle lands around ~170 KB JS + ~30 KB CSS gzipped. That is
above the v0.1 target (≤50 KB) but justified by the framework + form
machinery the operator console now ships.

## Dev loop

```sh
pnpm -C portal/ui dev
```

Runs `vite dev` on `http://127.0.0.1:5173`. API + OIDC calls are proxied
to the portal on `http://127.0.0.1:18080` (see `vite.config.ts`). The
quickest way to back it with a real portal + Keycloak is the demo stack:

```sh
docker compose -f dev/compose.yml up -d --build
bash dev/seed.sh
# then either:
#   - point a browser at http://127.0.0.1:18080/ui/ for the embedded SPA
#   - or `pnpm dev` here and use http://127.0.0.1:5173/ui/ for HMR
```

For the HMR path to authenticate end-to-end, add `http://127.0.0.1:5173/oidc/callback`
to the Keycloak client's `redirectUris` (in `dev/keycloak/realm.json`)
before bringing up the stack.

## Production build

`make ui` from the repo root is still the canonical way to produce a
bundle for the Go embed:

- prunes stale outputs while keeping the `dist/.gitkeep` stub so
  `//go:embed all:dist` always compiles on a fresh clone,
- runs `tsc -b && vite build`,
- emits hashed JS/CSS + `index.html` into `../internal/api/ui/dist/`.

Then `go build ./...` re-embeds. If you never run the UI build, the Go
binary still boots — it embeds a static placeholder under
`../internal/api/ui/placeholder/` and logs a `ui_bundle_missing` warning
at startup so the degraded mode is visible in production logs.

## Routing

`BrowserRouter` with `basename="/ui"`. The Go side
(`portal/internal/api/ui/ui.go`) falls back to `index.html` for any
extensionless path under `/ui/*`, so deep links like `/ui/grants/abc123`
hit the SPA and let react-router resolve them.

URL state lives in the path + search params, never the hash. The v0.1
hash router is gone; `main.tsx` carries a tiny one-shot rewrite that
upgrades old `#/grants` bookmarks to `/grants`.

## CSP

The portal serves the SPA behind:

```
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';
```

`script-src 'self'` forbids inline JS — `addEventListener` only.
`style-src 'unsafe-inline'` is intentionally left open because Mantine /
emotion inject `<style>` blocks at runtime; tightening this needs a
nonce strategy on the Go side and is a planned hardening.

## Tests

```sh
pnpm -C portal/ui typecheck    # tsc --noEmit -p tsconfig.json
```

Go-side: `go test ./portal/internal/api/ui/...` covers the embed,
security headers, and SPA fallback.
