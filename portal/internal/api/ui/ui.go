// Package ui serves the operator-facing single-page application.
//
// Assets are produced by the Vite pipeline under portal/ui/ and written to
// portal/internal/api/ui/dist/. They're embedded at Go-build time so the
// portal binary is self-contained. A sibling placeholder/ directory holds
// a static "UI not built" page that's also embedded; the handler prefers
// the real dist bundle when present and falls back to the placeholder
// otherwise. That keeps `go build` working on a fresh clone without ever
// running pnpm.
package ui

import (
	"embed"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
)

// distFS holds every file under dist/. Using `all:` makes the embed
// include dot-files (notably the .gitkeep stub that keeps the directory
// present on a fresh clone) so the embed directive always compiles.
//
//go:embed all:dist
var distFS embed.FS

// placeholderFS holds the "UI not built" fallback page used when the
// real Vite bundle is absent from dist/.
//
//go:embed placeholder
var placeholderFS embed.FS

// chooseFS returns the dist sub-FS when the real Vite bundle is present
// (signalled by dist/index.html), otherwise the placeholder sub-FS, plus
// a bool reporting which one was picked (true = real bundle).
func chooseFS() (fs.FS, bool) {
	distSub, err := fs.Sub(distFS, "dist")
	if err == nil {
		if _, statErr := fs.Stat(distSub, "index.html"); statErr == nil {
			return distSub, true
		}
	}
	placeholderSub, err := fs.Sub(placeholderFS, "placeholder")
	if err != nil {
		// Impossible in practice: the embed directive guarantees
		// placeholder/ exists at compile time.
		panic("ui: embedded placeholder/ missing: " + err.Error())
	}
	return placeholderSub, false
}

// Handler returns an http.Handler that serves the embedded SPA bundle under
// /ui/*. It strips the /ui prefix, sets strict security headers (tight CSP
// compatible with a no-inline-script build), and falls back to index.html
// for client-side routes — a standard SPA pattern.
//
// When the real Vite bundle is missing from the embedded dist/, the
// handler serves the static "UI not built" placeholder and emits a single
// startup warning via logger so operators notice the degraded mode in
// production logs. A nil logger is allowed for tests.
//
// The CSP is intentionally strict: no inline scripts (wouldn't pass without
// `unsafe-inline`), no third-party origins (`default-src 'self'`). Styles
// still allow `'unsafe-inline'` because Vite-injected <style> blocks and
// framework-agnostic toolchains frequently emit inline style attributes;
// tightening this further is a follow-up.
func Handler(logger *slog.Logger) http.Handler {
	sub, real := chooseFS()
	if !real && logger != nil {
		logger.Warn("ui_bundle_missing",
			"detail", "embedded dist/ has no index.html; serving fallback placeholder",
			"fix", "run `make ui` to build the SPA, then rebuild the portal binary")
	}
	fileServer := http.FileServer(http.FS(sub))

	return http.StripPrefix("/ui", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setSecurityHeaders(w)

		// SPA fallback strategy:
		//   - "/" and "" → serve index.html directly (avoid the
		//     FileServer's default directory → "./" redirect loop
		//     that kicks in after StripPrefix).
		//   - Paths with a file extension → delegate to the embedded
		//     FileServer; a real miss yields 404, as desired.
		//   - Extensionless routes like "/grants" that don't map to
		//     a real asset → rewrite to /index.html so the client
		//     router can take over.
		clean := strings.TrimPrefix(r.URL.Path, "/")
		if clean == "" || !strings.Contains(clean, ".") {
			if clean != "" {
				if _, err := fs.Stat(sub, clean); err == nil {
					fileServer.ServeHTTP(w, r)
					return
				}
			}
			serveIndex(w, r, sub)
			return
		}
		fileServer.ServeHTTP(w, r)
	}))
}

// serveIndex writes dist/index.html with a short cache directive. Pulled
// out of the main handler so the two fallback branches (root + SPA route)
// share one implementation.
func serveIndex(w http.ResponseWriter, _ *http.Request, sub fs.FS) {
	data, err := fs.ReadFile(sub, "index.html")
	if err != nil {
		http.Error(w, "ui not built", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// No-cache on the HTML shell so a fresh asset manifest is always
	// picked up after a deploy; hashed JS/CSS bundles are still
	// immutably cacheable by the FileServer's own defaults.
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(data)
}

// setSecurityHeaders applies the headers required for the UI surface.
// Kept as a named function so tests can assert on a single source of truth.
func setSecurityHeaders(w http.ResponseWriter) {
	// CSP: same-origin scripts only, no inline JS (UI wires events via
	// addEventListener). Styles permit inline as a pragmatic concession
	// to Vite-style bundles and small utility stylesheets.
	w.Header().Set("Content-Security-Policy",
		"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
	w.Header().Set("X-Content-Type-Options", "nosniff")
}
