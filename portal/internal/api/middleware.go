package api

import (
	"context"
	"crypto/subtle"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/babs/poc-proxies/internal/metrics"
	"github.com/babs/poc-proxies/portal/internal/oidc"
)

// requireProxyToken enforces a shared secret on proxy-facing endpoints.
// If token is empty, the guard is disabled (local-dev convenience).
func requireProxyToken(token string, next http.Handler) http.Handler {
	if token == "" {
		return next
	}
	want := []byte(token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := []byte(r.Header.Get("X-Portal-Token"))
		if subtle.ConstantTimeCompare(got, want) != 1 {
			writeErr(w, http.StatusUnauthorized, "invalid proxy token")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// sessionContextKey uniquely types the per-request OIDC session injected by
// requireUserAuth. Downstream handlers can call SessionFromContext to recover
// the authenticated operator identity for audit trails.
type sessionContextKey struct{}

// SessionFromContext returns the OIDC session associated with r, or nil when
// the request was authenticated via the static bearer (or OIDC is disabled).
func SessionFromContext(ctx context.Context) *oidc.Session {
	s, _ := ctx.Value(sessionContextKey{}).(*oidc.Session)
	return s
}

// requireUserAuth guards user-facing endpoints. It accepts EITHER a valid
// OIDC session cookie (when `provider` is configured) OR a static bearer
// token matching `staticToken`. Both empty = open (local-dev convenience).
//
// Two auth paths are supported simultaneously so operators can run OIDC for
// humans and bearer-tokens for automation on the same endpoints.
func requireUserAuth(provider *oidc.Provider, staticToken string, next http.Handler) http.Handler {
	// Everything disabled — no-op guard. Logged at router construction.
	if provider == nil && staticToken == "" {
		return next
	}
	want := []byte(staticToken)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// OIDC session cookie: if present and valid, inject the session and pass through.
		if sess := provider.LookupSession(r); sess != nil {
			ctx := context.WithValue(r.Context(), sessionContextKey{}, sess)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}
		// Fall back to static bearer when configured.
		if staticToken != "" {
			auth := r.Header.Get("Authorization")
			const prefix = "Bearer "
			if strings.HasPrefix(auth, prefix) {
				got := []byte(strings.TrimPrefix(auth, prefix))
				if subtle.ConstantTimeCompare(got, want) == 1 {
					next.ServeHTTP(w, r)
					return
				}
			}
		}
		writeErr(w, http.StatusUnauthorized, "authentication required")
	})
}

// requireUserAuthHTML is the browser-flavoured twin of requireUserAuth: on an
// unauthenticated hit it issues a 302 to /oidc/login instead of writing a JSON
// 401. Used by the operator SPA mount so humans land in the login flow rather
// than staring at a JSON body. When both guards are disabled (local dev) it
// degrades to a pass-through, matching requireUserAuth's behaviour.
func requireUserAuthHTML(provider *oidc.Provider, staticToken string, next http.Handler) http.Handler {
	if provider == nil && staticToken == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if sess := provider.LookupSession(r); sess != nil {
			ctx := context.WithValue(r.Context(), sessionContextKey{}, sess)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}
		// No static-bearer fallback here: browsers can't attach Authorization
		// headers on a plain navigation, so the only useful response is to
		// kick off the OIDC dance.
		if provider != nil {
			http.Redirect(w, r, "/oidc/login", http.StatusFound)
			return
		}
		writeErr(w, http.StatusUnauthorized, "authentication required")
	})
}

// sessionHandler returns the authenticated operator's session metadata.
// 200 + JSON when a session cookie is valid, 401 otherwise (middleware
// already short-circuits unauthenticated requests, so we only reach here
// on success). The payload is intentionally minimal: the UI uses it to
// decide whether to show admin affordances and who's logged in.
func sessionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	sess := SessionFromContext(r.Context())
	if sess == nil {
		// Static-bearer caller — no OIDC identity attached. Return a
		// synthetic principal so the UI can still render "logged in".
		writeJSON(w, http.StatusOK, map[string]any{
			"username": "api-bearer",
			"is_operator": true,
		})
		return
	}
	name := sess.Name
	if name == "" {
		name = sess.Email
	}
	if name == "" {
		name = sess.Subject
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"username": name,
		"email":    sess.Email,
		"subject":  sess.Subject,
		"is_operator": sess.IsOperator,
	})
}

// accessLog emits one structured line per request. Keeps latency visible without OTel.
func accessLog(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		logger.Info("http_request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"duration_ms", time.Since(start).Milliseconds(),
			"remote", r.RemoteAddr,
		)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// promMetrics records portal_request_duration_seconds{path,status}. Path labels
// are normalised to the ServeMux registered template so cardinality stays
// bounded (no IDs leak in). Disabled when reg is nil.
func promMetrics(reg *metrics.Registry, next http.Handler) http.Handler {
	if reg == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		path := normalisePath(r.URL.Path)
		reg.PortalRequest(path, strconv.Itoa(rec.status)).Observe(time.Since(start))
	})
}

// normalisePath collapses high-cardinality path segments (grant IDs, backend
// IDs, usernames) down to the stable template registered on the router. This
// keeps portal_request_duration_seconds label cardinality proportional to the
// handler count, not the request volume.
func normalisePath(p string) string {
	switch {
	case p == "/api/v1/auth":
		return p
	case p == "/api/v1/audit/query":
		return p
	case strings.HasPrefix(p, "/api/v1/grants/status/"):
		return "/api/v1/grants/status/"
	case p == "/api/v1/grants":
		return p
	case strings.HasPrefix(p, "/api/v1/grants/"):
		return "/api/v1/grants/"
	case p == "/api/v1/users":
		return p
	case p == "/api/v1/backends":
		return p
	case strings.HasPrefix(p, "/api/v1/backends/"):
		return "/api/v1/backends/"
	case strings.HasPrefix(p, "/oidc/"):
		return p
	default:
		return "other"
	}
}
