package api

import (
	"context"
	"crypto/subtle"
	"log/slog"
	"net/http"
	"strings"
	"time"

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
// token matching `staticToken`. Both empty = open (local-dev convenience),
// matching the previous scaffold behaviour.
//
// The design favours gradual rollout: operators can deploy OIDC alongside
// existing bearer-using automation, then retire the bearer when all callers
// have migrated.
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
