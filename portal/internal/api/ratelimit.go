package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/babs/poc-proxies/internal/auth"
	"github.com/babs/poc-proxies/internal/ratelimit"
)

// bucketSweepInterval is how often idle rate-limit buckets are evicted. Tied
// to the buckets' own TTL (PerMinute uses 10m): sweeping at a fraction of the
// TTL keeps the map bounded without a tight busy-loop.
const bucketSweepInterval = 2 * time.Minute

// startBucketSweeper launches a single goroutine that periodically evicts idle
// buckets from every supplied limiter, stopping when ctx is cancelled.
//
// Security: the per-IP limiter is keyed on an attacker-controllable dimension.
// Buckets.Sweep() is otherwise never called in production, so a spoofed-IP
// flood would grow the bucket map without bound and OOM the portal. Bounding
// the map to the unique-key rate across the bucket TTL closes that DoS vector.
func startBucketSweeper(ctx context.Context, logger *slog.Logger, buckets ...*ratelimit.Buckets) {
	// Drop nil limiters (a dimension disabled via config) so the loop body
	// doesn't have to nil-check on every tick.
	active := make([]*ratelimit.Buckets, 0, len(buckets))
	for _, b := range buckets {
		if b != nil {
			active = append(active, b)
		}
	}
	if len(active) == 0 {
		return
	}
	go func() {
		t := time.NewTicker(bucketSweepInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				for _, b := range active {
					b.Sweep()
				}
			}
		}
	}()
}

// RateLimitMetrics carries the two counters surfaced via /metrics as
// rate_limited_total{dimension="ip|user"}. Exported so main() can register
// a snapshot callback on the obs sidecar; Inc* is called from middleware.
type RateLimitMetrics struct {
	ip   atomic.Uint64
	user atomic.Uint64
}

// NewRateLimitMetrics returns a zeroed counter pair. Safe for concurrent use.
func NewRateLimitMetrics() *RateLimitMetrics { return &RateLimitMetrics{} }

// Snapshot returns the current (ip, user) counts. Lock-free; a reader may see
// a one-event-behind value — acceptable for /metrics scraping.
func (m *RateLimitMetrics) Snapshot() (ip, user uint64) {
	return m.ip.Load(), m.user.Load()
}

// KeyFn extracts a rate-limit key from an in-flight HTTP request. Returns ""
// to skip the bucket for this dimension (e.g. user key when the body hasn't
// been parsed yet and we couldn't pull a username).
type KeyFn func(r *http.Request) string

// ClientIPKey extracts the host portion of r.RemoteAddr. X-Forwarded-For is
// NOT trusted — anyone can set it; the portal should be behind a trusted
// reverse proxy that rewrites RemoteAddr if per-real-client limiting matters
// in that topology. Keeps the surface tight by default.
func ClientIPKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// Fall back to the raw string; some test harnesses set RemoteAddr
		// without a port, and we'd rather key on *something* than drop the
		// check silently.
		return r.RemoteAddr
	}
	return host
}

// AuthUsernameKey pulls `username` from a buffered copy of the /api/v1/auth
// body. Returns "" if decoding fails (the downstream handler will 400 anyway,
// so the user-dimension bucket is simply skipped for the malformed request).
//
// Must be called BEFORE decodeJSONBody consumes r.Body in the handler.
// requireAuthRateLimit handles the body-restore dance itself.
func AuthUsernameKey(body []byte) string {
	var req auth.LookupRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return ""
	}
	return req.Username
}

// GrantUserIDKey pulls `user_id` from a buffered copy of the /api/v1/grants
// POST body. Same contract as AuthUsernameKey.
func GrantUserIDKey(body []byte) string {
	var req struct {
		UserID string `json:"user_id"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return ""
	}
	return req.UserID
}

// requireAuthRateLimit wraps next with per-IP and (optionally) per-user
// token-bucket limits. When a bucket is empty the handler short-circuits with
// 429 and increments the matching dimension counter.
//
// The per-user bucket needs the request body (to pull username / user_id) so
// this middleware buffers the body into memory (bounded by rateLimitBodyLimit)
// and re-assigns r.Body so the downstream handler still reads the full stream.
// For the endpoints covered (auth lookup, grant create) the body is a tiny
// JSON object — the buffer is effectively free.
//
// Either bucket may be nil; passing both nil leaves next untouched.
func requireAuthRateLimit(
	ipBuckets, userBuckets *ratelimit.Buckets,
	userKey func(body []byte) string,
	metrics *RateLimitMetrics,
	next http.Handler,
) http.Handler {
	if ipBuckets == nil && userBuckets == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// IP check first — it doesn't need the body, so a flood from a single
		// source trips here without paying the body-read cost.
		if ipBuckets != nil {
			if key := ClientIPKey(r); key != "" && !ipBuckets.Allow(key) {
				metrics.ip.Add(1)
				writeErr(w, http.StatusTooManyRequests, "rate limit exceeded")
				return
			}
		}
		// User check — only when both a user bucket is configured AND the
		// caller supplied an extractor. Body is read into memory, restored
		// via http.NoBody-equivalent so the handler can decode it again.
		if userBuckets != nil && userKey != nil && r.Body != nil {
			// Buffer the body so the downstream handler can decode it again.
			// MaxBytesReader caps the read to what the handler would accept
			// anyway; oversized payloads fall through to the 413 path below.
			lr := http.MaxBytesReader(w, r.Body, rateLimitBodyLimit)
			buf, err := io.ReadAll(lr)
			_ = r.Body.Close()
			if err != nil {
				var mbe *http.MaxBytesError
				if errors.As(err, &mbe) {
					writeErr(w, http.StatusRequestEntityTooLarge, "request body too large")
					return
				}
				writeErr(w, http.StatusBadRequest, "invalid body")
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(buf))
			if key := userKey(buf); key != "" && !userBuckets.Allow(key) {
				metrics.user.Add(1)
				writeErr(w, http.StatusTooManyRequests, "rate limit exceeded")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// rateLimitBodyLimit mirrors defaultBodyLimit — keeping the buffer bounded
// matches what the downstream handler would accept anyway, so the limiter
// never reads more than the handler would have read itself.
const rateLimitBodyLimit = defaultBodyLimit

// withPOSTOnly routes POST requests to `post` and everything else to `other`.
// Used to rate-limit POST /api/v1/grants (create) without throttling GET/PATCH
// on the same collection path (list, update by admins).
func withPOSTOnly(post, other http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			post.ServeHTTP(w, r)
			return
		}
		other.ServeHTTP(w, r)
	})
}

// requireIPRateLimit applies only the per-IP bucket (no body buffering, no
// per-user key). Intended for sub-resources like /grants/:id/approve|deny|claim
// where the body is either empty or a small opaque payload and we just want
// to cap burst traffic per remote. Skips entirely when ipBuckets is nil so
// tests / local-dev don't need to configure limits.
func requireIPRateLimit(ipBuckets *ratelimit.Buckets, metrics *RateLimitMetrics, next http.Handler) http.Handler {
	if ipBuckets == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if key := ClientIPKey(r); key != "" && !ipBuckets.Allow(key) {
			metrics.ip.Add(1)
			writeErr(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}
		next.ServeHTTP(w, r)
	})
}
