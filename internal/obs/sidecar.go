package obs

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync/atomic"
	"time"
)

// BuildInfo is populated via -ldflags -X in the cmd/* binaries.
type BuildInfo struct {
	Version        string
	Commit         string
	BuildTimestamp string
	Builder        string
}

// StatsFn exposes live proxy counters to the metrics endpoint.
type StatsFn func() (accepted, rejected, active uint64)

// AuditStatsFn exposes portal audit counters. Optional — only the portal
// binary plugs this in today. Returns (total rows, cumulative pruned).
type AuditStatsFn func() (total, prunedTotal uint64)

// GrantStatsFn exposes portal grant-lifecycle counters. Returns the
// cumulative count of grants flipped APPROVED->EXPIRED by the sweeper.
type GrantStatsFn func() (expiredTotal uint64)

// RateLimitStatsFn exposes rate-limit rejection counters. Returns cumulative
// rejections broken down by the dimension that caused the trip (ip | user).
// Optional — portals and proxies register the callback only when rate limiting
// is enabled (and on the proxy, only the "ip" dimension is ever non-zero).
type RateLimitStatsFn func() (ip, user uint64)

// Server is a tiny HTTP sidecar for /healthz and /metrics (Prometheus text format).
type Server struct {
	addr       string
	ln         net.Listener
	logger     *slog.Logger
	info       BuildInfo
	stats      StatsFn
	auditStats AuditStatsFn
	grantStats GrantStatsFn
	rlStats    RateLimitStatsFn
	ready      atomic.Bool
	srv        *http.Server
	started    time.Time
}

func NewServer(addr string, logger *slog.Logger, info BuildInfo, stats StatsFn) *Server {
	return &Server{
		addr:    addr,
		logger:  logger.With("component", "obs"),
		info:    info,
		stats:   stats,
		started: time.Now(),
	}
}

// SetAuditStats registers (or clears, with nil) the audit counter callback.
// Kept separate from NewServer so every existing caller keeps working.
func (s *Server) SetAuditStats(fn AuditStatsFn) { s.auditStats = fn }

// SetGrantStats registers (or clears, with nil) the grant counter callback.
func (s *Server) SetGrantStats(fn GrantStatsFn) { s.grantStats = fn }

// SetRateLimitStats registers (or clears, with nil) the rate-limit counter
// callback. Exposed so both portal and proxy binaries can surface
// rate_limited_total on /metrics without coupling the sidecar to either.
func (s *Server) SetRateLimitStats(fn RateLimitStatsFn) { s.rlStats = fn }

// MarkReady flips /healthz to 200.
func (s *Server) MarkReady() { s.ready.Store(true) }

// Addr returns the sidecar listener address (valid after Start).
func (s *Server) Addr() net.Addr {
	if s.ln == nil {
		return nil
	}
	return s.ln.Addr()
}

// Start begins serving. Non-blocking; use Shutdown to stop.
func (s *Server) Start() error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	return s.serve(ln)
}

// StartWithListener begins serving using a caller-provided listener.
// Useful for tests that need to reserve a port atomically.
func (s *Server) StartWithListener(ln net.Listener) error {
	return s.serve(ln)
}

func (s *Server) serve(ln net.Listener) error {
	s.ln = ln
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/metrics", s.handleMetrics)
	mux.HandleFunc("/version", s.handleVersion)

	s.srv = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		if err := s.srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.logger.Error("obs sidecar exited", "err", err)
		}
	}()
	s.logger.Info("obs sidecar listening", "addr", ln.Addr().String())
	return nil
}

// Shutdown gracefully stops the sidecar.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.srv == nil {
		return nil
	}
	return s.srv.Shutdown(ctx)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if !s.ready.Load() {
		http.Error(w, "starting", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "version=%s commit=%s built=%s builder=%s\n",
		s.info.Version, s.info.Commit, s.info.BuildTimestamp, s.info.Builder)
}

// handleMetrics emits Prometheus text format without pulling in the client lib.
// Keep it narrow — the goal is visibility, not full Prom tooling.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	var accepted, rejected, active uint64
	if s.stats != nil {
		accepted, rejected, active = s.stats()
	}
	uptime := time.Since(s.started).Seconds()

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	fmt.Fprintf(w, "# HELP proxy_uptime_seconds Seconds since process start.\n")
	fmt.Fprintf(w, "# TYPE proxy_uptime_seconds gauge\n")
	fmt.Fprintf(w, "proxy_uptime_seconds %f\n", uptime)

	fmt.Fprintf(w, "# HELP proxy_connections_accepted_total Client connections accepted.\n")
	fmt.Fprintf(w, "# TYPE proxy_connections_accepted_total counter\n")
	fmt.Fprintf(w, "proxy_connections_accepted_total %d\n", accepted)

	fmt.Fprintf(w, "# HELP proxy_connections_rejected_total Client connections rejected by cap.\n")
	fmt.Fprintf(w, "# TYPE proxy_connections_rejected_total counter\n")
	fmt.Fprintf(w, "proxy_connections_rejected_total %d\n", rejected)

	fmt.Fprintf(w, "# HELP proxy_connections_active Active client connections.\n")
	fmt.Fprintf(w, "# TYPE proxy_connections_active gauge\n")
	fmt.Fprintf(w, "proxy_connections_active %d\n", active)

	fmt.Fprintf(w, "# HELP proxy_build_info Build metadata.\n")
	fmt.Fprintf(w, "# TYPE proxy_build_info gauge\n")
	fmt.Fprintf(w, "proxy_build_info{version=%q,commit=%q,built=%q,builder=%q} 1\n",
		s.info.Version, s.info.Commit, s.info.BuildTimestamp, s.info.Builder)

	if s.auditStats != nil {
		total, pruned := s.auditStats()
		fmt.Fprintf(w, "# HELP audit_entries_total Current count of audit rows in the portal store.\n")
		fmt.Fprintf(w, "# TYPE audit_entries_total gauge\n")
		fmt.Fprintf(w, "audit_entries_total %d\n", total)

		fmt.Fprintf(w, "# HELP audit_entries_pruned_total Cumulative audit rows removed by retention sweeps.\n")
		fmt.Fprintf(w, "# TYPE audit_entries_pruned_total counter\n")
		fmt.Fprintf(w, "audit_entries_pruned_total %d\n", pruned)
	}

	if s.grantStats != nil {
		expired := s.grantStats()
		fmt.Fprintf(w, "# HELP grants_expired_total Cumulative grants flipped APPROVED->EXPIRED by the sweeper.\n")
		fmt.Fprintf(w, "# TYPE grants_expired_total counter\n")
		fmt.Fprintf(w, "grants_expired_total %d\n", expired)
	}

	if s.rlStats != nil {
		ip, user := s.rlStats()
		fmt.Fprintf(w, "# HELP rate_limited_total Requests/connections rejected by a rate-limit bucket, broken down by dimension.\n")
		fmt.Fprintf(w, "# TYPE rate_limited_total counter\n")
		fmt.Fprintf(w, "rate_limited_total{dimension=%q} %d\n", "ip", ip)
		fmt.Fprintf(w, "rate_limited_total{dimension=%q} %d\n", "user", user)
	}
}
