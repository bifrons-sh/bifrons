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

	"github.com/babs/poc-proxies/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
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

// ScramCacheStatsFn exposes the SCRAM stored-credentials cache counters.
type ScramCacheStatsFn func() (hits, misses, evictions uint64)

// RateLimitStatsFn exposes rate-limit rejection counters.
type RateLimitStatsFn func() (ip, user uint64)

// EphemeralStatsFn exposes ephemeral-provisioner counters.
type EphemeralStatsFn func() (provisioned, revoked, revokeFailed, provisionFailed uint64)

// EntraStatsFn exposes portal Entra-integration counters.
type EntraStatsFn func() (emailSent, emailFailed, policyRejected, managerLookupFailed uint64)

// Server is a tiny HTTP sidecar for /healthz and /metrics.
type Server struct {
	addr       string
	ln         net.Listener
	logger     *slog.Logger
	info       BuildInfo
	stats      StatsFn
	auditStats AuditStatsFn
	grantStats GrantStatsFn
	reg        *metrics.Registry
	ready      atomic.Bool
	srv        *http.Server
	started    time.Time
}

func NewServer(addr string, logger *slog.Logger, info BuildInfo, stats StatsFn) *Server {
	s := &Server{
		addr:    addr,
		logger:  logger.With("component", "obs"),
		info:    info,
		stats:   stats,
		started: time.Now(),
	}
	// Every /metrics scrape goes through a Prometheus registry. Auto-create
	// one here so tests and local-dev callers don't have to wire it; the
	// portal binary still calls SetRegistry with a shared registry to expose
	// extra collectors.
	s.SetRegistry(metrics.New(s.started))
	return s
}

// SetAuditStats registers (or clears, with nil) the audit counter callback.
// Kept separate from NewServer so every existing caller keeps working.
func (s *Server) SetAuditStats(fn AuditStatsFn) { s.auditStats = fn }

// SetGrantStats registers (or clears, with nil) the grant counter callback.
func (s *Server) SetGrantStats(fn GrantStatsFn) { s.grantStats = fn }

// SetRegistry attaches a shared metrics.Registry.
func (s *Server) SetRegistry(r *metrics.Registry) {
	s.reg = r
	if r != nil {
		r.SetBuildInfo(s.info.Version, s.info.Commit, s.info.BuildTimestamp, s.info.Builder)
	}
}

// SetScramCacheStats registers three CounterFunc collectors for the SCRAM
// stored-credentials cache. Call once at startup; re-calls register duplicate
// collectors and panic.
func (s *Server) SetScramCacheStats(fn ScramCacheStatsFn) {
	s.registerCounterFuncs(
		[3]string{"scram_cache_hits_total", "scram_cache_misses_total", "scram_cache_evictions_total"},
		[3]string{
			"Cumulative SCRAM stored-credentials cache hits.",
			"Cumulative SCRAM stored-credentials cache misses.",
			"Cumulative SCRAM cache evictions due to capacity.",
		},
		func() (uint64, uint64, uint64) { return fn() },
	)
}

// SetRateLimitStats registers two CounterFunc collectors for rate-limit
// rejections, one per dimension (ip / user). Flat names keep the registry
// simple; dashboards can glob rate_limited_*.
func (s *Server) SetRateLimitStats(fn RateLimitStatsFn) {
	s.registerCounterFunc("rate_limited_ip_total",
		"Requests/connections rejected by the per-IP rate-limit bucket.",
		func() uint64 { ip, _ := fn(); return ip })
	s.registerCounterFunc("rate_limited_user_total",
		"Requests/connections rejected by the per-user rate-limit bucket.",
		func() uint64 { _, user := fn(); return user })
}

// SetEphemeralStats registers four CounterFunc collectors for the
// per-grant backend-user provisioner.
func (s *Server) SetEphemeralStats(fn EphemeralStatsFn) {
	s.registerCounterFunc("ephemeral_provisioned_total",
		"Cumulative ephemeral backend users created on grant approval.",
		func() uint64 { p, _, _, _ := fn(); return p })
	s.registerCounterFunc("ephemeral_revoked_total",
		"Cumulative ephemeral backend users dropped.",
		func() uint64 { _, r, _, _ := fn(); return r })
	s.registerCounterFunc("ephemeral_revoke_failed_total",
		"Cumulative failures dropping ephemeral backend users.",
		func() uint64 { _, _, rf, _ := fn(); return rf })
	s.registerCounterFunc("ephemeral_provision_failed_total",
		"Cumulative failures creating ephemeral backend users.",
		func() uint64 { _, _, _, pf := fn(); return pf })
}

// SetEntraStats registers four CounterFunc collectors for the Entra /
// Graph API integration.
func (s *Server) SetEntraStats(fn EntraStatsFn) {
	s.registerCounterFunc("entra_email_sent_total",
		"Graph /sendMail calls that succeeded.",
		func() uint64 { sent, _, _, _ := fn(); return sent })
	s.registerCounterFunc("entra_email_failed_total",
		"Graph /sendMail calls that failed.",
		func() uint64 { _, failed, _, _ := fn(); return failed })
	s.registerCounterFunc("entra_policy_rejected_total",
		"Grant requests denied by the Entra request policy.",
		func() uint64 { _, _, rej, _ := fn(); return rej })
	s.registerCounterFunc("entra_manager_lookup_failed_total",
		"Graph /manager lookups that failed.",
		func() uint64 { _, _, _, mf := fn(); return mf })
}

// registerCounterFunc registers a single CounterFunc on the server's registry.
// The callback is invoked on every scrape; values must be monotonically
// non-decreasing (Prom enforces this).
func (s *Server) registerCounterFunc(name, help string, fn func() uint64) {
	s.reg.Prom().MustRegister(prometheus.NewCounterFunc(
		prometheus.CounterOpts{Name: name, Help: help},
		func() float64 { return float64(fn()) },
	))
}

// registerCounterFuncs batches three registrations from a single fn3 returning
// three cumulative totals.
func (s *Server) registerCounterFuncs(names, helps [3]string, fn3 func() (uint64, uint64, uint64)) {
	s.registerCounterFunc(names[0], helps[0], func() uint64 { a, _, _ := fn3(); return a })
	s.registerCounterFunc(names[1], helps[1], func() uint64 { _, b, _ := fn3(); return b })
	s.registerCounterFunc(names[2], helps[2], func() uint64 { _, _, c := fn3(); return c })
}

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

// handleMetrics snapshots live counters into the promhttp registry right
// before the scrape renders. Keeps the classic metric names
// (proxy_connections_*, audit_entries_*, grants_expired_total, …) in sync
// without forcing callers to push on every change.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if s.stats != nil {
		accepted, rejected, active := s.stats()
		s.reg.SetConnCounters(accepted, rejected, active)
	}
	if s.auditStats != nil {
		total, pruned := s.auditStats()
		s.reg.SetAuditStats(total, pruned)
	}
	if s.grantStats != nil {
		s.reg.SetGrantStats(s.grantStats())
	}
	s.reg.Handler().ServeHTTP(w, r)
}
