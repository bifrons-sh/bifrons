// Package metrics centralises the Prometheus collectors shared by the proxies
// and the portal. A single *Registry is created per process, bundles every
// histogram / gauge / counter the codebase needs to expose, and is attached to
// the obs sidecar via Server.SetRegistry.
//
// Design note: we keep the existing metric *names* (proxy_uptime_seconds,
// proxy_connections_*, proxy_build_info, audit_entries_*, grants_expired_total)
// so any alert or dashboard already built against the hand-rolled text format
// keeps working after the swap to promhttp.
package metrics

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Registry bundles the Prom registry together with the standard set of
// histograms/gauges/counters used across the proxies + portal. Callers obtain
// per-metric observers via helper methods (AuthLookup, BackendDial, ...).
type Registry struct {
	reg *prometheus.Registry

	// Proxy-side histograms.
	authLookupDuration  *prometheus.HistogramVec
	backendDialDuration *prometheus.HistogramVec
	handshakeDuration   *prometheus.HistogramVec
	connectionDuration  *prometheus.HistogramVec

	// Portal-side histogram labelled by {path,status}.
	portalRequestDuration *prometheus.HistogramVec

	// Existing gauges/counters preserved from the hand-rolled /metrics text.
	uptime             prometheus.GaugeFunc
	connsAccepted      prometheus.Counter     // proxy_connections_accepted_total
	connsRejected      prometheus.Counter     // proxy_connections_rejected_total
	connsActive        prometheus.Gauge       // proxy_connections_active
	buildInfo          *prometheus.GaugeVec   // proxy_build_info{version,commit,built,builder}
	auditEntriesTotal  prometheus.Gauge       // audit_entries_total (portal only)
	auditEntriesPruned prometheus.Counter     // audit_entries_pruned_total (portal only)
	grantsExpired      prometheus.Counter     // grants_expired_total (portal only)

	// Delta trackers translate cumulative snapshots → Counter.Add(delta).
	connAcceptedObs  counterDelta
	connRejectedObs  counterDelta
	auditPrunedObs   counterDelta
	grantsExpiredObs counterDelta
}

// Default histogram buckets — fine for HTTP-ish work (ms → seconds).
// Derived from prometheus.DefBuckets to stay consistent with common queries.
var defaultLatencyBuckets = prometheus.DefBuckets

// connectionDurationBuckets extends the default buckets with a long tail so
// session-length histograms can still answer "how many sessions ran > 4h?".
// Values are in seconds.
var connectionDurationBuckets = []float64{
	0.1, 0.5, 1, 5, 10, 30,
	60,          // 1m
	5 * 60,      // 5m
	15 * 60,     // 15m
	60 * 60,     // 1h
	4 * 60 * 60, // 4h
	24 * 60 * 60,
}

// New builds a fresh Registry with all collectors registered. started should be
// the process start time — it's read by the uptime GaugeFunc each scrape.
func New(started time.Time) *Registry {
	reg := prometheus.NewRegistry()
	r := &Registry{reg: reg}

	r.authLookupDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "proxy_auth_lookup_duration_seconds",
		Help:    "Latency of the portal /api/v1/auth lookup made by the proxy.",
		Buckets: defaultLatencyBuckets,
	}, []string{"proxy"})

	r.backendDialDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "proxy_backend_dial_duration_seconds",
		Help:    "Latency of dialling the backend database from the proxy.",
		Buckets: defaultLatencyBuckets,
	}, []string{"proxy"})

	r.handshakeDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "proxy_handshake_duration_seconds",
		Help:    "Latency of the end-to-end authentication/handshake phase.",
		Buckets: defaultLatencyBuckets,
	}, []string{"proxy"})

	r.connectionDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "proxy_connection_duration_seconds",
		Help:    "Full client-connection lifecycle duration (observed at disconnect).",
		Buckets: connectionDurationBuckets,
	}, []string{"proxy"})

	r.portalRequestDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "portal_request_duration_seconds",
		Help:    "Latency of portal HTTP requests by normalised path template and status.",
		Buckets: defaultLatencyBuckets,
	}, []string{"path", "status"})

	r.uptime = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "proxy_uptime_seconds",
		Help: "Seconds since process start.",
	}, func() float64 { return time.Since(started).Seconds() })

	r.connsAccepted = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "proxy_connections_accepted_total",
		Help: "Client connections accepted.",
	})
	r.connsRejected = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "proxy_connections_rejected_total",
		Help: "Client connections rejected by cap.",
	})
	r.connsActive = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "proxy_connections_active",
		Help: "Active client connections.",
	})
	r.buildInfo = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "proxy_build_info",
		Help: "Build metadata.",
	}, []string{"version", "commit", "built", "builder"})

	r.auditEntriesTotal = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "audit_entries_total",
		Help: "Current count of audit rows in the portal store.",
	})
	r.auditEntriesPruned = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "audit_entries_pruned_total",
		Help: "Cumulative audit rows removed by retention sweeps.",
	})
	r.grantsExpired = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "grants_expired_total",
		Help: "Cumulative grants flipped APPROVED->EXPIRED by the sweeper.",
	})

	reg.MustRegister(
		r.authLookupDuration,
		r.backendDialDuration,
		r.handshakeDuration,
		r.connectionDuration,
		r.portalRequestDuration,
		r.uptime,
		r.connsAccepted,
		r.connsRejected,
		r.connsActive,
		r.buildInfo,
		r.auditEntriesTotal,
		r.auditEntriesPruned,
		r.grantsExpired,
	)
	return r
}

// Prom exposes the underlying registry so callers can register ad-hoc
// collectors (tests, ancillary subsystems). Prefer the typed helpers below.
func (r *Registry) Prom() *prometheus.Registry { return r.reg }

// Handler returns an http.Handler that serves the Prom text format.
func (r *Registry) Handler() http.Handler {
	return promhttp.HandlerFor(r.reg, promhttp.HandlerOpts{})
}

// SetBuildInfo stamps the single proxy_build_info series. Safe to call once at
// startup; subsequent calls overwrite. Empty fields collapse to "" labels.
func (r *Registry) SetBuildInfo(version, commit, built, builder string) {
	r.buildInfo.WithLabelValues(version, commit, built, builder).Set(1)
}

// SetConnCounters refreshes the proxy connection counters/gauge from the
// existing atomic counters inside proxy.Server. Called on every scrape via
// Observer-style callback. Kept simple: Set monotonic counters to the current
// total (Prom tolerates re-setting counters through WithLabelValues.Add of a
// delta — but we already track the running total, so use Set on a gauge and
// counter semantics via Add(delta)).
//
// To avoid drift, we model accepted/rejected as gauges-backed-by-counter via
// Add: the caller is expected to pass cumulative totals, we keep a cache of
// the last seen value and add the delta.
func (r *Registry) SetConnCounters(accepted, rejected, active uint64) {
	r.connAcceptedObs.apply(r.connsAccepted, accepted)
	r.connRejectedObs.apply(r.connsRejected, rejected)
	r.connsActive.Set(float64(active))
}

// counterDelta tracks the last pushed cumulative value so we can translate
// snapshot-style stats (uint64 totals) into Counter.Add(delta) calls without
// breaking Prom's monotonic-counter invariant across process lifetime.
type counterDelta struct{ last uint64 }

func (c *counterDelta) apply(ctr prometheus.Counter, total uint64) {
	if total < c.last {
		// Stats were reset (e.g. test harness). Re-seed without decrementing.
		c.last = total
		return
	}
	delta := total - c.last
	if delta > 0 {
		ctr.Add(float64(delta))
		c.last = total
	}
}

// SetAuditStats mirrors obs.AuditStatsFn semantics: total (current) + pruned (cumulative).
func (r *Registry) SetAuditStats(total, prunedTotal uint64) {
	r.auditEntriesTotal.Set(float64(total))
	r.auditPrunedObs.apply(r.auditEntriesPruned, prunedTotal)
}

// SetGrantStats pushes the cumulative expired-grant total.
func (r *Registry) SetGrantStats(expiredTotal uint64) {
	r.grantsExpiredObs.apply(r.grantsExpired, expiredTotal)
}

// Observer-style accessors return a thin wrapper over prometheus.Observer so
// protocol handlers can record latencies without importing the prom library.

// AuthLookup returns an Observer for proxy_auth_lookup_duration_seconds{proxy}.
func (r *Registry) AuthLookup(proxy string) Observer {
	return observer{h: r.authLookupDuration.WithLabelValues(proxy)}
}

// BackendDial returns an Observer for proxy_backend_dial_duration_seconds{proxy}.
func (r *Registry) BackendDial(proxy string) Observer {
	return observer{h: r.backendDialDuration.WithLabelValues(proxy)}
}

// Handshake returns an Observer for proxy_handshake_duration_seconds{proxy}.
func (r *Registry) Handshake(proxy string) Observer {
	return observer{h: r.handshakeDuration.WithLabelValues(proxy)}
}

// Connection returns an Observer for proxy_connection_duration_seconds{proxy}.
func (r *Registry) Connection(proxy string) Observer {
	return observer{h: r.connectionDuration.WithLabelValues(proxy)}
}

// PortalRequest returns an Observer for portal_request_duration_seconds{path,status}.
func (r *Registry) PortalRequest(path, status string) Observer {
	return observer{h: r.portalRequestDuration.WithLabelValues(path, status)}
}

// Observer records a duration into a histogram. nil is a safe no-op so
// handlers can be wired with `var obs Observer` + `obs.Observe(...)`.
type Observer interface {
	Observe(d time.Duration)
}

type observer struct{ h prometheus.Observer }

func (o observer) Observe(d time.Duration) {
	if o.h == nil {
		return
	}
	o.h.Observe(d.Seconds())
}
