package provisioning

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/babs/poc-proxies/portal/internal/domain"
)

// Metrics holds the portal (producer) side provisioning counters surfaced on
// the obs sidecar. It deliberately mirrors the atomic-counter + Snapshot idiom
// used by ephemeral.Metrics / store.AuditMetrics so the metrics endpoint stays
// decoupled from this package and a nil handle is a safe no-op (tests that
// don't wire metrics still exercise the Client unchanged).
//
// Spec §8.8 (Workstream F), portal-side series:
//   - portal_provision_intents_emitted_total{kind}
//   - portal_provision_intents_pending          (gauge, best-effort queue depth)
//   - portal_provision_intent_latency_seconds    (emit→result, summarised)
//   - portal_provision_claim_timeout_total       (WaitForResult gave up → 202)
type Metrics struct {
	provisionEmitted atomic.Uint64 // emitted provision intents
	revokeEmitted    atomic.Uint64 // emitted revoke intents
	claimTimeouts    atomic.Uint64 // WaitForResult returned still-pending

	// pending is a best-effort gauge of intents emitted but not yet observed
	// terminal by a WaitForResult on this process. It is signed-safe: an
	// emit increments, a terminal/timed-out wait decrements. Modelled as a
	// gauge so a backlog (worker stuck) shows up as a rising value.
	pending atomic.Int64

	// latency accumulates emit→result observations as a count + sum of
	// seconds, the minimum a Prometheus summary needs (_count / _sum). The
	// obs sidecar lacks a histogram-snapshot hook, so a count+sum pair is the
	// repo-faithful way to expose latency through the CounterFunc plumbing.
	mu          sync.Mutex
	latCount    uint64
	latSumSecs  float64
	emittedAtMu sync.Mutex
	emittedAt   map[string]time.Time // intent id → emit time, for latency
}

// NewMetrics returns a zeroed metrics holder ready to attach to a Client.
func NewMetrics() *Metrics {
	return &Metrics{emittedAt: make(map[string]time.Time)}
}

// IncEmitted bumps the per-kind emitted counter, records the emit time for a
// later latency observation, and raises the pending gauge. kind is the intent
// kind string ("provision" / "revoke").
func (m *Metrics) IncEmitted(kind, intentID string) {
	if m == nil {
		return
	}
	switch kind {
	case "revoke":
		m.revokeEmitted.Add(1)
	default:
		m.provisionEmitted.Add(1)
	}
	m.pending.Add(1)
	m.emittedAtMu.Lock()
	m.emittedAt[intentID] = time.Now()
	m.emittedAtMu.Unlock()
}

// ObserveResult records the emit→result latency for a terminal intent and
// lowers the pending gauge. Called once per intent that WaitForResult sees
// reach a terminal state. A missing emit timestamp (e.g. emitted by another
// replica) only skips the latency sample — the gauge is still corrected.
func (m *Metrics) ObserveResult(intentID string) {
	if m == nil {
		return
	}
	m.pending.Add(-1)
	m.emittedAtMu.Lock()
	start, ok := m.emittedAt[intentID]
	delete(m.emittedAt, intentID)
	m.emittedAtMu.Unlock()
	if !ok {
		return
	}
	m.mu.Lock()
	m.latCount++
	m.latSumSecs += time.Since(start).Seconds()
	m.mu.Unlock()
}

// IncClaimTimeout records that WaitForResult returned a still-pending intent
// (the portal answered 202). The pending gauge is lowered too: this waiter is
// no longer holding the intent open, the worker will reconcile it. The emit
// timestamp is dropped without a latency sample — there is no result yet.
func (m *Metrics) IncClaimTimeout(intentID string) {
	if m == nil {
		return
	}
	m.claimTimeouts.Add(1)
	m.pending.Add(-1)
	m.emittedAtMu.Lock()
	delete(m.emittedAt, intentID)
	m.emittedAtMu.Unlock()
}

// EmittedSnapshot returns the cumulative per-kind emitted totals for the obs
// sidecar's CounterFunc collectors.
func (m *Metrics) EmittedSnapshot() (provision, revoke uint64) {
	if m == nil {
		return 0, 0
	}
	return m.provisionEmitted.Load(), m.revokeEmitted.Load()
}

// ClaimTimeoutSnapshot returns the cumulative claim-timeout total.
func (m *Metrics) ClaimTimeoutSnapshot() uint64 {
	if m == nil {
		return 0
	}
	return m.claimTimeouts.Load()
}

// PendingSnapshot returns the current best-effort queue depth. Floored at 0 so
// a decrement racing ahead of its increment can never surface a negative gauge.
func (m *Metrics) PendingSnapshot() float64 {
	if m == nil {
		return 0
	}
	if v := m.pending.Load(); v > 0 {
		return float64(v)
	}
	return 0
}

// LatencySnapshot returns the emit→result observation count and summed seconds,
// the (_count, _sum) pair a Prometheus summary exposes.
func (m *Metrics) LatencySnapshot() (count uint64, sumSeconds float64) {
	if m == nil {
		return 0, 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.latCount, m.latSumSecs
}

// CountWorkerStates classifies a heartbeat slice into alive vs stale counts as
// of now, using staleAfter as the liveness threshold. It backs the
// portal_provision_workers{state} gauge: main.go wires a GaugeFunc that reads
// the heartbeat table on each scrape and calls this to bucket the rows.
//
// Pure + threshold-injected so it stays testable and so the obs threshold knob
// lives with the api handler (not duplicated here). A nil/empty slice yields
// (0, 0) — a worker-less deployment reports both series at zero, never absent.
func CountWorkerStates(hbs []domain.WorkerHeartbeat, now time.Time, staleAfter time.Duration) (alive, stale int) {
	for _, hb := range hbs {
		if hb.IsStale(now, staleAfter) {
			stale++
		} else {
			alive++
		}
	}
	return alive, stale
}
