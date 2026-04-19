package ephemeral

import "sync/atomic"

// Metrics counts provisioner outcomes across the process. Exposed to the obs
// sidecar via getter funcs so the metrics endpoint stays decoupled from the
// package (same pattern as store.AuditMetrics).
type Metrics struct {
	provisioned   atomic.Uint64
	revoked       atomic.Uint64
	revokeFailed  atomic.Uint64
	provisionFail atomic.Uint64
}

// NewMetrics returns a zeroed metrics holder.
func NewMetrics() *Metrics { return &Metrics{} }

// IncProvisioned bumps the success counter.
func (m *Metrics) IncProvisioned() {
	if m == nil {
		return
	}
	m.provisioned.Add(1)
}

// IncRevoked bumps the revoke-success counter.
func (m *Metrics) IncRevoked() {
	if m == nil {
		return
	}
	m.revoked.Add(1)
}

// IncRevokeFailed bumps the revoke-failure counter.
func (m *Metrics) IncRevokeFailed() {
	if m == nil {
		return
	}
	m.revokeFailed.Add(1)
}

// IncProvisionFailed bumps the provision-failure counter. Not strictly
// required by the spec (which lists only the three success counters) but
// trivially cheap and makes rollback events observable.
func (m *Metrics) IncProvisionFailed() {
	if m == nil {
		return
	}
	m.provisionFail.Add(1)
}

// Snapshot returns current counters for the metrics sidecar.
func (m *Metrics) Snapshot() (provisioned, revoked, revokeFailed, provisionFailed uint64) {
	if m == nil {
		return 0, 0, 0, 0
	}
	return m.provisioned.Load(), m.revoked.Load(), m.revokeFailed.Load(), m.provisionFail.Load()
}
