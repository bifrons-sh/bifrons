package main

import (
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// workerMetrics holds the consumer-side provisioning counters (spec §8.8,
// Workstream F). It follows the repo's atomic-counter + snapshot idiom so the
// metrics HTTP listener stays decoupled and a nil handle is a safe no-op (the
// worker unit tests construct a Worker without metrics).
//
// Series exposed:
//   - worker_provision_intents_processed_total{kind,result}
//   - worker_provision_ddl_latency_seconds        (count+sum summary)
//   - worker_stale_leases_reclaimed_total
//   - worker_notify_missed_total
type workerMetrics struct {
	// processed is keyed by "kind:result" (e.g. "provision:done",
	// "revoke:failed"). A map keeps the cardinality open without a fixed enum
	// of kind×result pairs hard-coded here; guarded by mu.
	mu        sync.Mutex
	processed map[string]uint64

	ddlCount   uint64  // ddl latency observation count
	ddlSumSecs float64 // summed ddl latency seconds

	staleReclaimed atomic.Uint64 // worker_stale_leases_reclaimed_total
	notifyMissed   atomic.Uint64 // worker_notify_missed_total
}

func newWorkerMetrics() *workerMetrics {
	return &workerMetrics{processed: make(map[string]uint64)}
}

// IncProcessed bumps the processed counter for a (kind,result) pair. result is
// the terminal outcome: "done" on success, "failed" on a terminal/exhausted
// failure.
func (m *workerMetrics) IncProcessed(kind, result string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.processed[kind+":"+result]++
	m.mu.Unlock()
}

// ObserveDDL records one DDL round-trip latency (provision/revoke execution).
func (m *workerMetrics) ObserveDDL(d time.Duration) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.ddlCount++
	m.ddlSumSecs += d.Seconds()
	m.mu.Unlock()
}

// IncStaleReclaimed records a stale-lease takeover (a claimed row that was
// in_flight past its lease).
func (m *workerMetrics) IncStaleReclaimed(n int) {
	if m == nil || n <= 0 {
		return
	}
	m.staleReclaimed.Add(uint64(n))
}

// IncNotifyMissed records intents found by the catch-up poll rather than a
// NOTIFY wake — a LISTEN connection-health indicator (spec §8.8 alert).
func (m *workerMetrics) IncNotifyMissed(n int) {
	if m == nil || n <= 0 {
		return
	}
	m.notifyMissed.Add(uint64(n))
}

// ProcessedSnapshot returns a copy of the per-(kind,result) processed totals.
func (m *workerMetrics) ProcessedSnapshot() map[string]uint64 {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]uint64, len(m.processed))
	for k, v := range m.processed {
		out[k] = v
	}
	return out
}

// DDLSnapshot returns the DDL latency observation count and summed seconds.
func (m *workerMetrics) DDLSnapshot() (count uint64, sumSeconds float64) {
	if m == nil {
		return 0, 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ddlCount, m.ddlSumSecs
}

// StaleReclaimedSnapshot returns the cumulative stale-lease reclaim total.
func (m *workerMetrics) StaleReclaimedSnapshot() uint64 {
	if m == nil {
		return 0
	}
	return m.staleReclaimed.Load()
}

// NotifyMissedSnapshot returns the cumulative notify-missed total.
func (m *workerMetrics) NotifyMissedSnapshot() uint64 {
	if m == nil {
		return 0
	}
	return m.notifyMissed.Load()
}

// processedCollector emits worker_provision_intents_processed_total{kind,result}
// at scrape time, one series per observed (kind,result) pair. A custom
// Collector is the idiomatic way to surface a dynamically-labelled counter
// whose label set isn't known at registration time.
type processedCollector struct {
	m    *workerMetrics
	desc *prometheus.Desc
}

func newProcessedCollector(m *workerMetrics) *processedCollector {
	return &processedCollector{
		m: m,
		desc: prometheus.NewDesc(
			"worker_provision_intents_processed_total",
			"Intents processed to a terminal state, by kind and result.",
			[]string{"kind", "result"}, nil,
		),
	}
}

func (c *processedCollector) Describe(ch chan<- *prometheus.Desc) { ch <- c.desc }

func (c *processedCollector) Collect(ch chan<- prometheus.Metric) {
	for key, v := range c.m.ProcessedSnapshot() {
		// key is "kind:result"; split once so a result containing ':' (none do
		// today) wouldn't corrupt the kind label.
		kind, result, ok := strings.Cut(key, ":")
		if !ok {
			continue
		}
		ch <- prometheus.MustNewConstMetric(c.desc, prometheus.CounterValue, float64(v), kind, result)
	}
}
