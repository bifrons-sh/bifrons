package main

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/babs/poc-proxies/portal/internal/domain"
	"github.com/babs/poc-proxies/portal/internal/ephemeral"
	"github.com/babs/poc-proxies/portal/internal/store"
)

// fakeProber records which backends it was asked to probe and fails the ones
// named in failFor — letting a test assert OK=true/false per backend without
// dialing a real DB.
type fakeProber struct {
	mu      sync.Mutex
	calls   []string
	failFor map[string]error
}

func (p *fakeProber) probe(_ context.Context, b domain.Backend) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, b.ID)
	if err, ok := p.failFor[b.ID]; ok {
		return err
	}
	return nil
}

func (p *fakeProber) callCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.calls)
}

// newHeartbeatWorker seeds two postgres backends and returns a Worker wired to
// the given prober with a short heartbeat interval so a couple of ticks land
// fast. The whitelist is left empty so OwnedInstances expands to the DBACreds
// map (both backends).
func newHeartbeatWorker(t *testing.T, p *fakeProber, probe bool) (*Worker, store.Store) {
	t.Helper()
	st := store.NewMemory()
	ctx := context.Background()
	for _, id := range []string{"b-1", "b-2"} {
		if err := st.CreateBackend(ctx, domain.Backend{
			ID: id, Name: id, Type: domain.ProxyPostgres, Host: id + ".internal", Port: 5432,
		}); err != nil {
			t.Fatalf("seed backend %s: %v", id, err)
		}
	}
	cfg := Config{
		WorkerID:          "hb-worker",
		LeaseTTL:          60 * time.Second,
		DDLTimeout:        5 * time.Second,
		HeartbeatInterval: 10 * time.Millisecond,
		HeartbeatProbe:    probe,
		// DBACreds drives OwnedInstances when the whitelist is empty.
		DBACreds: dbaMap("b-1", "b-2"),
	}
	w := NewWorker(cfg, st, &fakeNotifier{}, nil, nil, nil).
		WithVersion("v9.9.9").
		WithProber(p.probe)
	return w, st
}

// onlyHB returns the single heartbeat row for hb-worker, failing if absent.
func onlyHB(t *testing.T, st store.Store) domain.WorkerHeartbeat {
	t.Helper()
	hbs, err := st.ListWorkerHeartbeats(context.Background())
	if err != nil {
		t.Fatalf("list heartbeats: %v", err)
	}
	if len(hbs) != 1 {
		t.Fatalf("want exactly one heartbeat row, got %d", len(hbs))
	}
	return hbs[0]
}

// TestHeartbeat_WritesRowWithOwnedAndHealth asserts the loop registers one row
// with the right WorkerID, version, owned instances, and (probe on) one Health
// entry per owned backend.
func TestHeartbeat_WritesRowWithOwnedAndHealth(t *testing.T) {
	p := &fakeProber{}
	w, st := newHeartbeatWorker(t, p, true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go w.heartbeatLoop(ctx, time.Now().UTC())

	waitFor(t, time.Second, func() bool {
		hbs, _ := st.ListWorkerHeartbeats(ctx)
		return len(hbs) == 1 && len(hbs[0].Health) == 2
	}, "heartbeat row with per-backend health")

	hb := onlyHB(t, st)
	if hb.WorkerID != "hb-worker" {
		t.Errorf("worker_id = %q, want hb-worker", hb.WorkerID)
	}
	if hb.Version != "v9.9.9" {
		t.Errorf("version = %q, want v9.9.9", hb.Version)
	}
	if got := hb.Instances; len(got) != 2 || got[0] != "b-1" || got[1] != "b-2" {
		t.Errorf("instances = %v, want [b-1 b-2]", got)
	}
	byID := map[string]domain.InstanceHealth{}
	for _, h := range hb.Health {
		byID[h.BackendID] = h
	}
	for _, id := range []string{"b-1", "b-2"} {
		h, ok := byID[id]
		if !ok {
			t.Fatalf("missing health entry for %s", id)
		}
		if !h.OK || h.LastOKAt == nil || h.ErrorClass != "" {
			t.Errorf("%s health = %+v, want OK with LastOKAt set", id, h)
		}
	}
}

// TestHeartbeat_FailingProbeDoesNotStopBeats asserts a failing probe yields
// OK=false + an ErrorClass and that the loop keeps beating afterwards (LastSeenAt
// advances), proving one bad backend can't kill the heartbeat.
func TestHeartbeat_FailingProbeDoesNotStopBeats(t *testing.T) {
	p := &fakeProber{failFor: map[string]error{"b-2": errors.New("connection refused")}}
	w, st := newHeartbeatWorker(t, p, true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go w.heartbeatLoop(ctx, time.Now().UTC())

	waitFor(t, time.Second, func() bool {
		hbs, _ := st.ListWorkerHeartbeats(ctx)
		return len(hbs) == 1 && len(hbs[0].Health) == 2
	}, "first heartbeat with health")

	hb := onlyHB(t, st)
	byID := map[string]domain.InstanceHealth{}
	for _, h := range hb.Health {
		byID[h.BackendID] = h
	}
	if h := byID["b-1"]; !h.OK {
		t.Errorf("b-1 should be OK, got %+v", h)
	}
	// connection refused → classTransientNetwork via the shared classify helper.
	if h := byID["b-2"]; h.OK || h.ErrorClass != classTransientNetwork {
		t.Errorf("b-2 = %+v, want OK=false ErrorClass=%s", h, classTransientNetwork)
	}

	// The loop must keep beating despite the failing probe: LastSeenAt advances.
	first := hb.LastSeenAt
	waitFor(t, time.Second, func() bool {
		return onlyHB(t, st).LastSeenAt.After(first)
	}, "subsequent beat after a failing probe")

	if p.callCount() < 2 {
		t.Errorf("prober called %d times, want it to keep probing", p.callCount())
	}
}

// TestHeartbeat_ImmediateBeatOnStartup asserts a beat lands without waiting a
// full interval: with a long interval, the row exists almost immediately.
func TestHeartbeat_ImmediateBeatOnStartup(t *testing.T) {
	p := &fakeProber{}
	w, st := newHeartbeatWorker(t, p, true)
	w.cfg.HeartbeatInterval = time.Hour // only the startup beat can land in the window
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	started := time.Now().UTC()
	go w.heartbeatLoop(ctx, started)

	waitFor(t, time.Second, func() bool {
		hbs, _ := st.ListWorkerHeartbeats(ctx)
		return len(hbs) == 1
	}, "immediate startup beat")

	if got := onlyHB(t, st).StartedAt; !got.Equal(started) {
		t.Errorf("started_at = %v, want %v (captured once at Run start)", got, started)
	}
}

// TestHeartbeat_ProbeDisabledShipsEmptyHealth asserts that with probing off the
// row still registers (owned instances + advancing LastSeenAt) but carries no
// Health entries and never invokes the prober.
func TestHeartbeat_ProbeDisabledShipsEmptyHealth(t *testing.T) {
	p := &fakeProber{}
	w, st := newHeartbeatWorker(t, p, false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go w.heartbeatLoop(ctx, time.Now().UTC())

	waitFor(t, time.Second, func() bool {
		hbs, _ := st.ListWorkerHeartbeats(ctx)
		return len(hbs) == 1
	}, "heartbeat row")

	hb := onlyHB(t, st)
	if len(hb.Health) != 0 {
		t.Errorf("health = %v, want empty when probing disabled", hb.Health)
	}
	if len(hb.Instances) != 2 {
		t.Errorf("instances = %v, want both owned backends", hb.Instances)
	}
	if p.callCount() != 0 {
		t.Errorf("prober called %d times, want 0 when probing disabled", p.callCount())
	}
}

// dbaMap builds a DBACreds map with a placeholder credential per id — only the
// keys matter for OwnedInstances; the fake prober never uses the values.
func dbaMap(ids ...string) map[string]ephemeral.DBACredential {
	m := make(map[string]ephemeral.DBACredential, len(ids))
	for _, id := range ids {
		m[id] = ephemeral.DBACredential{Username: "dba", Password: "x"}
	}
	return m
}
