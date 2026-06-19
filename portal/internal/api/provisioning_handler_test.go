package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/babs/poc-proxies/portal/internal/config"
	"github.com/babs/poc-proxies/portal/internal/domain"
	"github.com/babs/poc-proxies/portal/internal/oidc"
	"github.com/babs/poc-proxies/portal/internal/policy"
	"github.com/babs/poc-proxies/portal/internal/store"
)

// seedWorkers stages two heartbeat rows: one fresh (beat now) and one stale
// (last beat well past workerStaleThreshold). Returns nothing — callers assert
// against the known worker ids.
func seedWorkers(t *testing.T, s store.Store) {
	t.Helper()
	ctx := context.Background()
	now := time.Now()
	okAt := now
	fresh := domain.WorkerHeartbeat{
		WorkerID:   "w-fresh",
		Instances:  []string{"b-1"},
		Health:     []domain.InstanceHealth{{BackendID: "b-1", OK: true, LastOKAt: &okAt}},
		Version:    "v1.2.3",
		StartedAt:  now.Add(-time.Hour),
		LastSeenAt: now,
	}
	if err := s.UpsertWorkerHeartbeat(ctx, fresh); err != nil {
		t.Fatal(err)
	}
	// Stale: last seen 2 minutes ago, far past the 30s obs threshold but well
	// inside the 1h prune cutoff, so it lingers as stale=true.
	stale := domain.WorkerHeartbeat{
		WorkerID:   "w-stale",
		Instances:  []string{},
		Health:     []domain.InstanceHealth{{BackendID: "b-1", OK: false, ErrorClass: "dial_timeout"}},
		Version:    "v1.2.2",
		StartedAt:  now.Add(-2 * time.Hour),
		LastSeenAt: now.Add(-2 * time.Minute),
	}
	if err := s.UpsertWorkerHeartbeat(ctx, stale); err != nil {
		t.Fatal(err)
	}
}

// TestListWorkers_AdminSeesStaleFlags: an operator (OIDC session, IsOperator)
// gets both heartbeat rows with the stale flag computed per row.
func TestListWorkers_AdminSeesStaleFlags(t *testing.T) {
	cfg := &config.Config{}
	s := store.NewMemory()
	seedWorkers(t, s)
	h := NewRouter(cfg, store.Store(s), policy.New(s), slog.New(slog.NewJSONHandler(io.Discard, nil)))
	admin := &oidc.Session{Subject: "sub-admin", PortalUserID: "u-admin", IsOperator: true, ExpiresAt: time.Now().Add(time.Hour)}
	srv := httptest.NewServer(withSession(h, admin))
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/api/v1/provisioning/workers")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("want 200, got %d body=%s", resp.StatusCode, raw)
	}
	var got []workerDTO
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 workers, got %d", len(got))
	}
	byID := map[string]workerDTO{}
	for _, w := range got {
		byID[w.WorkerID] = w
	}
	if w := byID["w-fresh"]; w.Stale {
		t.Errorf("w-fresh should not be stale (age=%.1fs)", w.AgeSeconds)
	}
	if w, ok := byID["w-fresh"]; !ok || w.Version != "v1.2.3" || len(w.Instances) != 1 {
		t.Errorf("w-fresh DTO unexpected: %+v", w)
	}
	if w := byID["w-stale"]; !w.Stale {
		t.Errorf("w-stale should be stale (age=%.1fs)", w.AgeSeconds)
	}
	// Health is carried through with its error class.
	if w := byID["w-stale"]; len(w.Health) != 1 || w.Health[0].ErrorClass != "dial_timeout" {
		t.Errorf("w-stale health unexpected: %+v", w.Health)
	}
}

// TestListWorkers_NonAdminRejected: a non-operator OIDC session is 403'd — the
// liveness table reveals fleet topology and is operator-only.
func TestListWorkers_NonAdminRejected(t *testing.T) {
	cfg := &config.Config{}
	s := store.NewMemory()
	seedWorkers(t, s)
	h := NewRouter(cfg, store.Store(s), policy.New(s), slog.New(slog.NewJSONHandler(io.Discard, nil)))
	user := &oidc.Session{Subject: "sub-user", PortalUserID: "u-user", IsOperator: false, ExpiresAt: time.Now().Add(time.Hour)}
	srv := httptest.NewServer(withSession(h, user))
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/api/v1/provisioning/workers")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("want 403, got %d body=%s", resp.StatusCode, raw)
	}
}
