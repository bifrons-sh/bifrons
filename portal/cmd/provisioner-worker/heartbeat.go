package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/babs/poc-proxies/portal/internal/domain"
	"github.com/babs/poc-proxies/portal/internal/ephemeral"
)

// prober tests reachability of one backend by opening an admin connection and
// immediately closing it. It returns nil when the backend answered (the
// ephemeral connectors Ping on connect, so a successful open IS a reachability
// proof) and an error otherwise. Injected on the Worker so tests substitute a
// fake instead of dialing a real DB.
type prober func(ctx context.Context, backend domain.Backend) error

// defaultProber builds the production prober: it resolves the backend's DBA
// credential from the worker's config map and dispatches to the matching
// ephemeral connector, reusing the exact connect+Ping path Provision/Revoke use
// rather than duplicating DSN/TLS logic. The returned admin handle is closed at
// once — this is a liveness ping, not a session we keep warm.
func defaultProber(dbaCreds map[string]ephemeral.DBACredential) prober {
	return func(ctx context.Context, backend domain.Backend) error {
		dba, ok := dbaCreds[backend.ID]
		if !ok {
			// No master credential configured for a backend this worker claims to
			// own — surfaced as ErrNoDBACredential so classify maps it to a
			// terminal_permission class (operator must fix config).
			return ephemeral.ErrNoDBACredential
		}
		switch ephemeral.MapBackendType(backend.Type) {
		case ephemeral.BackendPostgres:
			conn, err := ephemeral.DefaultPostgresConnector(ctx, backend.Host, backend.Port, "", dba)
			if err != nil {
				return err
			}
			return conn.Close()
		case ephemeral.BackendMySQL:
			conn, err := ephemeral.DefaultMySQLConnector(ctx, backend.Host, backend.Port, "", dba)
			if err != nil {
				return err
			}
			return conn.Close()
		case ephemeral.BackendMongo:
			conn, err := ephemeral.DefaultMongoConnector(ctx, backend.Host, backend.Port, "", dba)
			if err != nil {
				return err
			}
			return conn.Close(ctx)
		default:
			return fmt.Errorf("no connector for backend type %q", backend.Type)
		}
	}
}

// heartbeatLoop emits a process-level liveness heartbeat every
// HeartbeatInterval until ctx is cancelled. One row per worker_id (distinct
// from the per-intent lease heartbeat), embedding a per-backend reachability
// map so an operator can see a worker is alive AND which of its instances it
// can reach — even while the outbox is idle.
//
// An immediate beat fires at startup so a freshly-booted worker shows up
// without waiting a full interval. startedAt is captured by the caller and
// preserved across beats (the store also pins it on first registration).
func (w *Worker) heartbeatLoop(ctx context.Context, startedAt time.Time) {
	w.emitHeartbeat(ctx, startedAt)

	// LoadConfig already floors the interval, but a Worker built directly (unit
	// tests, or a future caller bypassing LoadConfig) may leave it zero — guard
	// so NewTicker never panics on a non-positive interval.
	interval := w.cfg.HeartbeatInterval
	if interval <= 0 {
		interval = 10 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.emitHeartbeat(ctx, startedAt)
		}
	}
}

// emitHeartbeat builds and upserts one heartbeat row. A probe or store failure
// is logged and swallowed: liveness must keep beating even when a backend is
// wedged or the store blips, so the next tick still advances LastSeenAt.
func (w *Worker) emitHeartbeat(ctx context.Context, startedAt time.Time) {
	owned := w.cfg.OwnedInstances()
	var health []domain.InstanceHealth
	// Probe only when enabled AND a prober is wired — a nil prober (probe-free
	// Worker) must not panic the loop.
	if w.cfg.HeartbeatProbe && w.prober != nil {
		health = w.probeAll(ctx, owned)
	}
	hb := domain.WorkerHeartbeat{
		WorkerID:   w.cfg.WorkerID,
		Instances:  owned,
		Health:     health,
		Version:    w.version,
		StartedAt:  startedAt,
		LastSeenAt: time.Now().UTC(),
	}
	if err := w.store.UpsertWorkerHeartbeat(ctx, hb); err != nil {
		w.logger.Warn("worker_heartbeat_upsert_failed", slog.Any("error", err))
	}
}

// probeAll probes every owned backend and returns one InstanceHealth per id.
// Probes run sequentially but each is bounded by its own ddl-timeout-derived
// deadline (probeBackend), so a single wedged host can stall at most that long
// and never blocks the others indefinitely — keeping the loop simple without a
// goroutine fan-out the PoC doesn't need.
func (w *Worker) probeAll(ctx context.Context, owned []string) []domain.InstanceHealth {
	if len(owned) == 0 {
		return nil
	}
	out := make([]domain.InstanceHealth, 0, len(owned))
	for _, id := range owned {
		if ctx.Err() != nil {
			return out
		}
		out = append(out, w.probeBackend(ctx, id))
	}
	return out
}

// probeBackend resolves a backend from the store and pings it via the injected
// prober under a bounded deadline (the same budget DDL uses, so a probe can
// never outlast what a real op would). On success OK=true with LastOKAt=now; on
// failure OK=false with the classified error_class (the closed §8.4.2 enum) so
// the heartbeat carries a structured, host-free reason rather than raw driver
// text.
func (w *Worker) probeBackend(ctx context.Context, backendID string) domain.InstanceHealth {
	backend, err := w.store.GetBackend(ctx, backendID)
	if err != nil {
		// The worker owns a backend id the store doesn't know — a config/store
		// drift. terminal_intent_invalid is the closest closed-enum class.
		return domain.InstanceHealth{BackendID: backendID, OK: false, ErrorClass: classTerminalIntentInval}
	}

	probeCtx := ctx
	if d := w.ddlDeadline(); d > 0 {
		var cancel context.CancelFunc
		probeCtx, cancel = context.WithTimeout(ctx, d)
		defer cancel()
	}

	if err := w.prober(probeCtx, backend); err != nil {
		w.logger.Warn("worker_heartbeat_probe_failed",
			slog.String("backend_id", backendID),
			slog.String("error_class", classify(err)))
		return domain.InstanceHealth{BackendID: backendID, OK: false, ErrorClass: classify(err)}
	}
	now := time.Now().UTC()
	return domain.InstanceHealth{BackendID: backendID, OK: true, LastOKAt: &now}
}
