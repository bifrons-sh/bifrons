package main

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/babs/poc-proxies/portal/internal/provisioning"
)

// Run drives the worker until ctx is cancelled. It subscribes to the intent
// channel (sub-ms wakeup on postgres; a no-op stream on poll-only stores), runs
// a catch-up ticker as the self-healing fallback, and does a startup scan so a
// worker that boots with a backlog drains it immediately. Each wake claims a
// batch of eligible intents and processes them. Shutdown is graceful: the
// in-flight processing finishes on the current ctx before Run returns.
func (w *Worker) Run(ctx context.Context) error {
	w.logger.Info("worker_starting",
		slog.String("worker_id", w.cfg.WorkerID),
		slog.String("store", schemeOnly(w.cfg.StoreURL)),
		slog.Int("whitelist", len(w.cfg.InstanceWhitelist)),
		slog.Duration("catch_up", w.cfg.CatchUpInterval),
		slog.Duration("lease_ttl", w.cfg.LeaseTTL),
	)

	// Process-level liveness heartbeat (one row per worker_id, distinct from the
	// per-intent lease heartbeat): proves the worker is alive even while idle and
	// carries per-backend reachability. StartedAt is captured ONCE here so every
	// beat reports a stable uptime. Started before the startup drain so a worker
	// busy draining a large backlog still registers promptly.
	startedAt := time.Now().UTC()
	go w.heartbeatLoop(ctx, startedAt)

	// Startup scan: drain any backlog left by a previous worker / portal
	// restart. This is a catch-up scan (no NOTIFY drove it), so anything found
	// counts as notify-missed — same health signal as a steady-state poll hit.
	w.drain(ctx, true)

	ticker := time.NewTicker(w.cfg.CatchUpInterval)
	defer ticker.Stop()

	// listenLoop owns the LISTEN subscription with reconnect-on-close. It pushes
	// a token onto wake whenever an intent NOTIFY arrives. On poll-only stores
	// the stream never delivers, so the catch-up ticker is the only wake source.
	wake := make(chan struct{}, 1)
	go w.listenLoop(ctx, wake)

	for {
		select {
		case <-ctx.Done():
			w.logger.Info("worker_stopping", slog.String("worker_id", w.cfg.WorkerID))
			return nil
		case <-ticker.C:
			// Catch-up tick: any work found here was NOT delivered by a NOTIFY
			// wake → notify-missed (LISTEN connection-health indicator, §8.8).
			w.drain(ctx, true)
		case <-wake:
			// NOTIFY-driven wake: work found here arrived via the fast path.
			w.drain(ctx, false)
		}
	}
}

// listenLoop subscribes to ChannelProvisionIntent and re-subscribes with
// backoff whenever the stream closes (connection loss). Every payload nudges
// the main loop via wake (coalesced — a full channel means a drain is already
// queued).
func (w *Worker) listenLoop(ctx context.Context, wake chan<- struct{}) {
	const reconnectDelay = 2 * time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		stream, err := w.notifier.Listen(ctx, provisioning.ChannelProvisionIntent)
		if err != nil {
			w.logger.Warn("listen_subscribe_failed", slog.Any("error", err))
			if !sleepCtx(ctx, reconnectDelay) {
				return
			}
			continue
		}
		// The payload is the intent id, but we re-scan the store rather than
		// trust it (a single drain catches several coalesced NOTIFYs), so the
		// value is intentionally discarded.
		for range stream {
			select {
			case wake <- struct{}{}:
			default:
			}
		}
		// Stream closed: ctx cancelled (stop) or connection lost (reconnect).
		if ctx.Err() != nil {
			return
		}
		w.logger.Warn("listen_stream_closed_reconnecting")
		if !sleepCtx(ctx, reconnectDelay) {
			return
		}
	}
}

// drain claims and processes one batch of eligible intents. The store orders
// revoke-before-provision for the same grant, so processing in returned order
// honours the spec §8.6 preemption rule. Errors per intent are already recorded
// on the row by processIntent; the loop logs and continues.
//
// viaCatchUp is true when a catch-up tick (not a NOTIFY wake) drove this drain;
// any intents found are then counted as notify-missed (§8.8). Stale-lease
// reclaims are counted regardless of the wake source.
func (w *Worker) drain(ctx context.Context, viaCatchUp bool) {
	if ctx.Err() != nil {
		return
	}
	intents, err := w.store.ClaimPendingIntents(ctx, w.cfg.WorkerID, w.cfg.InstanceWhitelist, w.cfg.LeaseTTL, w.cfg.ClaimBatch)
	if err != nil {
		w.logger.Error("claim_intents_failed", slog.Any("error", err))
		return
	}
	// A catch-up tick that turned up work means the NOTIFY for it never landed
	// (or this is the startup backlog) — the §8.8 LISTEN-health indicator.
	if viaCatchUp && len(intents) > 0 {
		w.metrics.IncNotifyMissed(len(intents))
	}
	// Stale-lease reclaim: ClaimPendingIntents also leases in_flight rows whose
	// lease lapsed. We can't see the pre-claim status (the row is already
	// re-leased to us), so we use retry_count > 0 as the best-effort signal — a
	// row that a prior worker attempted and abandoned mid-lease. A crash before
	// the first attempt (retry_count still 0) is missed; that under-count is
	// acceptable for a health gauge and avoids a store-layer change.
	stale := 0
	for _, in := range intents {
		if in.RetryCount > 0 {
			stale++
		}
	}
	w.metrics.IncStaleReclaimed(stale)
	for _, in := range intents {
		if ctx.Err() != nil {
			return
		}
		if perr := w.processIntent(ctx, in); perr != nil {
			// processIntent already persisted the failure + logged details under
			// intent_id; this is the top-level breadcrumb.
			w.logger.Debug("intent_processed_with_error", slog.String("intent_id", in.ID), slog.Any("error", perr))
		}
	}
}

// sleepCtx waits d or returns false if ctx is cancelled first.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// schemeOnly returns the URL up to the first "://" so the store scheme can be
// logged without leaking credentials embedded in the DSN. A URL with no "://"
// (or an empty one) yields "unknown" rather than panicking on a short slice.
func schemeOnly(url string) string {
	if i := strings.Index(url, "://"); i > 0 {
		return url[:i]
	}
	return "unknown"
}
