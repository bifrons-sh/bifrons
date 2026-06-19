package provisioning

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/babs/poc-proxies/portal/internal/domain"
	"github.com/babs/poc-proxies/portal/internal/store"
)

// pollInterval is the WaitForResult fallback cadence on stores without a real
// result notifier (sqlite/memory). Short enough that /claim stays snappy, long
// enough not to hammer the store. The postgres path doesn't poll — it's woken
// by the result listener.
const pollInterval = 200 * time.Millisecond

// Listener reconnect backoff bounds (M4/M5). On a dead/lost result stream the
// single restart goroutine retries with exponential backoff so a downed pg
// doesn't get hammered, while parked waiters fall back to their poll timer in
// the meantime.
const (
	listenerBackoffMin = 200 * time.Millisecond
	listenerBackoffMax = 5 * time.Second
)

// Client is the portal-side producer API over the provisioning outbox. It
// emits intents, wakes workers, and waits (bounded) for results.
//
// On postgres it holds ONE shared background result-listener that fans out
// terminal-intent notifications to waiters by intent id, so N concurrent
// WaitForResult calls share a single pgx connection instead of opening one
// each. On no-op notifiers there is no listener and WaitForResult polls.
type Client struct {
	store  store.Store
	notify Notifier
	logger *slog.Logger

	// metrics is the optional Workstream F (spec §8.8) producer-side counter
	// handle. nil is a safe no-op so callers (and tests) that don't wire
	// metrics keep working unchanged.
	metrics *Metrics

	// subscriptions fans out result notifications by intent id. Guarded by mu.
	// A waiter registers a channel keyed by intent id; the shared listener
	// goroutine closes the matching channel when that intent's result lands.
	mu     sync.Mutex
	subs   map[string]chan struct{}
	listen bool // true while the shared result listener goroutine is alive

	// listenerCancel tears down the shared result listener's context. nil until
	// the listener is first started; cleared again when it stops. Close() calls
	// it (MEDIUM-2) so the background goroutine + its pgx connection don't leak.
	listenerCancel context.CancelFunc
	closed         bool
}

// NewClient wires a producer Client over the store and notifier. logger may be
// nil (falls back to slog.Default).
func NewClient(s store.Store, n Notifier, logger *slog.Logger) *Client {
	if logger == nil {
		logger = slog.Default()
	}
	return &Client{
		store:  s,
		notify: n,
		logger: logger,
		subs:   make(map[string]chan struct{}),
	}
}

// WithMetrics attaches the Workstream F producer-side metrics handle and
// returns the Client for chaining. Kept separate from NewClient so every
// existing caller (and test) keeps compiling against the metric-free path.
func (c *Client) WithMetrics(m *Metrics) *Client {
	c.metrics = m
	return c
}

// EmitProvision builds, durably inserts, and announces a provision intent.
// InsertIntent is idempotent (ON CONFLICT DO NOTHING on the deterministic id),
// so a producer retry is a safe no-op. A failed NOTIFY is non-fatal — the
// worker's catch-up poll is the durable safety net — so it's logged, not
// returned.
func (c *Client) EmitProvision(ctx context.Context, g domain.Grant, ttl time.Duration) (domain.Intent, error) {
	return c.emit(ctx, ProvisionIntent(g, ttl))
}

// EmitRevoke builds, durably inserts, and announces a revoke intent. Same
// idempotency + best-effort-notify contract as EmitProvision.
func (c *Client) EmitRevoke(ctx context.Context, g domain.Grant) (domain.Intent, error) {
	return c.emit(ctx, RevokeIntent(g))
}

// RetryProvision re-arms a failed provision intent for re-processing (spec §8.6
// retry): it resets the row pending (clearing worker/lease/error, zeroing
// retry_count) and re-NOTIFYs the worker. Idempotent and race-safe via the
// store's status='failed' guard — ErrNotFound (the row was already re-claimed or
// isn't failed) is returned to the caller, which treats it as "nothing to do".
//
// This is the ONLY path that re-enters a failed intent into the claim queue:
// the deterministic id makes EmitProvision's INSERT a no-op on the existing row.
func (c *Client) RetryProvision(ctx context.Context, g domain.Grant, ttl time.Duration) error {
	id := domain.IntentID(g.ID, domain.IntentProvision)
	_ = ttl // ttl is part of the symmetric Emit/Retry API; the retry path only
	// re-arms the existing row to pending and re-NOTIFYs (the intent's frozen
	// RequestedDurationSec is preserved by ResetIntentForRetry), so it has no
	// duration to re-stamp here.
	if err := c.store.ResetIntentForRetry(ctx, id); err != nil {
		return fmt.Errorf("provisioning: reset intent %s: %w", id, err)
	}
	// Best-effort wakeup; the worker's catch-up poll is the durable safety net.
	if err := c.notify.Notify(ctx, ChannelProvisionIntent, id); err != nil {
		c.logger.Warn("provision_retry_notify_failed",
			slog.String("intent_id", id), slog.Any("error", err))
	}
	return nil
}

func (c *Client) emit(ctx context.Context, in domain.Intent) (domain.Intent, error) {
	if err := c.store.InsertIntent(ctx, in); err != nil {
		return domain.Intent{}, fmt.Errorf("provisioning: insert intent %s: %w", in.ID, err)
	}
	// Count the durable emission (post-insert): a failed insert is not an
	// emitted intent. Idempotent re-emits double-count by design — they are
	// real producer calls and the rate is what the dashboard wants.
	c.metrics.IncEmitted(string(in.Kind), in.ID)
	// Best-effort wakeup. The intent is already durable; a missed NOTIFY only
	// costs one catch-up poll interval of latency, never correctness.
	if err := c.notify.Notify(ctx, ChannelProvisionIntent, in.ID); err != nil {
		c.logger.Warn("provision_notify_failed",
			slog.String("intent_id", in.ID), slog.Any("error", err))
	}
	return in, nil
}

// WaitForResult blocks until the intent reaches a terminal state (done/failed)
// or timeout elapses, then returns the intent as last seen.
//
//   - First does a GetIntent: if the worker already finished (fast worker, or
//     an idempotent re-claim that completed before we waited) it returns
//     immediately.
//   - On postgres: parks on the shared result listener (woken when the worker
//     NOTIFYs ChannelProvisionResult with this intent id), re-reading on wake.
//   - On sqlite/memory: degrades to a bounded poll loop (GetIntent every
//     pollInterval).
//   - On timeout: returns the still-pending intent and nil error — the caller
//     maps that to HTTP 202 (provisioning in progress). ctx cancellation
//     surfaces ctx.Err().
func (c *Client) WaitForResult(ctx context.Context, intentID string, timeout time.Duration) (domain.Intent, error) {
	in, err := c.store.GetIntent(ctx, intentID)
	if err != nil {
		return domain.Intent{}, fmt.Errorf("provisioning: get intent %s: %w", intentID, err)
	}
	if in.Status.IsTerminal() {
		// Fast path: the worker already finished. Observe the (possibly tiny)
		// emit→result latency and clear the pending gauge entry.
		c.metrics.ObserveResult(intentID)
		return in, nil
	}

	deadline := time.Now().Add(timeout)
	wctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	// Register interest BEFORE the loop so a NOTIFY arriving while we re-read
	// can't be missed (the listener closes our channel; we then re-GetIntent).
	wake := c.subscribe(wctx, intentID)
	defer c.unsubscribe(intentID)

	for {
		// On stores without a result listener, wake never fires — the timer
		// drives the poll. On postgres, wake fires on the matching NOTIFY and
		// the timer is just the fallback ceiling.
		timer := time.NewTimer(pollInterval)
		select {
		case <-wctx.Done():
			timer.Stop()
			// Distinguish "our wait window lapsed" (return pending → 202) from
			// "the caller's ctx was cancelled" (propagate the error).
			if ctx.Err() != nil {
				return domain.Intent{}, ctx.Err()
			}
			// Wait window lapsed with the intent still pending → portal answers
			// 202. Record the user-visible claim timeout (spec §8.8 alert).
			c.metrics.IncClaimTimeout(intentID)
			return c.lastSeen(ctx, intentID, in)
		case <-wake:
			timer.Stop()
			// wake fires by being CLOSED — either by fire (our NOTIFY arrived) or
			// by wakeAllSubs (the listener dropped its stream, M4). Re-register so
			// the next iteration parks on a fresh channel rather than spinning on a
			// permanently-ready closed one. If the result already landed the
			// GetIntent below returns terminal and we never park again.
			wake = c.subscribe(wctx, intentID)
		case <-timer.C:
		}

		cur, err := c.store.GetIntent(ctx, intentID)
		if err != nil {
			return domain.Intent{}, fmt.Errorf("provisioning: get intent %s: %w", intentID, err)
		}
		in = cur
		if cur.Status.IsTerminal() {
			// Worker reported a terminal result within the wait window: observe
			// the emit→result latency and clear the pending gauge entry.
			c.metrics.ObserveResult(intentID)
			return cur, nil
		}
	}
}

// lastSeen re-reads the intent for the final return, falling back to the last
// in-loop value if the post-timeout read fails — we still want to hand the
// caller a usable pending intent for the 202 mapping.
func (c *Client) lastSeen(ctx context.Context, intentID string, fallback domain.Intent) (domain.Intent, error) {
	if cur, err := c.store.GetIntent(ctx, intentID); err == nil {
		return cur, nil
	}
	return fallback, nil
}

// subscribe registers a wake channel for intentID and lazily starts the shared
// result listener on first use. The returned channel is closed by the listener
// when intentID's result lands (or on a stream drop, to re-arm the waiter — see
// wakeAllSubs). On no-op notifiers the listener's stream never delivers, so the
// channel only ever closes via unsubscribe — and WaitForResult falls through to
// its poll timer.
//
// ctx is intentionally unused: the shared listener runs on a Client-owned
// background context (NOT any single waiter's ctx) so one waiter's timeout can't
// tear it down for the others. The waiter's own ctx still bounds WaitForResult
// via its select; subscribe only needs the intent id.
func (c *Client) subscribe(_ context.Context, intentID string) <-chan struct{} {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Single-flight the (re)start (M5): only kick a listener when one isn't
	// already alive or mid-restart. listen stays true across the backoff window
	// so concurrent waiters don't each fire a reconnect at a dead pg.
	if !c.listen && !c.closed {
		c.listen = true
		go c.runResultListener()
	}
	ch := make(chan struct{})
	c.subs[intentID] = ch
	return ch
}

func (c *Client) unsubscribe(intentID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Drop the registration; closing is the listener's job, but if we're
	// tearing down before any notification we just remove the entry. A double
	// close is avoided because the listener also deletes on fire.
	delete(c.subs, intentID)
}

// runResultListener is the single background goroutine that consumes
// ChannelProvisionResult and closes the matching waiter's channel. It is the
// only one in flight at a time (single-flight via c.listen, set by subscribe),
// which rate-limits restarts (M5): a dead pg gets one reconnect loop with shared
// backoff, not N concurrent attempts from every parked waiter.
//
// The listener outlives any single WaitForResult call, so it runs on a
// Client-owned context derived from Background (NOT the waiter's ctx) — one
// waiter's timeout must not tear the shared listener down under the others. Its
// lifetime is bound to the Client: Close() cancels listenerCancel, which closes
// the notifier stream and ends the loop (MEDIUM-2).
//
// On a stream drop (conn loss) it wakes all parked waiters (M4) so they
// immediately re-GetIntent — returning if their result already landed, or
// re-parking otherwise — then reconnects with bounded exponential backoff
// instead of staying dead and leaving waiters stranded until the next subscribe.
func (c *Client) runResultListener() {
	lctx, cancel := context.WithCancel(context.Background())
	c.mu.Lock()
	if c.closed {
		// Raced with Close between subscribe's flag set and here: don't start.
		c.listen = false
		c.mu.Unlock()
		cancel()
		return
	}
	c.listenerCancel = cancel
	c.mu.Unlock()

	defer func() {
		c.mu.Lock()
		c.listen = false
		c.listenerCancel = nil
		c.mu.Unlock()
		cancel()
	}()

	backoff := listenerBackoffMin
	for {
		stream, err := c.notify.Listen(lctx, ChannelProvisionResult)
		if err != nil {
			c.logger.Warn("provision_result_listen_failed", slog.Any("error", err))
		} else {
			backoff = listenerBackoffMin // healthy subscription: reset backoff
			for payload := range stream {
				c.fire(payload)
			}
		}
		// Stream closed or failed to open. If we're shutting down, stop. Otherwise
		// wake parked waiters (so they re-read / re-park) and retry with backoff —
		// staying alive is what keeps M5's single-flight guarantee meaningful.
		if lctx.Err() != nil {
			return
		}
		c.wakeAllSubs()
		select {
		case <-lctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > listenerBackoffMax {
			backoff = listenerBackoffMax
		}
	}
}

// wakeAllSubs closes every parked waiter's channel and drops the registrations
// (M4). A waiter whose result landed during the drop will see it on the next
// GetIntent and return; one still pending re-parks via a fresh subscribe. Closing
// + deleting under mu keeps it consistent with fire's single-close discipline.
func (c *Client) wakeAllSubs() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for id, ch := range c.subs {
		close(ch)
		delete(c.subs, id)
	}
}

// Close tears down the shared result listener and its underlying connection.
// Safe to call when the listener was never started and safe to call twice — a
// second call is a no-op. It does NOT close the Notifier (the portal owns that
// and closes it separately); it only cancels the listener context this Client
// created, so the notifier's Listen stream ends and the goroutine returns.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	if c.listenerCancel != nil {
		c.listenerCancel()
		c.listenerCancel = nil
	}
	return nil
}

// fire wakes the waiter for the given intent id (the NOTIFY payload), if any.
func (c *Client) fire(intentID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ch, ok := c.subs[intentID]; ok {
		close(ch)
		delete(c.subs, intentID)
	}
}
