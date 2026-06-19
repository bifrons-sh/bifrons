// Package audit buffers query-audit entries emitted by the protocol handlers
// and ships them in batches to the portal's POST /api/v1/audit/query endpoint.
// Entries are always written to the proxy's local structured log first —
// network shipping is a best-effort supplement that must never block the hot
// relay path or drop data silently without a log line.
package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// Entry mirrors the portal's domain.AuditEntry on the wire. Kept as a local
// type so the proxy doesn't import the portal package directly.
type Entry struct {
	Timestamp     time.Time `json:"timestamp"`
	GrantID       string    `json:"grant_id,omitempty"`
	Username      string    `json:"username"`
	ProxyType     string    `json:"proxy_type"`
	BackendServer string    `json:"backend_server"`
	Database      string    `json:"database,omitempty"`
	Query         string    `json:"query"`
	Truncated     bool      `json:"truncated,omitempty"`
	SourceIP      string    `json:"source_ip,omitempty"`
	DurationMs    int64     `json:"duration_ms,omitempty"`
	TraceID       string    `json:"trace_id,omitempty"`
}

// batchRequest is the wire shape the portal's audit handler expects.
type batchRequest struct {
	Entries []Entry `json:"entries"`
}

// Config tunes the batching client. Defaults (see New) are suitable for a
// POC-scale deployment; tune FlushInterval / MaxBatch for high-QPS workloads.
type Config struct {
	// URL of the portal audit endpoint (e.g. http://portal:8080/api/v1/audit/query).
	// Empty URL disables shipping — the returned Client is a no-op so call
	// sites don't need nil checks.
	URL string
	// Token is the shared secret set as X-Portal-Token. May be empty.
	Token string
	// BufferSize caps the in-memory queue of un-shipped entries. Once full,
	// new entries are dropped with a metric/log; local slog audit is unaffected.
	BufferSize int
	// MaxBatch is the largest batch size posted in a single HTTP call.
	MaxBatch int
	// FlushInterval caps how long an entry waits in the buffer before shipping.
	FlushInterval time.Duration
	// HTTPTimeout bounds a single POST. Retries happen inside this budget.
	HTTPTimeout time.Duration
	// MaxRetries on transient failures (5xx, network). 401/403 are not retried.
	MaxRetries int
}

// Client ships audit entries to the portal in background batches. The zero
// value is not usable; construct via New.
type Client struct {
	cfg    Config
	logger *slog.Logger
	http   *http.Client

	ch   chan Entry
	done chan struct{}

	// runCtx is cancelled on Shutdown so an in-flight retry backoff or POST
	// can be interrupted instead of running its full timeout during teardown.
	runCtx context.Context
	cancel context.CancelFunc

	dropped atomic.Uint64
	sent    atomic.Uint64
	failed  atomic.Uint64

	stopOnce sync.Once
	wg       sync.WaitGroup
}

// New builds an audit Client and starts its background shipper. When cfg.URL
// is empty, returns a no-op Client whose Submit is a silent drop — callers can
// always call Submit without branching on "is audit enabled".
func New(cfg Config, logger *slog.Logger) *Client {
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = 1024
	}
	if cfg.MaxBatch <= 0 {
		cfg.MaxBatch = 64
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 5 * time.Second
	}
	if cfg.HTTPTimeout <= 0 {
		cfg.HTTPTimeout = 10 * time.Second
	}
	if cfg.MaxRetries < 0 {
		cfg.MaxRetries = 0
	}

	runCtx, cancel := context.WithCancel(context.Background())
	c := &Client{
		cfg:    cfg,
		logger: logger.With("component", "audit"),
		http:   &http.Client{Timeout: cfg.HTTPTimeout},
		ch:     make(chan Entry, cfg.BufferSize),
		done:   make(chan struct{}),
		runCtx: runCtx,
		cancel: cancel,
	}

	if cfg.URL == "" {
		// No-op client: drain the channel to keep Submit non-blocking, but
		// never attempt HTTP. Still counts dropped so local metrics reflect
		// reality.
		c.wg.Add(1)
		go c.drainNoop()
		return c
	}

	c.wg.Add(1)
	go c.run()
	return c
}

// Submit enqueues an entry for shipping. Non-blocking: if the buffer is full,
// the entry is dropped and the dropped counter is incremented. The caller has
// already logged locally, so a transient network stall doesn't lose audit.
func (c *Client) Submit(e Entry) {
	if c == nil {
		return
	}
	select {
	case c.ch <- e:
	default:
		n := c.dropped.Add(1)
		// Log only on power-of-two boundaries to bound log spam under sustained
		// drop: n&(n-1)==0 is true exactly when n is a power of two (1,2,4,8…),
		// so the warning frequency falls off logarithmically as drops mount.
		if n&(n-1) == 0 {
			c.logger.Warn("audit buffer full, dropped entry", "total_dropped", n)
		}
	}
}

// Stats returns a snapshot of shipper counters. Useful for /metrics.
func (c *Client) Stats() (sent, failed, dropped uint64) {
	if c == nil {
		return 0, 0, 0
	}
	return c.sent.Load(), c.failed.Load(), c.dropped.Load()
}

// Shutdown stops the background shipper, attempting one final flush within
// the supplied context's deadline. Safe to call multiple times.
func (c *Client) Shutdown(ctx context.Context) error {
	if c == nil {
		return nil
	}
	var err error
	c.stopOnce.Do(func() {
		close(c.done)
		waitDone := make(chan struct{})
		go func() {
			c.wg.Wait()
			close(waitDone)
		}()
		select {
		case <-waitDone:
		case <-ctx.Done():
			// Shutdown deadline hit: propagate it into the shipper so the
			// in-flight final flush's backoff/POST is interrupted rather than
			// running its own HTTPTimeout past the caller's deadline.
			err = ctx.Err()
		}
		// Always release runCtx so the shipper goroutine can exit even if the
		// final flush completed cleanly within the deadline.
		c.cancel()
	})
	return err
}

// drainNoop consumes from ch without shipping; used when audit URL is empty.
// On shutdown it drains any remaining queued entries so the dropped counter
// reflects every Submit the caller made.
func (c *Client) drainNoop() {
	defer c.wg.Done()
	for {
		select {
		case <-c.ch:
			// Still count as dropped so the operator can see "audit not wired"
			// at a glance via /metrics.
			c.dropped.Add(1)
		case <-c.done:
			drained := 0
			for {
				select {
				case <-c.ch:
					c.dropped.Add(1)
					drained++
				default:
					// Surface the otherwise-silent shutdown drop so an operator
					// running without an audit URL doesn't lose entries unseen.
					if drained > 0 {
						c.logger.Warn("audit not wired, dropped queued entries on shutdown", "drained", drained, "total_dropped", c.dropped.Load())
					}
					return
				}
			}
		}
	}
}

// run is the batch-shipper loop.
func (c *Client) run() {
	defer c.wg.Done()

	batch := make([]Entry, 0, c.cfg.MaxBatch)
	tick := time.NewTicker(c.cfg.FlushInterval)
	defer tick.Stop()

	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := c.ship(c.runCtx, batch); err != nil {
			c.failed.Add(uint64(len(batch)))
			c.logger.Warn("audit shipment failed", "err", err, "batch", len(batch))
		} else {
			c.sent.Add(uint64(len(batch)))
		}
		batch = batch[:0]
	}

	for {
		select {
		case e := <-c.ch:
			batch = append(batch, e)
			if len(batch) >= c.cfg.MaxBatch {
				flush()
			}
		case <-tick.C:
			flush()
		case <-c.done:
			// Final drain: pick up anything already queued, then flush once.
			for {
				select {
				case e := <-c.ch:
					batch = append(batch, e)
				default:
					flush()
					return
				}
			}
		}
	}
}

// ship posts one batch, retrying transient failures with exponential backoff.
// ctx is the shipper's lifecycle context: cancelling it (on shutdown) aborts
// an in-flight backoff or POST instead of running the full timeout budget.
func (c *Client) ship(ctx context.Context, batch []Entry) error {
	body, err := json.Marshal(batchRequest{Entries: batch})
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	var lastErr error
	backoff := 200 * time.Millisecond
	for attempt := 0; attempt <= c.cfg.MaxRetries; attempt++ {
		if attempt > 0 {
			// Cancellable backoff: a context-unaware time.Sleep would block
			// teardown for the full backoff window.
			timer := time.NewTimer(backoff)
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			}
			backoff *= 2
		}
		err := c.doPost(ctx, body)
		if err == nil {
			return nil
		}
		if errors.Is(err, errNonRetryable) {
			return err
		}
		lastErr = err
	}
	return fmt.Errorf("exhausted retries: %w", lastErr)
}

var errNonRetryable = errors.New("non-retryable audit failure")

func (c *Client) doPost(parent context.Context, body []byte) error {
	// Derive the per-request timeout from the parent so a shutdown cancellation
	// aborts the POST early while still bounding each attempt independently.
	ctx, cancel := context.WithTimeout(parent, c.cfg.HTTPTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.cfg.Token != "" {
		req.Header.Set("X-Portal-Token", c.cfg.Token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("post: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusAccepted || resp.StatusCode == http.StatusOK {
		return nil
	}
	// 401/403 indicate wrong token or endpoint — retrying wastes cycles.
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("%w: portal returned %d", errNonRetryable, resp.StatusCode)
	}
	// Drain a capped prefix of the body for diagnostics.
	const maxDiag = 1 << 10
	data, _ := io.ReadAll(io.LimitReader(resp.Body, maxDiag))
	return fmt.Errorf("portal returned %d: %s", resp.StatusCode, string(data))
}
