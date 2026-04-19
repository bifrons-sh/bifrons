package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// WebhookNotifier POSTs a JSON payload to a fixed URL on grant creation.
// Exists primarily to feed external four-eyes tooling; other lifecycle
// transitions are no-ops (ManagerApproved/Approved/Denied) since the typical
// receiver only cares about "new grant request". A full lifecycle stream can
// be built by layering a second webhook that handles all transitions.
type WebhookNotifier struct {
	url    string
	secret string
	client *http.Client
	logger *slog.Logger
	wg     sync.WaitGroup
}

// NewWebhookNotifier returns a notifier that POSTs to url on OnGrantCreated.
// A nil client uses a default http.Client with 5s timeout. An empty secret
// sends unsigned payloads (local dev only — receivers should require the
// X-Portal-Signature header).
func NewWebhookNotifier(url, secret string, client *http.Client, logger *slog.Logger) *WebhookNotifier {
	if logger == nil {
		logger = slog.Default()
	}
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	return &WebhookNotifier{url: url, secret: secret, client: client, logger: logger}
}

// OnGrantCreated fires the webhook with the request payload. Non-blocking:
// the background goroutine owns its own timeout + one retry.
func (w *WebhookNotifier) OnGrantCreated(_ context.Context, e Event) error {
	if w.url == "" {
		return nil
	}
	// delivered_at is a top-level field receivers use to drop stale / replayed
	// deliveries (alongside HMAC verification). Separate from requested_at so
	// a retry within the same grant-request window carries a fresh value.
	payload := map[string]any{
		"grant_id":     e.Grant.ID,
		"user":         e.User.Username,
		"backend":      e.Backend.Address(),
		"role":         string(e.Grant.Role),
		"reason":       e.Grant.Reason,
		"requested_by": e.Grant.RequestedBy,
		"requested_at": e.Grant.RequestedAt,
		"delivered_at": time.Now().UTC(),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		w.logger.Error("approval_webhook_marshal", "err", err, "grant_id", e.Grant.ID)
		return err
	}
	// Receivers authenticate the sender via HMAC-SHA256 over the raw body,
	// hex-encoded in X-Portal-Signature. Empty secret = unsigned (local dev).
	var sig string
	if w.secret != "" {
		mac := hmac.New(sha256.New, []byte(w.secret))
		mac.Write(body)
		sig = hex.EncodeToString(mac.Sum(nil))
	}
	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		w.deliver(body, sig, e.Grant.ID)
	}()
	return nil
}

// Other lifecycle events are no-ops for the webhook target — see type doc.
func (w *WebhookNotifier) OnManagerApproved(context.Context, Event) error { return nil }
func (w *WebhookNotifier) OnApproved(context.Context, Event) error        { return nil }
func (w *WebhookNotifier) OnDenied(context.Context, Event) error          { return nil }

// Wait blocks until any in-flight deliveries finish.
func (w *WebhookNotifier) Wait() { w.wg.Wait() }

// deliver does the actual POST + 1 retry. Failures are logged, never raised.
func (w *WebhookNotifier) deliver(body []byte, sig, grantID string) {
	// 1 retry on failure — transient 5xx / network errors shouldn't drop the
	// notification. 500ms gap avoids hammering a target that's already 5xx-ing;
	// bounded to 2 attempts so a sustained outage never queues unboundedly.
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			time.Sleep(500 * time.Millisecond)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(body))
		if err != nil {
			cancel()
			lastErr = err
			break // malformed URL — retry won't help
		}
		req.Header.Set("Content-Type", "application/json")
		if sig != "" {
			req.Header.Set("X-Portal-Signature", "sha256="+sig)
		}
		resp, err := w.client.Do(req)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			cancel()
			if resp.StatusCode < 500 {
				return
			}
			lastErr = fmt.Errorf("webhook returned status %d", resp.StatusCode)
			continue
		}
		cancel()
		lastErr = err
	}
	w.logger.Warn("approval_webhook_failed", "err", lastErr, "grant_id", grantID)
}

// ensure interface compliance at compile time.
var _ Notifier = (*WebhookNotifier)(nil)
