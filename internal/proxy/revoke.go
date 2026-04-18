package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

// GrantStatus is the minimal payload the revoke watcher cares about.
// Mirrors portal's GET /api/v1/grants/status/:id response.
type GrantStatus struct {
	ID        string    `json:"id"`
	Status    string    `json:"status"`
	ExpiresAt time.Time `json:"expires_at"`
}

// GrantStatusClient abstracts the portal poll so tests can inject a fake.
type GrantStatusClient interface {
	FetchStatus(ctx context.Context, grantID string) (GrantStatus, error)
}

// httpGrantStatusClient calls the portal's proxy-guarded status endpoint.
// Authorization uses the same X-Portal-Token shared secret as /api/v1/auth.
type httpGrantStatusClient struct {
	baseURL     string
	portalToken string
	httpClient  *http.Client
}

// NewHTTPGrantStatusClient builds a status client pointing at a portal base URL
// (e.g. "https://portal:8080"). `portalToken` is forwarded as X-Portal-Token
// on every poll; leave empty for local-dev deployments with the guard disabled.
func NewHTTPGrantStatusClient(baseURL, portalToken string, timeout time.Duration) GrantStatusClient {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	return &httpGrantStatusClient{
		baseURL:     baseURL,
		portalToken: portalToken,
		httpClient: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				MaxIdleConns:        16,
				MaxIdleConnsPerHost: 4,
				IdleConnTimeout:     60 * time.Second,
				TLSHandshakeTimeout: 5 * time.Second,
			},
		},
	}
}

func (c *httpGrantStatusClient) FetchStatus(ctx context.Context, grantID string) (GrantStatus, error) {
	url := c.baseURL + "/api/v1/grants/status/" + grantID
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return GrantStatus{}, err
	}
	if c.portalToken != "" {
		req.Header.Set("X-Portal-Token", c.portalToken)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return GrantStatus{}, fmt.Errorf("grant status request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// Drain a small diagnostic snippet to keep the connection reusable,
		// then surface a typed error so the watcher fails-closed on 5xx/401/etc.
		const maxDiag = 1 << 10
		_, _ = io.CopyN(io.Discard, resp.Body, maxDiag)
		return GrantStatus{}, fmt.Errorf("grant status HTTP %d", resp.StatusCode)
	}
	var gs GrantStatus
	if err := json.NewDecoder(resp.Body).Decode(&gs); err != nil {
		return GrantStatus{}, fmt.Errorf("decode grant status: %w", err)
	}
	return gs, nil
}

// RevokeWatcherConfig parametrises StartRevokeWatcher. Callers populate this
// from the proxy's AuthResponse and a pre-built GrantStatusClient.
type RevokeWatcherConfig struct {
	GrantID              string
	ExpiresAt            time.Time // hint from initial auth; server value takes precedence on each poll
	ConnectionTTLSeconds int       // 0 => no hard TTL (still revoked if portal flips or grant expires)
	Client               GrantStatusClient
	Logger               *slog.Logger

	// MaxFailures is the consecutive-error threshold for fail-closed cancellation.
	// Defaults to 3 when zero; negative disables fail-closed (use for tests only).
	MaxFailures int

	// pollInterval is a test hook. Zero => compute from ConnectionTTLSeconds.
	pollInterval time.Duration
}

// StartRevokeWatcher spawns a goroutine that polls the portal for grant status
// and cancels the provided `cancel` (derived from the conn's childCtx) when:
//   - status != APPROVED
//   - server-side expires_at is in the past
//   - the hard connection TTL deadline is reached
//   - MaxFailures consecutive poll errors occur (fail-closed)
//
// The goroutine exits promptly when ctx is cancelled (happy-path close),
// so it never leaks past the lifetime of the owning connection.
func StartRevokeWatcher(ctx context.Context, cancel context.CancelFunc, cfg RevokeWatcherConfig) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.MaxFailures == 0 {
		cfg.MaxFailures = 3
	}

	interval := cfg.pollInterval
	if interval <= 0 {
		// Poll at TTL/5 bounded by [1s, 30s]. TTL==0 means "no hard TTL"; we
		// still poll at the 30s cap so revocation flips are observed.
		switch {
		case cfg.ConnectionTTLSeconds <= 0:
			interval = 30 * time.Second
		default:
			interval = time.Duration(cfg.ConnectionTTLSeconds) * time.Second / 5
			if interval < time.Second {
				interval = time.Second
			}
			if interval > 30*time.Second {
				interval = 30 * time.Second
			}
		}
	}

	// Hard TTL deadline: if configured, this is the upper bound on connection
	// lifetime even if the portal keeps saying APPROVED. Zero => no hard cap.
	var hardDeadline time.Time
	if cfg.ConnectionTTLSeconds > 0 {
		hardDeadline = time.Now().Add(time.Duration(cfg.ConnectionTTLSeconds) * time.Second)
	}

	log := cfg.Logger.With("grant_id", cfg.GrantID, "component", "revokeWatcher")

	go func() {
		defer cancel() // defensive: any exit path should guarantee child ctx is cancelled

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		var hardTimerC <-chan time.Time
		if !hardDeadline.IsZero() {
			hardTimer := time.NewTimer(time.Until(hardDeadline))
			defer hardTimer.Stop()
			hardTimerC = hardTimer.C
		}

		failures := 0
		for {
			select {
			case <-ctx.Done():
				// Happy-path: parent cancelled (conn closed cleanly). Exit without cancelling again.
				return
			case <-hardTimerC:
				log.Info("connection_ttl_expired", "ttl_seconds", cfg.ConnectionTTLSeconds)
				return
			case <-ticker.C:
			}

			// Bounded per-poll timeout: never let a slow portal drag the tick past
			// the next poll interval. The client also enforces its own Timeout.
			pollCtx, pollCancel := context.WithTimeout(ctx, interval)
			gs, err := cfg.Client.FetchStatus(pollCtx, cfg.GrantID)
			pollCancel()
			if err != nil {
				failures++
				log.Warn("poll_failed", "err", err, "consecutive_failures", failures)
				if cfg.MaxFailures > 0 && failures >= cfg.MaxFailures {
					log.Warn("fail_closed", "consecutive_failures", failures)
					return
				}
				continue
			}
			failures = 0

			if gs.Status != "APPROVED" {
				log.Info("grant_not_approved", "status", gs.Status)
				return
			}
			// Server-side expiry is authoritative; clock skew is bounded by poll
			// interval so we accept small drift rather than cancelling eagerly.
			if !gs.ExpiresAt.IsZero() && time.Now().After(gs.ExpiresAt) {
				log.Info("grant_expired_server", "expires_at", gs.ExpiresAt)
				return
			}
		}
	}()
}
