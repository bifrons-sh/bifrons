package auth

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	mrand "math/rand/v2"
	"net/http"
	"time"

	"github.com/xdg-go/scram"
)

// DefaultSCRAMIters matches MongoDB's default for SCRAM-SHA-256 and exceeds
// the RFC 5802 minimum of 4096. Prefer this over raw literals.
const DefaultSCRAMIters = 15000

// LookupRequest matches the portal HLD §5.1 contract for POST /api/v1/auth.
type LookupRequest struct {
	Username      string `json:"username"`
	SourceIP      string `json:"source_ip,omitempty"`
	ProxyType     string `json:"proxy_type,omitempty"`
	BackendServer string `json:"backend_server,omitempty"`
	// Database is the target database/schema the client requested at connect
	// time (Postgres startup `database`, MySQL handshake schema). It lets the
	// portal disambiguate when a user holds several active grants on the same
	// backend that differ only by database — without it the lookup keys solely
	// on (user, backend) and cannot tell two grants apart. Empty when the
	// client supplied none (or the protocol has no per-connection database).
	Database string `json:"database,omitempty"`
}

// AuthResponse is the expected response from the auth API.
// Mirrors HLD §5.1 — Portal API Contract. All non-credential fields are optional
// (omitempty) so portals that do not yet implement policy/TTL surface can still
// return a valid response.
//
// Sensitive fields are redacted by LogValue() to avoid leaking secrets into structured logs.
type AuthResponse struct {
	// Credentials — required. The proxy authenticates the client against Password,
	// then re-authenticates to the backend using BackendUser/BackendPass.
	Password    string `json:"password"`
	BackendUser string `json:"backend_user"`
	BackendPass string `json:"backend_pass"`

	// Grant metadata — optional. Used for audit correlation, TTL enforcement, and
	// policy-driven query authorization. Present fields are logged (non-sensitive).
	GrantID              string    `json:"grant_id,omitempty"`
	Role                 string    `json:"role,omitempty"`
	AllowedDBs           []string  `json:"allowed_dbs,omitempty"`
	ExpiresAt            time.Time `json:"expires_at,omitempty"`
	ConnectionTTLSeconds int       `json:"connection_ttl_seconds,omitempty"`
}

// LogValue implements slog.LogValuer so AuthResponse never leaks secrets into structured logs.
func (a AuthResponse) LogValue() slog.Value {
	attrs := []slog.Attr{
		slog.String("password", "[REDACTED]"),
		slog.String("backend_user", a.BackendUser),
		slog.String("backend_pass", "[REDACTED]"),
	}
	if a.GrantID != "" {
		attrs = append(attrs, slog.String("grant_id", a.GrantID))
	}
	if a.Role != "" {
		attrs = append(attrs, slog.String("role", a.Role))
	}
	if len(a.AllowedDBs) > 0 {
		attrs = append(attrs, slog.Any("allowed_dbs", a.AllowedDBs))
	}
	if !a.ExpiresAt.IsZero() {
		attrs = append(attrs, slog.Time("expires_at", a.ExpiresAt))
	}
	if a.ConnectionTTLSeconds > 0 {
		attrs = append(attrs, slog.Int("connection_ttl_seconds", a.ConnectionTTLSeconds))
	}
	return slog.GroupValue(attrs...)
}

// ErrAccessDenied is returned by Lookup when the portal responds with 401/403.
// Wrapped errors preserve username context via fmt.Errorf.
var ErrAccessDenied = errors.New("access denied")

// Client calls an HTTP API to validate credentials and retrieve backend mapping.
type Client struct {
	url        string
	httpClient *http.Client

	// Retry policy: retries transient failures (net errors + 5xx), never 401/403.
	maxRetries int
	retryBase  time.Duration
}

// Option configures a Client via NewClient.
type Option func(*Client)

// WithHTTPClient overrides the HTTP client (use for test injection).
func WithHTTPClient(hc *http.Client) Option { return func(c *Client) { c.httpClient = hc } }

// WithMaxRetries sets retry attempts on transient failures (default 2).
// Negative values are clamped to 0.
func WithMaxRetries(n int) Option {
	return func(c *Client) {
		if n < 0 {
			n = 0
		}
		c.maxRetries = n
	}
}

// NewClient creates an auth API client with sane Transport defaults and retry policy.
func NewClient(url string, opts ...Option) *Client {
	tr := &http.Transport{
		MaxIdleConns:        32,
		MaxIdleConnsPerHost: 8,
		IdleConnTimeout:     60 * time.Second,
		TLSHandshakeTimeout: 5 * time.Second,
	}
	c := &Client{
		url: url,
		httpClient: &http.Client{
			Timeout:   5 * time.Second,
			Transport: tr,
		},
		maxRetries: 2,
		retryBase:  50 * time.Millisecond,
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Lookup calls the auth API. Returns ErrAccessDenied on 401/403 (no retry), or the
// underlying error after all retry attempts are exhausted.
func (c *Client) Lookup(ctx context.Context, req LookupRequest) (*AuthResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	var lastErr error
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		if attempt > 0 {
			// Jittered backoff: base * 2^(attempt-1) + [0, base) random jitter.
			backoff := c.retryBase << (attempt - 1)
			jitter := time.Duration(mrand.Int64N(int64(c.retryBase)))
			t := time.NewTimer(backoff + jitter)
			select {
			case <-ctx.Done():
				t.Stop()
				return nil, ctx.Err()
			case <-t.C:
			}
		}

		resp, retryable, err := c.do(ctx, body)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		if !retryable {
			return nil, err
		}
	}
	return nil, fmt.Errorf("auth lookup exhausted retries: %w", lastErr)
}

// do performs one Lookup attempt. retryable=true means caller may retry.
func (c *Client) do(ctx context.Context, body []byte) (*AuthResponse, bool, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return nil, false, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		// Network / timeout errors are retryable; ctx cancellation is not.
		if ctx.Err() != nil {
			return nil, false, ctx.Err()
		}
		return nil, true, fmt.Errorf("auth API request: %w", err)
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusOK:
		// fall through
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return nil, false, ErrAccessDenied
	case resp.StatusCode >= 500:
		const maxDiag = 1 << 10
		data, _ := io.ReadAll(io.LimitReader(resp.Body, maxDiag))
		return nil, true, fmt.Errorf("auth API returned %d: %s", resp.StatusCode, string(data))
	default:
		const maxDiag = 1 << 10
		data, _ := io.ReadAll(io.LimitReader(resp.Body, maxDiag))
		return nil, false, fmt.Errorf("auth API returned %d: %s", resp.StatusCode, string(data))
	}

	var authResp AuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return nil, false, fmt.Errorf("decode auth response: %w", err)
	}
	if authResp.Password == "" || authResp.BackendUser == "" || authResp.BackendPass == "" {
		return nil, false, fmt.Errorf("auth response missing required fields")
	}
	return &authResp, false, nil
}

// SCRAMStoredCredentials computes SCRAM-SHA-256 stored credentials from a plaintext password
// using the given iteration count. Callers should pass DefaultSCRAMIters unless they have a reason.
func SCRAMStoredCredentials(password string, iters int) (scram.StoredCredentials, error) {
	if iters < 4096 {
		return scram.StoredCredentials{}, fmt.Errorf("SCRAM iters %d below RFC 5802 minimum", iters)
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return scram.StoredCredentials{}, err
	}

	saltedPassword, err := pbkdf2.Key(sha256.New, password, salt, iters, sha256.Size)
	if err != nil {
		return scram.StoredCredentials{}, fmt.Errorf("pbkdf2: %w", err)
	}

	clientKeyMAC := hmac.New(sha256.New, saltedPassword)
	clientKeyMAC.Write([]byte("Client Key"))
	clientKey := clientKeyMAC.Sum(nil)

	storedKeyHash := sha256.Sum256(clientKey)

	serverKeyMAC := hmac.New(sha256.New, saltedPassword)
	serverKeyMAC.Write([]byte("Server Key"))
	serverKey := serverKeyMAC.Sum(nil)

	return scram.StoredCredentials{
		KeyFactors: scram.KeyFactors{
			Salt:  string(salt),
			Iters: iters,
		},
		StoredKey: storedKeyHash[:],
		ServerKey: serverKey,
	}, nil
}
