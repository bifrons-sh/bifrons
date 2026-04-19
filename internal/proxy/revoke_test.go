package proxy

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

// fakePortal serves /api/v1/grants/status/:id with atomically-swappable fields
// so tests can flip status / expires_at mid-flight.
type fakePortal struct {
	srv         *httptest.Server
	status      atomic.Value // string
	expiresAt   atomic.Value // time.Time
	httpStatus  atomic.Int32
	calls       atomic.Int32
	receivedTok atomic.Value // string
}

func newFakePortal(t *testing.T, wantToken string) *fakePortal {
	t.Helper()
	fp := &fakePortal{}
	fp.status.Store("ACTIVE")
	fp.expiresAt.Store(time.Now().Add(time.Hour))
	fp.httpStatus.Store(int32(http.StatusOK))
	fp.receivedTok.Store("")

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/grants/status/", func(w http.ResponseWriter, r *http.Request) {
		fp.calls.Add(1)
		fp.receivedTok.Store(r.Header.Get("X-Portal-Token"))
		if wantToken != "" && r.Header.Get("X-Portal-Token") != wantToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		code := int(fp.httpStatus.Load())
		if code != http.StatusOK {
			w.WriteHeader(code)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":         "g-1",
			"status":     fp.status.Load().(string),
			"expires_at": fp.expiresAt.Load().(time.Time),
		})
	})
	fp.srv = httptest.NewServer(mux)
	t.Cleanup(fp.srv.Close)
	return fp
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(io.Discard, nil))
}

// TestRevokeWatcher_HardTTL: connection cancels within ConnectionTTLSeconds even
// when the portal keeps reporting ACTIVE.
func TestRevokeWatcher_HardTTL(t *testing.T) {
	fp := newFakePortal(t, "tok")
	client := NewHTTPGrantStatusClient(fp.srv.URL, "tok", 2*time.Second)

	parent, parentCancel := context.WithCancel(context.Background())
	defer parentCancel()
	childCtx, cancel := context.WithCancel(parent)

	cfg := RevokeWatcherConfig{
		GrantID:              "g-1",
		ExpiresAt:            time.Now().Add(time.Hour),
		ConnectionTTLSeconds: 1,
		Client:               client,
		Logger:               testLogger(),
	}
	StartRevokeWatcher(childCtx, cancel, cfg)

	select {
	case <-childCtx.Done():
		// expected
	case <-time.After(3 * time.Second):
		t.Fatal("child ctx not cancelled within hard TTL window")
	}
}

// TestRevokeWatcher_ExpiresAtHardDeadline: when no ConnectionTTLSeconds is
// set but ExpiresAt is imminent, the watcher still tears the conn down at
// expiry without waiting for a poll tick.
func TestRevokeWatcher_ExpiresAtHardDeadline(t *testing.T) {
	fp := newFakePortal(t, "tok")
	client := NewHTTPGrantStatusClient(fp.srv.URL, "tok", 2*time.Second)

	parent, parentCancel := context.WithCancel(context.Background())
	defer parentCancel()
	childCtx, cancel := context.WithCancel(parent)

	cfg := RevokeWatcherConfig{
		GrantID:              "g-1",
		ExpiresAt:            time.Now().Add(500 * time.Millisecond),
		ConnectionTTLSeconds: 0, // no TTL — deadline must come from ExpiresAt alone
		Client:               client,
		Logger:               testLogger(),
	}
	StartRevokeWatcher(childCtx, cancel, cfg)

	select {
	case <-childCtx.Done():
		// expected
	case <-time.After(2 * time.Second):
		t.Fatal("child ctx not cancelled at ExpiresAt deadline")
	}
}

// TestRevokeWatcher_StatusFlip: connection cancels after portal flips to a
// non-ACTIVE status — covers REVOKED, DENIED, EXPIRED transitions.
func TestRevokeWatcher_StatusFlip(t *testing.T) {
	for _, st := range []string{"REVOKED", "DENIED", "EXPIRED"} {
		t.Run(st, func(t *testing.T) {
			fp := newFakePortal(t, "tok")
			client := NewHTTPGrantStatusClient(fp.srv.URL, "tok", 2*time.Second)

			parent, parentCancel := context.WithCancel(context.Background())
			defer parentCancel()
			childCtx, cancel := context.WithCancel(parent)

			cfg := RevokeWatcherConfig{
				GrantID:              "g-1",
				ExpiresAt:            time.Now().Add(time.Hour),
				ConnectionTTLSeconds: 3600,
				Client:               client,
				Logger:               testLogger(),
				pollInterval:         50 * time.Millisecond,
			}
			StartRevokeWatcher(childCtx, cancel, cfg)

			// Give the watcher time to poll the happy-path state once.
			time.Sleep(120 * time.Millisecond)
			fp.status.Store(st)

			select {
			case <-childCtx.Done():
				// expected within one poll + RTT
			case <-time.After(2 * time.Second):
				t.Fatalf("status=%s: child ctx not cancelled after flip", st)
			}
		})
	}
}

// TestRevokeWatcher_HappyPathNoLeak: when the parent cancels the child (clean
// client close), the watcher goroutine must exit promptly — no leak.
func TestRevokeWatcher_HappyPathNoLeak(t *testing.T) {
	fp := newFakePortal(t, "")
	client := NewHTTPGrantStatusClient(fp.srv.URL, "", 2*time.Second)

	time.Sleep(50 * time.Millisecond)
	runtime.GC()
	before := runtime.NumGoroutine()

	parent, parentCancel := context.WithCancel(context.Background())
	childCtx, cancel := context.WithCancel(parent)

	cfg := RevokeWatcherConfig{
		GrantID:              "g-1",
		ExpiresAt:            time.Now().Add(time.Hour),
		ConnectionTTLSeconds: 3600,
		Client:               client,
		Logger:               testLogger(),
		pollInterval:         50 * time.Millisecond,
	}
	StartRevokeWatcher(childCtx, cancel, cfg)

	// Happy-path: parent cancels first.
	parentCancel()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		runtime.GC()
		if runtime.NumGoroutine() <= before+1 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("watcher leaked: before=%d after=%d", before, runtime.NumGoroutine())
}

// TestRevokeWatcher_FailClosed: N consecutive 5xx failures must cancel the conn.
func TestRevokeWatcher_FailClosed(t *testing.T) {
	fp := newFakePortal(t, "")
	fp.httpStatus.Store(int32(http.StatusInternalServerError))
	client := NewHTTPGrantStatusClient(fp.srv.URL, "", 500*time.Millisecond)

	parent, parentCancel := context.WithCancel(context.Background())
	defer parentCancel()
	childCtx, cancel := context.WithCancel(parent)

	cfg := RevokeWatcherConfig{
		GrantID:              "g-1",
		ExpiresAt:            time.Now().Add(time.Hour),
		ConnectionTTLSeconds: 3600,
		Client:               client,
		Logger:               testLogger(),
		pollInterval:         30 * time.Millisecond,
		MaxFailures:          3,
	}
	StartRevokeWatcher(childCtx, cancel, cfg)

	select {
	case <-childCtx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("fail-closed never triggered")
	}
}

// TestRevokeWatcher_PastExpiry: server-reported expires_at in the past must cancel.
func TestRevokeWatcher_PastExpiry(t *testing.T) {
	fp := newFakePortal(t, "")
	fp.expiresAt.Store(time.Now().Add(-time.Minute))
	client := NewHTTPGrantStatusClient(fp.srv.URL, "", 2*time.Second)

	parent, parentCancel := context.WithCancel(context.Background())
	defer parentCancel()
	childCtx, cancel := context.WithCancel(parent)

	cfg := RevokeWatcherConfig{
		GrantID:              "g-1",
		ExpiresAt:            time.Now().Add(time.Hour),
		ConnectionTTLSeconds: 3600,
		Client:               client,
		Logger:               testLogger(),
		pollInterval:         30 * time.Millisecond,
	}
	StartRevokeWatcher(childCtx, cancel, cfg)

	select {
	case <-childCtx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("watcher did not honour server-side past expires_at")
	}
}

// TestRevokeWatcher_SendsPortalToken: the HTTP client forwards X-Portal-Token.
func TestRevokeWatcher_SendsPortalToken(t *testing.T) {
	fp := newFakePortal(t, "abc123")
	client := NewHTTPGrantStatusClient(fp.srv.URL, "abc123", 2*time.Second)

	parent, parentCancel := context.WithCancel(context.Background())
	defer parentCancel()
	childCtx, cancel := context.WithCancel(parent)

	cfg := RevokeWatcherConfig{
		GrantID:              "g-1",
		ExpiresAt:            time.Now().Add(time.Hour),
		ConnectionTTLSeconds: 3600,
		Client:               client,
		Logger:               testLogger(),
		pollInterval:         30 * time.Millisecond,
	}
	StartRevokeWatcher(childCtx, cancel, cfg)
	time.Sleep(150 * time.Millisecond)

	if got := fp.receivedTok.Load().(string); got != "abc123" {
		t.Fatalf("portal did not receive expected token: got %q", got)
	}
}
