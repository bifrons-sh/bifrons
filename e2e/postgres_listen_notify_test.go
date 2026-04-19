//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/lib/pq"
	_ "github.com/lib/pq"
	"github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/babs/poc-proxies/internal/config"
	pgproto "github.com/babs/poc-proxies/internal/protocol/postgres"
	"github.com/babs/poc-proxies/internal/proxy"
)

// TestPostgresListenNotifyThroughProxy proves Phase 4.4: a LISTEN'ing
// connection held idle for longer than the configured client→backend
// idle-timeout still receives async NotificationResponse frames. The fix
// is that the backend→client Relay direction no longer arms a read
// deadline (see internal/protocol/postgres/postgres.go).
func TestPostgresListenNotifyThroughProxy(t *testing.T) {
	skipIfNoDocker(t)

	ctx := context.Background()

	ctr, err := postgres.Run(ctx, "postgres:16-alpine",
		postgres.WithDatabase("testdb"),
		postgres.WithUsername("testuser"),
		postgres.WithPassword("testpass"),
		postgres.BasicWaitStrategies(),
	)
	if err != nil {
		t.Fatal("start postgres container:", err)
	}
	t.Cleanup(func() { _ = ctr.Terminate(ctx) })

	backendHost, err := ctr.Host(ctx)
	if err != nil {
		t.Fatal("get container host:", err)
	}
	backendPort, err := ctr.MappedPort(ctx, "5432/tcp")
	if err != nil {
		t.Fatal("get container port:", err)
	}
	backendAddr := fmt.Sprintf("%s:%s", backendHost, backendPort.Port())

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	// Short idle-timeout makes the regression reproducible: if the
	// backend→client relay still armed a read deadline, conn A would be
	// killed long before the 60s idle window below elapses.
	cfg := &config.Config{
		ListenAddr:  "127.0.0.1:0",
		BackendAddr: backendAddr,
		IdleTimeout: 2 * time.Second,
	}
	handler := pgproto.NewFromConfig(logger, nil, nil, nil, pgproto.ClientAuthSCRAM, cfg)
	srv, err := proxy.NewWithOptions(cfg, handler, logger, proxy.Options{ForcePlainListener: true, DBSystem: "postgresql"})
	if err != nil {
		t.Fatal("create proxy:", err)
	}
	proxyCtx, proxyCancel := context.WithCancel(ctx)
	defer proxyCancel()
	go func() { _ = srv.Serve(proxyCtx) }()

	proxyAddr := srv.Addr().String()
	t.Logf("proxy=%s backend=%s", proxyAddr, backendAddr)

	// Connection A: LISTEN'er, through the proxy. pq.Listener manages its
	// own keep-alive pings, but those are on a long interval (default 90s)
	// — the protocol-level issue is the proxy killing reads after
	// IdleTimeout, which pq cannot mitigate from the client side.
	dsnProxy := fmt.Sprintf("postgres://testuser:testpass@%s/testdb?sslmode=disable", proxyAddr)

	notifyCh := make(chan *pq.Notification, 4)
	listener := pq.NewListener(dsnProxy, 10*time.Millisecond, time.Minute,
		func(ev pq.ListenerEventType, err error) {
			if err != nil {
				t.Logf("listener event=%v err=%v", ev, err)
			}
		})
	t.Cleanup(func() { _ = listener.Close() })

	if err := listener.Listen("foo"); err != nil {
		t.Fatal("listen foo:", err)
	}

	// Drain notifications into our channel.
	go func() {
		for n := range listener.Notify {
			if n != nil {
				notifyCh <- n
			}
		}
	}()

	// Connection B: NOTIFY'er, direct to backend to keep the test
	// self-contained (the proxy side is what we're stressing).
	dsnDirect := fmt.Sprintf("postgres://testuser:testpass@%s/testdb?sslmode=disable", backendAddr)
	notifier, err := sql.Open("postgres", dsnDirect)
	if err != nil {
		t.Fatal("open notifier:", err)
	}
	defer notifier.Close()

	// Wait for the listener to complete its startup + handshake.
	if err := waitListenerReady(listener, 10*time.Second); err != nil {
		t.Fatal("listener ready:", err)
	}

	// First NOTIFY: sanity check that the async frame makes it through.
	if _, err := notifier.ExecContext(ctx, "NOTIFY foo, 'hello'"); err != nil {
		t.Fatal("first notify:", err)
	}
	if err := expectNotification(notifyCh, "hello", 5*time.Second); err != nil {
		t.Fatal("first notification:", err)
	}

	// Hold the listener idle well past IdleTimeout. Pre-fix, the proxy
	// would close conn A at ~2s because the backend→client Read deadline
	// fired. Post-fix, the conn stays open indefinitely on the backend
	// side while still allowing client→backend idle enforcement
	// (pq.Listener reconnects transparently if the client-side read
	// deadline fires — the end-to-end "LISTEN works" guarantee is what
	// matters to applications).
	idleFor := 60 * time.Second
	t.Logf("holding LISTEN conn idle for %s (IdleTimeout=%s)", idleFor, cfg.IdleTimeout)
	time.Sleep(idleFor)

	// Second NOTIFY after the idle window: if the proxy killed the conn,
	// pq.NewListener would have reconnected — but the notification might
	// be lost during the gap. A successful receive here is the proof point.
	if _, err := notifier.ExecContext(ctx, "NOTIFY foo, 'after_idle'"); err != nil {
		t.Fatal("second notify:", err)
	}
	if err := expectNotification(notifyCh, "after_idle", 5*time.Second); err != nil {
		t.Fatalf("post-idle notification: %v\nproxy logs:\n%s", err, logBuf.String())
	}
}

// waitListenerReady polls until lib/pq's listener goroutine has issued its
// LISTEN and is receiving on the wire. pq has no direct "ready" signal so we
// use the Ping method which round-trips through the listener conn.
func waitListenerReady(l *pq.Listener, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		if err := l.Ping(); err == nil {
			return nil
		} else {
			lastErr = err
		}
		time.Sleep(100 * time.Millisecond)
	}
	if lastErr != nil {
		return lastErr
	}
	return fmt.Errorf("listener not ready after %s", timeout)
}

func expectNotification(ch <-chan *pq.Notification, wantPayload string, timeout time.Duration) error {
	t := time.NewTimer(timeout)
	defer t.Stop()
	for {
		select {
		case n := <-ch:
			if n == nil {
				continue
			}
			if n.Extra == wantPayload {
				return nil
			}
			// Drain stale notifications (e.g. from a reconnect replay).
		case <-t.C:
			return fmt.Errorf("no notification with payload %q within %s", wantPayload, timeout)
		}
	}
}
