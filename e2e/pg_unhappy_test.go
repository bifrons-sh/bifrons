//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/babs/poc-proxies/internal/config"
	pgproto "github.com/babs/poc-proxies/internal/protocol/postgres"
	"github.com/babs/poc-proxies/internal/proxy"
)

// startPGProxy boots a proxy in front of a PG container and returns its addr + stop fn.
func startPGProxy(t *testing.T, logBuf *syncBuf) (proxyAddr, backendHostPort string, stop func()) {
	t.Helper()
	ctx := context.Background()

	ctr, err := postgres.Run(ctx, "postgres:16-alpine",
		postgres.WithDatabase("testdb"),
		postgres.WithUsername("testuser"),
		postgres.WithPassword("testpass"),
		postgres.BasicWaitStrategies(),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ctr.Terminate(ctx) })

	host, _ := ctr.Host(ctx)
	port, _ := ctr.MappedPort(ctx, "5432/tcp")
	backend := fmt.Sprintf("%s:%s", host, port.Port())

	logger := slog.New(slog.NewJSONHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	cfg := &config.Config{
		ListenAddr:          "127.0.0.1:0",
		BackendAddr:         backend,
		HandshakeTimeout:    5 * time.Second,
		ShutdownGracePeriod: 3 * time.Second,
	}
	srv, err := proxy.NewWithOptions(cfg, pgproto.NewFromConfig(logger, nil, nil, nil, "", cfg), logger,
		proxy.Options{ForcePlainListener: true})
	if err != nil {
		t.Fatal(err)
	}

	proxyCtx, cancel := context.WithCancel(ctx)
	serveDone := make(chan struct{})
	go func() {
		_ = srv.Serve(proxyCtx)
		close(serveDone)
	}()

	return srv.Addr().String(), backend, func() {
		cancel()
		select {
		case <-serveDone:
		case <-time.After(10 * time.Second):
			t.Error("pg proxy didn't stop")
		}
	}
}

// TestPG_CancelRequest_Plain: run SELECT pg_sleep(5), cancel from second conn.
// Query should return within ~1s with a cancelled-by-user error.
func TestPG_CancelRequest_Plain(t *testing.T) {
	logBuf := &syncBuf{}
	proxyAddr, _, stop := startPGProxy(t, logBuf)
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	dsn := fmt.Sprintf("postgres://testuser:testpass@%s/testdb?sslmode=disable", proxyAddr)
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)

	queryCtx, queryCancel := context.WithTimeout(ctx, 10*time.Second)
	defer queryCancel()

	start := time.Now()
	queryDone := make(chan error, 1)
	go func() {
		_, err := conn.Exec(queryCtx, "SELECT pg_sleep(5)")
		queryDone <- err
	}()

	time.Sleep(500 * time.Millisecond)
	// pgx sends a CancelRequest over a fresh TCP conn to the server (proxy).
	if err := conn.PgConn().CancelRequest(ctx); err != nil {
		t.Fatal("cancel request:", err)
	}

	err = <-queryDone
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected query to be cancelled")
	}
	if elapsed > 3*time.Second {
		t.Errorf("query took %s, cancel didn't take effect fast enough", elapsed)
	}
	if !strings.Contains(strings.ToLower(err.Error()), "cancel") &&
		!strings.Contains(strings.ToLower(err.Error()), "7014") {
		t.Errorf("unexpected cancel error: %v", err)
	}

	time.Sleep(100 * time.Millisecond)
	logs := logBuf.String()
	if !strings.Contains(logs, "cancel request forwarded") {
		t.Errorf("proxy should log 'cancel request forwarded', got: %s", logs)
	}
}

// TestPG_RelayAuthCap verifies the auth-loop cap at unit boundary is exercised in e2e
// by running a normal handshake (cap should not fire). Regression guard: if the cap
// logic were inverted, normal auth would fail.
func TestPG_NormalAuthUnderCap(t *testing.T) {
	logBuf := &syncBuf{}
	proxyAddr, _, stop := startPGProxy(t, logBuf)
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	dsn := fmt.Sprintf("postgres://testuser:testpass@%s/testdb?sslmode=disable", proxyAddr)
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)

	var n int
	if err := conn.QueryRow(ctx, "SELECT 42").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 42 {
		t.Fatalf("got %d", n)
	}

	time.Sleep(50 * time.Millisecond)
	logs := logBuf.String()
	if strings.Contains(logs, "exceeded max auth messages") {
		t.Error("normal auth should not trip the cap")
	}
}

// Dummy placeholder to silence unused import in the case bytes is not referenced.
var _ = bytes.Contains
