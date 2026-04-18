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

	_ "github.com/lib/pq"
	"github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/babs/poc-proxies/internal/config"
	pgproto "github.com/babs/poc-proxies/internal/protocol/postgres"
	"github.com/babs/poc-proxies/internal/proxy"
)

// TestShutdown_MidQueryUnblocksQuickly verifies that cancelling the Serve context
// while a query is in-flight closes backend conns via CloseOnDone and lets Serve
// return within the grace window — not hanging for IdleTimeout.
func TestShutdown_MidQueryUnblocksQuickly(t *testing.T) {
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

	logger := slog.New(slog.NewJSONHandler(&bytes.Buffer{}, nil))
	cfg := &config.Config{
		ListenAddr:          "127.0.0.1:0",
		BackendAddr:         backend,
		HandshakeTimeout:    5 * time.Second,
		IdleTimeout:         5 * time.Minute, // intentionally long — shutdown must not wait for it
		ShutdownGracePeriod: 3 * time.Second,
	}
	srv, err := proxy.NewWithOptions(cfg, pgproto.NewFromConfig(logger, nil, nil, nil, "", cfg), logger,
		proxy.Options{ForcePlainListener: true})
	if err != nil {
		t.Fatal(err)
	}

	proxyCtx, cancelProxy := context.WithCancel(ctx)
	serveDone := make(chan error, 1)
	go func() { serveDone <- srv.Serve(proxyCtx) }()

	dsn := fmt.Sprintf("postgres://testuser:testpass@%s/testdb?sslmode=disable", srv.Addr().String())
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		t.Fatal(err)
	}

	// Kick off a long-running query, then immediately cancel proxy ctx.
	queryDone := make(chan error, 1)
	go func() {
		_, err := db.ExecContext(ctx, "SELECT pg_sleep(60)")
		queryDone <- err
	}()
	time.Sleep(500 * time.Millisecond)

	cancelStart := time.Now()
	cancelProxy()

	select {
	case err := <-serveDone:
		elapsed := time.Since(cancelStart)
		// Grace (3s) + force (5s) + slack (2s) = 10s ceiling.
		if elapsed > 10*time.Second {
			t.Errorf("Serve took %s to return; expected ≤10s", elapsed)
		}
		// err is nil on clean drain, ErrShutdownTimeout if forced — both acceptable here.
		_ = err
	case <-time.After(12 * time.Second):
		t.Fatal("Serve did not return within 12s after ctx cancel — CloseOnDone likely broken")
	}

	// Drain the query goroutine (its conn should have been closed by the proxy).
	select {
	case <-queryDone:
	case <-time.After(5 * time.Second):
		t.Error("query goroutine did not observe conn close")
	}
}
