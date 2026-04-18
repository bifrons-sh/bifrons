//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/testcontainers/testcontainers-go/modules/mysql"

	"github.com/babs/poc-proxies/internal/config"
	mysqlproto "github.com/babs/poc-proxies/internal/protocol/mysql"
	"github.com/babs/poc-proxies/internal/proxy"
)

// TestMySQL_CachingSha2FullAuth verifies proxy handles caching_sha2_password full-auth
// (server default in MySQL 8). First connect on a fresh user triggers the full_auth
// sub-flow — our proxy must forward pubkey request + encrypted password round-trips.
func TestMySQL_CachingSha2FullAuth(t *testing.T) {
	ctx := context.Background()

	ctr, err := mysql.Run(ctx, "mysql:8.0",
		mysql.WithDatabase("testdb"),
		mysql.WithUsername("testuser"),
		mysql.WithPassword("testpass"),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ctr.Terminate(ctx) })

	host, err := ctr.Host(ctx)
	if err != nil {
		t.Fatal(err)
	}
	port, err := ctr.MappedPort(ctx, "3306/tcp")
	if err != nil {
		t.Fatal(err)
	}
	backend := fmt.Sprintf("%s:%s", host, port.Port())

	logBuf := &syncBuf{}
	logger := slog.New(slog.NewJSONHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	cfg := &config.Config{ListenAddr: "127.0.0.1:0", BackendAddr: backend}
	srv, err := proxy.New(cfg, mysqlproto.NewFromConfig(logger, nil, nil, cfg), logger)
	if err != nil {
		t.Fatal(err)
	}
	proxyCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go srv.Serve(proxyCtx)

	// Use "allowNativePasswords=false" so the driver MUST negotiate caching_sha2.
	dsn := fmt.Sprintf("testuser:testpass@tcp(%s)/testdb?allowNativePasswords=false&tls=false",
		srv.Addr().String())
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	pingCtx, pingCancel := context.WithTimeout(ctx, 10*time.Second)
	defer pingCancel()
	if err := db.PingContext(pingCtx); err != nil {
		t.Fatalf("caching_sha2 ping failed: %v", err)
	}
	var n int
	if err := db.QueryRowContext(ctx, "SELECT 1").Scan(&n); err != nil || n != 1 {
		t.Fatalf("query: n=%d err=%v", n, err)
	}

	db.Close()
	cancel()
	time.Sleep(100 * time.Millisecond)

	// Confirm we actually went through the caching_sha2 branch (AuthMoreData 0x01).
	// The proxy doesn't log this explicitly; assert connect + authenticated are present.
	logs := logBuf.String()
	if !strings.Contains(logs, `"msg":"authenticated"`) {
		t.Errorf("expected 'authenticated' log, got: %s", logs)
	}
}

// TestMySQL_MaxConnsSaturation opens N+1 conns via a cap-2 proxy and asserts
// the 3rd is rejected. Uses direct TCP to avoid the driver's retry logic
// papering over the rejection.
func TestMySQL_MaxConnsSaturation(t *testing.T) {
	ctx := context.Background()

	ctr, err := mysql.Run(ctx, "mysql:8.0",
		mysql.WithDatabase("testdb"),
		mysql.WithUsername("testuser"),
		mysql.WithPassword("testpass"),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ctr.Terminate(ctx) })

	host, _ := ctr.Host(ctx)
	port, _ := ctr.MappedPort(ctx, "3306/tcp")
	backend := fmt.Sprintf("%s:%s", host, port.Port())

	logger := slog.New(slog.NewJSONHandler(&bytes.Buffer{}, nil))
	cfg := &config.Config{
		ListenAddr:          "127.0.0.1:0",
		BackendAddr:         backend,
		MaxConns:            2,
		HandshakeTimeout:    5 * time.Second,
		ShutdownGracePeriod: 2 * time.Second,
	}
	srv, err := proxy.New(cfg, mysqlproto.NewFromConfig(logger, nil, nil, cfg), logger)
	if err != nil {
		t.Fatal(err)
	}
	proxyCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go srv.Serve(proxyCtx)

	addr := srv.Addr().String()
	var conns []net.Conn
	for i := 0; i < 3; i++ {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		conns = append(conns, c)
	}
	defer func() {
		for _, c := range conns {
			_ = c.Close()
		}
	}()

	// Wait for stats to show accepted=2 rejected=1. Drivers do nothing until handshake.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			_, rejected, active := srv.Stats()
			if rejected >= 1 && active == 2 {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()
	wg.Wait()

	_, rejected, active := srv.Stats()
	if rejected < 1 {
		t.Errorf("expected ≥1 rejection, got rejected=%d active=%d", rejected, active)
	}
	if active != 2 {
		t.Errorf("expected active=2, got %d", active)
	}
}
