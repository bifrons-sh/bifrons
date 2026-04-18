//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/testcontainers/testcontainers-go/modules/mysql"

	"github.com/babs/poc-proxies/internal/config"
	mysqlproto "github.com/babs/poc-proxies/internal/protocol/mysql"
	"github.com/babs/poc-proxies/internal/proxy"
)

func TestMySQLProxy(t *testing.T) {
	ctx := context.Background()

	// Start MySQL container
	ctr, err := mysql.Run(ctx, "mysql:8.0",
		mysql.WithDatabase("testdb"),
		mysql.WithUsername("testuser"),
		mysql.WithPassword("testpass"),
	)
	if err != nil {
		t.Fatal("start mysql container:", err)
	}
	t.Cleanup(func() { ctr.Terminate(ctx) })

	backendHost, err := ctr.Host(ctx)
	if err != nil {
		t.Fatal("get container host:", err)
	}
	backendPort, err := ctr.MappedPort(ctx, "3306/tcp")
	if err != nil {
		t.Fatal("get container port:", err)
	}
	backendAddr := fmt.Sprintf("%s:%s", backendHost, backendPort.Port())

	// Start proxy
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	cfg := &config.Config{
		ListenAddr:  "127.0.0.1:0",
		BackendAddr: backendAddr,
	}
	handler := mysqlproto.NewHandler(logger)
	srv, err := proxy.New(cfg, handler, logger)
	if err != nil {
		t.Fatal("create proxy:", err)
	}

	proxyCtx, proxyCancel := context.WithCancel(ctx)
	defer proxyCancel()
	go srv.Serve(proxyCtx)

	proxyAddr := srv.Addr().String()
	t.Logf("proxy listening on %s, backend on %s", proxyAddr, backendAddr)

	// Connect through proxy
	dsn := fmt.Sprintf("testuser:testpass@tcp(%s)/testdb", proxyAddr)
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatal("open db:", err)
	}
	defer db.Close()

	// Wait for connection to be ready
	dbCtx, dbCancel := context.WithTimeout(ctx, 10*time.Second)
	defer dbCancel()
	if err := db.PingContext(dbCtx); err != nil {
		t.Fatal("ping:", err)
	}

	// Run a test query
	var result int
	if err := db.QueryRowContext(ctx, "SELECT 42 AS answer").Scan(&result); err != nil {
		t.Fatal("query:", err)
	}
	if result != 42 {
		t.Fatalf("expected 42, got %d", result)
	}

	// Run a more identifiable query
	rows, err := db.QueryContext(ctx, "SELECT 'hello_from_e2e_test' AS marker")
	if err != nil {
		t.Fatal("marker query:", err)
	}
	rows.Close()

	// Close connection and stop proxy to flush logs
	db.Close()
	proxyCancel()
	time.Sleep(100 * time.Millisecond)

	// Verify logs contain the queries
	logs := logBuf.String()
	t.Logf("proxy logs:\n%s", logs)

	if !strings.Contains(logs, "SELECT 42 AS answer") {
		t.Error("logs should contain 'SELECT 42 AS answer'")
	}
	if !strings.Contains(logs, "hello_from_e2e_test") {
		t.Error("logs should contain 'hello_from_e2e_test'")
	}
	if !strings.Contains(logs, `"msg":"connect"`) {
		t.Error("logs should contain connect event")
	}
}
