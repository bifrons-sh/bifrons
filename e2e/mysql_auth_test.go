//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/testcontainers/testcontainers-go/modules/mysql"

	"github.com/babs/poc-proxies/internal/auth"
	"github.com/babs/poc-proxies/internal/config"
	mysqlproto "github.com/babs/poc-proxies/internal/protocol/mysql"
	"github.com/babs/poc-proxies/internal/proxy"
)

// TestMySQLProxyAuthRemapping spins up real MySQL + proxy with a stub portal,
// then connects with portal credentials and verifies the proxy re-mapped to
// the backend role.
//
// The backend user is provisioned with mysql_native_password via an init script
// because MySQL 8.0+ defaults to caching_sha2_password which this proxy does
// not speak on the backend side.
func TestMySQLProxyAuthRemapping(t *testing.T) {
	ctx := context.Background()

	const (
		backendUser = "app_rw"
		backendPass = "backendSecret123"
		proxyUser   = "alice"
		proxyPass   = "alicePassword456"
		testDB      = "orders"
	)

	// Init SQL: rotate the bootstrap user to mysql_native_password, and create
	// the backend role with the same plugin. Must be raw filesystem path for
	// testcontainers' WithScripts, so we write to a temp dir.
	initPath := writeMySQLInitSQL(t, fmt.Sprintf(`
ALTER USER 'root'@'%%' IDENTIFIED WITH mysql_native_password BY 'rootpw';
CREATE USER '%s'@'%%' IDENTIFIED WITH mysql_native_password BY '%s';
GRANT ALL PRIVILEGES ON %s.* TO '%s'@'%%';
FLUSH PRIVILEGES;
`, backendUser, backendPass, testDB, backendUser))

	ctr, err := mysql.Run(ctx, "mysql:8.0",
		mysql.WithDatabase(testDB),
		mysql.WithUsername("bootstrap"),
		mysql.WithPassword("bootstrap"),
		mysql.WithScripts(initPath),
	)
	if err != nil {
		t.Fatal("start mysql container:", err)
	}
	t.Cleanup(func() { ctr.Terminate(ctx) })

	backendHost, err := ctr.Host(ctx)
	if err != nil {
		t.Fatal(err)
	}
	backendPort, err := ctr.MappedPort(ctx, "3306/tcp")
	if err != nil {
		t.Fatal(err)
	}
	backendAddr := fmt.Sprintf("%s:%s", backendHost, backendPort.Port())

	// Stub portal: returns the mapped backend creds when alice asks.
	var gotReq auth.LookupRequest
	authAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotReq)
		if gotReq.Username != proxyUser {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(auth.AuthResponse{
			Password:    proxyPass,
			BackendUser: backendUser,
			BackendPass: backendPass,
		})
	}))
	defer authAPI.Close()

	// Start proxy with auth re-mapping.
	logBuf := &syncBuf{}
	logger := slog.New(slog.NewJSONHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	authClient := auth.NewClient(authAPI.URL)
	cfg := &config.Config{
		ListenAddr:  "127.0.0.1:0",
		BackendAddr: backendAddr,
	}
	handler := mysqlproto.NewFromConfig(logger, authClient, nil, cfg)
	srv, err := proxy.New(cfg, handler, logger)
	if err != nil {
		t.Fatal("create proxy:", err)
	}

	proxyCtx, proxyCancel := context.WithCancel(ctx)
	defer proxyCancel()
	go srv.Serve(proxyCtx)

	proxyAddr := srv.Addr().String()
	t.Logf("proxy=%s backend=%s portal=%s", proxyAddr, backendAddr, authAPI.URL)

	// Connect through proxy with alice's credentials.
	dsn := fmt.Sprintf("%s:%s@tcp(%s)/%s", proxyUser, proxyPass, proxyAddr, testDB)
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	pingCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		t.Fatalf("ping: %v", err)
	}

	var answer int
	if err := db.QueryRowContext(ctx, "SELECT 42 AS answer").Scan(&answer); err != nil {
		t.Fatal(err)
	}
	if answer != 42 {
		t.Fatalf("answer=%d", answer)
	}

	var who string
	if err := db.QueryRowContext(ctx, "SELECT CURRENT_USER()").Scan(&who); err != nil {
		t.Fatal(err)
	}
	// Backend must see the mapped role, not the portal user.
	if !strings.HasPrefix(who, backendUser+"@") {
		t.Errorf("CURRENT_USER()=%q, want prefix %q", who, backendUser+"@")
	}

	db.Close()
	proxyCancel()

	for _, want := range []string{"client authenticated", "backend authenticated", "auth remapping complete", "SELECT 42 AS answer"} {
		if !waitForLog(t, logBuf, want, 2*time.Second) {
			t.Errorf("logs missing %q", want)
		}
	}

	// Portal contract field checks.
	if gotReq.ProxyType != "mysql" {
		t.Errorf("proxy_type=%q want mysql", gotReq.ProxyType)
	}
	if gotReq.BackendServer != backendAddr {
		t.Errorf("backend_server=%q want %q", gotReq.BackendServer, backendAddr)
	}
	if gotReq.SourceIP == "" {
		t.Error("source_ip empty")
	}
}

// TestMySQLProxyAuthRemapping_Denied asserts the proxy returns an ERR packet
// (surfaced as a connect failure) when the portal denies access.
func TestMySQLProxyAuthRemapping_Denied(t *testing.T) {
	ctx := context.Background()

	initPath := writeMySQLInitSQL(t, `ALTER USER 'root'@'%' IDENTIFIED WITH mysql_native_password BY 'rootpw';`)
	ctr, err := mysql.Run(ctx, "mysql:8.0",
		mysql.WithDatabase("any"),
		mysql.WithUsername("bootstrap"),
		mysql.WithPassword("bootstrap"),
		mysql.WithScripts(initPath),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ctr.Terminate(ctx) })
	host, _ := ctr.Host(ctx)
	port, _ := ctr.MappedPort(ctx, "3306/tcp")

	authAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer authAPI.Close()

	logger := slog.New(slog.NewJSONHandler(&bytes.Buffer{}, nil))
	cfg := &config.Config{ListenAddr: "127.0.0.1:0", BackendAddr: fmt.Sprintf("%s:%s", host, port.Port())}
	handler := mysqlproto.NewFromConfig(logger, auth.NewClient(authAPI.URL), nil, cfg)
	srv, err := proxy.New(cfg, handler, logger)
	if err != nil {
		t.Fatal(err)
	}
	proxyCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go srv.Serve(proxyCtx)

	dsn := fmt.Sprintf("nobody:nothing@tcp(%s)/any?timeout=5s", srv.Addr().String())
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Ping(); err == nil {
		t.Fatal("expected ping to fail (portal denied), got success")
	}
}

// writeMySQLInitSQL writes the given SQL to a temp file and returns its path.
// The testcontainers mysql module's WithScripts copies the file into
// /docker-entrypoint-initdb.d/ where mysqld picks it up at first boot.
func writeMySQLInitSQL(t *testing.T, sql string) string {
	t.Helper()
	path := t.TempDir() + "/init.sql"
	if err := os.WriteFile(path, []byte(sql), 0o644); err != nil {
		t.Fatalf("write init sql: %v", err)
	}
	return path
}
