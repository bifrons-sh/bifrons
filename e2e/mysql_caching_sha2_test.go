//go:build e2e

package e2e

import (
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

// TestMySQLProxyAuthRemapping_CachingSHA2 spins up a MySQL 8 container where
// the backend user is provisioned with caching_sha2_password (no legacy
// plugin override) and asserts the proxy's backend-side caching_sha2
// handshake — including the RSA full-auth fallback — completes end to end.
func TestMySQLProxyAuthRemapping_CachingSHA2(t *testing.T) {
	skipIfNoDocker(t)

	ctx := context.Background()

	const (
		backendUser = "app_sha2"
		backendPass = "sha2Secret123"
		proxyUser   = "alice"
		proxyPass   = "alicePassword456"
		testDB      = "orders"
	)

	// Root stays on caching_sha2_password (MySQL 8 default). Backend role is
	// explicitly caching_sha2_password to prove this code path is in use.
	initPath := writeMySQLInitSQL(t, fmt.Sprintf(`
CREATE USER '%s'@'%%' IDENTIFIED WITH caching_sha2_password BY '%s';
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

	authAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req auth.LookupRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Username != proxyUser {
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

	logBuf := &syncBuf{}
	logger := slog.New(slog.NewJSONHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	cfg := &config.Config{ListenAddr: "127.0.0.1:0", BackendAddr: backendAddr}
	handler := mysqlproto.NewFromConfig(logger, auth.NewClient(authAPI.URL), nil, cfg)
	srv, err := proxy.New(cfg, handler, logger)
	if err != nil {
		t.Fatal(err)
	}
	proxyCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go srv.Serve(proxyCtx)

	dsn := fmt.Sprintf("%s:%s@tcp(%s)/%s?allowNativePasswords=true", proxyUser, proxyPass, srv.Addr().String(), testDB)
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	pingCtx, pingCancel := context.WithTimeout(ctx, 20*time.Second)
	defer pingCancel()
	if err := db.PingContext(pingCtx); err != nil {
		t.Fatalf("ping: %v", err)
	}

	var who string
	if err := db.QueryRowContext(ctx, "SELECT CURRENT_USER()").Scan(&who); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(who, backendUser+"@") {
		t.Errorf("CURRENT_USER()=%q, want prefix %q", who, backendUser+"@")
	}

	for _, want := range []string{"client authenticated", "backend authenticated"} {
		if !waitForLog(t, logBuf, want, 2*time.Second) {
			t.Errorf("logs missing %q", want)
		}
	}
	if !strings.Contains(logBuf.String(), "caching_sha2_password") {
		t.Errorf("expected caching_sha2_password path to be taken; logs: %s", logBuf.String())
	}
}

// skipIfNoDocker skips the test when no docker socket is reachable at the
// usual locations. Keeps this file green on CI runners without docker.
func skipIfNoDocker(t *testing.T) {
	t.Helper()
	candidates := []string{"/var/run/docker.sock"}
	if h := os.Getenv("DOCKER_HOST"); h != "" {
		// DOCKER_HOST present — trust it, let testcontainers fail cleanly if wrong.
		return
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return
		}
	}
	t.Skip("docker socket not found; skipping e2e test")
}
