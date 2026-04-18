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
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/babs/poc-proxies/internal/auth"
	"github.com/babs/poc-proxies/internal/config"
	pgproto "github.com/babs/poc-proxies/internal/protocol/postgres"
	"github.com/babs/poc-proxies/internal/proxy"
)

// TestPostgresProxyAuthRemapping_SCRAM runs the SCRAM-SHA-256 path: client
// authenticates to proxy via SCRAM, proxy authenticates to backend via SCRAM.
func TestPostgresProxyAuthRemapping_SCRAM(t *testing.T) {
	runPGAuthTest(t, pgproto.ClientAuthSCRAM)
}

// TestPostgresProxyAuthRemapping_Cleartext drives the legacy cleartext path
// on the client side while keeping SCRAM on the backend.
func TestPostgresProxyAuthRemapping_Cleartext(t *testing.T) {
	runPGAuthTest(t, pgproto.ClientAuthCleartext)
}

func runPGAuthTest(t *testing.T, clientAuth pgproto.ClientAuthMethod) {
	ctx := context.Background()

	const (
		backendUser = "app_rw"
		backendPass = "backendSecret123"
		proxyUser   = "alice"
		proxyPass   = "alicePassword456"
		testDB      = "orders"
	)

	ctr, err := postgres.Run(ctx, "postgres:16-alpine",
		postgres.WithDatabase(testDB),
		postgres.WithUsername(backendUser),
		postgres.WithPassword(backendPass),
		postgres.BasicWaitStrategies(),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ctr.Terminate(ctx) })

	host, err := ctr.Host(ctx)
	if err != nil {
		t.Fatal(err)
	}
	port, err := ctr.MappedPort(ctx, "5432/tcp")
	if err != nil {
		t.Fatal(err)
	}
	backendAddr := fmt.Sprintf("%s:%s", host, port.Port())

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

	logBuf := &syncBuf{}
	logger := slog.New(slog.NewJSONHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	cfg := &config.Config{ListenAddr: "127.0.0.1:0", BackendAddr: backendAddr}
	handler := pgproto.NewFromConfig(logger, nil, auth.NewClient(authAPI.URL), nil, clientAuth, cfg)
	srv, err := proxy.NewWithOptions(cfg, handler, logger, proxy.Options{ForcePlainListener: true})
	if err != nil {
		t.Fatal(err)
	}
	proxyCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go srv.Serve(proxyCtx)

	proxyAddr := srv.Addr().String()
	t.Logf("proxy=%s backend=%s portal=%s mode=%s", proxyAddr, backendAddr, authAPI.URL, clientAuth)

	dsn := fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=disable", proxyUser, proxyPass, proxyAddr, testDB)
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	pingCtx, pcancel := context.WithTimeout(ctx, 15*time.Second)
	defer pcancel()
	if err := db.PingContext(pingCtx); err != nil {
		t.Fatalf("ping: %v", err)
	}

	var who string
	if err := db.QueryRow("SELECT current_user").Scan(&who); err != nil {
		t.Fatal(err)
	}
	if who != backendUser {
		t.Errorf("current_user=%q want %q", who, backendUser)
	}

	var answer int
	if err := db.QueryRow("SELECT 42 AS answer").Scan(&answer); err != nil {
		t.Fatal(err)
	}
	if answer != 42 {
		t.Fatalf("answer=%d", answer)
	}

	db.Close()
	cancel()

	for _, want := range []string{"client authenticated", "backend authenticated", "auth remapping complete", "SELECT 42 AS answer"} {
		if !waitForLog(t, logBuf, want, 2*time.Second) {
			t.Errorf("logs missing %q (mode=%s)", want, clientAuth)
		}
	}

	if gotReq.ProxyType != "postgres" {
		t.Errorf("proxy_type=%q want postgres", gotReq.ProxyType)
	}
	if gotReq.BackendServer != backendAddr {
		t.Errorf("backend_server=%q want %q", gotReq.BackendServer, backendAddr)
	}
}

// TestPostgresProxyAuthRemapping_Denied asserts that a 403 from the portal
// prevents the client from connecting.
func TestPostgresProxyAuthRemapping_Denied(t *testing.T) {
	ctx := context.Background()

	ctr, err := postgres.Run(ctx, "postgres:16-alpine",
		postgres.WithDatabase("any"),
		postgres.WithUsername("app_rw"),
		postgres.WithPassword("app_rw"),
		postgres.BasicWaitStrategies(),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ctr.Terminate(ctx) })
	host, _ := ctr.Host(ctx)
	port, _ := ctr.MappedPort(ctx, "5432/tcp")

	authAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer authAPI.Close()

	logger := slog.New(slog.NewJSONHandler(&bytes.Buffer{}, nil))
	cfg := &config.Config{ListenAddr: "127.0.0.1:0", BackendAddr: fmt.Sprintf("%s:%s", host, port.Port())}
	handler := pgproto.NewFromConfig(logger, nil, auth.NewClient(authAPI.URL), nil, pgproto.ClientAuthSCRAM, cfg)
	srv, err := proxy.NewWithOptions(cfg, handler, logger, proxy.Options{ForcePlainListener: true})
	if err != nil {
		t.Fatal(err)
	}
	proxyCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go srv.Serve(proxyCtx)

	dsn := fmt.Sprintf("postgres://nobody:nothing@%s/any?sslmode=disable&connect_timeout=5", srv.Addr().String())
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Ping(); err == nil {
		t.Fatal("expected ping failure (portal denied), got success")
	}
}
