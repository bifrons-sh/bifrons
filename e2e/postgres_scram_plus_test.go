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
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/babs/poc-proxies/internal/auth"
	"github.com/babs/poc-proxies/internal/config"
	pgproto "github.com/babs/poc-proxies/internal/protocol/postgres"
	"github.com/babs/poc-proxies/internal/proxy"
	"github.com/babs/poc-proxies/internal/tlsutil"
)

// TestPostgresProxy_SCRAMPlus_ChannelBinding_Required drives pgx with
// `channel_binding=require` through the proxy over TLS. It should connect
// via SCRAM-SHA-256-PLUS, proving: (a) we advertise PLUS on TLS, (b) our
// tls-server-end-point channel-binding matches what pgx computes, (c) the
// backend-side SCRAM-SHA-256 re-auth is unchanged.
func TestPostgresProxy_SCRAMPlus_ChannelBinding_Required(t *testing.T) {
	skipIfNoDocker(t)

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

	authAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req auth.LookupRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Username != proxyUser {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(auth.AuthResponse{
			Password: proxyPass, BackendUser: backendUser, BackendPass: backendPass,
		})
	}))
	defer authAPI.Close()

	// Issue a leaf for 127.0.0.1/localhost and install it on the proxy for
	// the SSLRequest upgrade. The CA is self-signed so we also hand it to pgx
	// as a RootCAs so the client TLS handshake succeeds.
	certs := genCerts(t)
	tlsCfg, err := tlsutil.ListenerTLSConfig(certs.ServerCert, certs.ServerKey, "", false)
	if err != nil {
		t.Fatal(err)
	}

	logBuf := &syncBuf{}
	logger := slog.New(slog.NewJSONHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	cfg := &config.Config{
		ListenAddr:          "127.0.0.1:0",
		BackendAddr:         backendAddr,
		ClientTLSCBRequired: true, // strict mode: advertise ONLY SCRAM-SHA-256-PLUS
	}
	handler := pgproto.NewFromConfig(logger, tlsCfg, auth.NewClient(authAPI.URL), nil, pgproto.ClientAuthSCRAM, cfg)
	srv, err := proxy.NewWithOptions(cfg, handler, logger, proxy.Options{ForcePlainListener: true})
	if err != nil {
		t.Fatal(err)
	}
	proxyCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go srv.Serve(proxyCtx)

	proxyAddr := srv.Addr().String()
	t.Logf("proxy=%s backend=%s", proxyAddr, backendAddr)

	// Connect via pgx with channel_binding=require + TLS. We pass the
	// self-signed CA via sslrootcert so pgx verifies our cert.
	dsn := fmt.Sprintf(
		"postgres://%s:%s@%s/%s?sslmode=verify-ca&sslrootcert=%s&channel_binding=require",
		proxyUser, proxyPass, proxyAddr, testDB, certs.CACert,
	)
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	pingCtx, pcancel := context.WithTimeout(ctx, 20*time.Second)
	defer pcancel()
	if err := db.PingContext(pingCtx); err != nil {
		t.Fatalf("ping with channel_binding=require: %v\nproxy logs:\n%s", err, logBuf.String())
	}

	var who string
	if err := db.QueryRow("SELECT current_user").Scan(&who); err != nil {
		t.Fatal(err)
	}
	if who != backendUser {
		t.Errorf("current_user=%q want %q", who, backendUser)
	}

	db.Close()
	cancel()

	for _, want := range []string{"client authenticated", "backend authenticated", "scram-plus selected"} {
		if !waitForLog(t, logBuf, want, 2*time.Second) {
			t.Errorf("log missing %q; logs: %s", want, logBuf.String())
		}
	}
	if !strings.Contains(logBuf.String(), "SCRAM-SHA-256-PLUS") {
		t.Errorf("expected PLUS mech in logs; got: %s", logBuf.String())
	}
}

// TestPostgresProxy_NonTLS_PlainSCRAMStillWorks asserts the plain (non-TLS)
// SCRAM path is unaffected when channel binding is not required.
func TestPostgresProxy_NonTLS_PlainSCRAMStillWorks(t *testing.T) {
	skipIfNoDocker(t)

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
	host, _ := ctr.Host(ctx)
	port, _ := ctr.MappedPort(ctx, "5432/tcp")

	authAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req auth.LookupRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Username != proxyUser {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(auth.AuthResponse{
			Password: proxyPass, BackendUser: backendUser, BackendPass: backendPass,
		})
	}))
	defer authAPI.Close()

	logger := slog.New(slog.NewJSONHandler(&syncBuf{}, nil))
	cfg := &config.Config{ListenAddr: "127.0.0.1:0", BackendAddr: fmt.Sprintf("%s:%s", host, port.Port())}
	handler := pgproto.NewFromConfig(logger, nil /*no TLS*/, auth.NewClient(authAPI.URL), nil, pgproto.ClientAuthSCRAM, cfg)
	srv, err := proxy.NewWithOptions(cfg, handler, logger, proxy.Options{ForcePlainListener: true})
	if err != nil {
		t.Fatal(err)
	}
	proxyCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go srv.Serve(proxyCtx)

	// channel_binding=disable keeps pgx on plain SCRAM. sslmode=disable keeps
	// the proxy on plaintext — exercising the fallthrough.
	dsn := fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=disable&channel_binding=disable",
		proxyUser, proxyPass, srv.Addr().String(), testDB)
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	pingCtx, pcancel := context.WithTimeout(ctx, 15*time.Second)
	defer pcancel()
	if err := db.PingContext(pingCtx); err != nil {
		t.Fatalf("ping plain: %v", err)
	}
}
