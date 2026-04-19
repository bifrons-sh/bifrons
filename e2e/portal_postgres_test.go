//go:build e2e

package e2e

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/babs/poc-proxies/internal/auth"
	"github.com/babs/poc-proxies/internal/config"
	pgproto "github.com/babs/poc-proxies/internal/protocol/postgres"
	"github.com/babs/poc-proxies/internal/proxy"

	"github.com/babs/poc-proxies/portal"
)

// TestPortal_PostgresE2E: real PostgreSQL + real portal + proxy end-to-end.
// Mirrors TestPortal_MySQLE2E but for PG. Exercises SCRAM on the client side.
func TestPortal_PostgresE2E(t *testing.T) {
	ctx := context.Background()

	const (
		backendUser = "app_rw"
		backendPass = "backendSecret!"
		testDB      = "orders"
		portalPW    = "alicePassword"
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
	backendAddr := fmt.Sprintf("%s:%s", host, port.Port())

	portalLogs := &syncBuf{}
	portalLogger := slog.New(slog.NewJSONHandler(portalLogs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	portalURL, portalStoreRef := startPortal(t, portalLogger)

	userResp := postJSONOrFail(t, portalURL+"/api/v1/users", map[string]string{"username": "alice"})
	defer userResp.Body.Close()
	var user struct {
		ID string `json:"id"`
	}
	_ = json.NewDecoder(userResp.Body).Decode(&user)

	backendResp := postJSONOrFail(t, portalURL+"/api/v1/backends", map[string]any{
		"name": "pg-under-test", "type": "postgres",
		"host": host, "port": port.Int(),
	})
	defer backendResp.Body.Close()
	var backendRec struct {
		ID string `json:"id"`
	}
	_ = json.NewDecoder(backendResp.Body).Decode(&backendRec)

	acctResp := postJSONOrFail(t, fmt.Sprintf("%s/api/v1/backends/%s/accounts", portalURL, backendRec.ID),
		map[string]string{"role": "app", "username": backendUser, "password": backendPass})
	defer acctResp.Body.Close()

	grantResp := postJSONOrFail(t, portalURL+"/api/v1/grants", map[string]any{
		"user_id":            user.ID,
		"backend_addr":       backendAddr,
		"role":               "app",
		"database":           testDB,
		"portal_password":    portalPW,
	})
	defer grantResp.Body.Close()
	var grant struct {
		ID string `json:"id"`
	}
	_ = json.NewDecoder(grantResp.Body).Decode(&grant)

	proxyLogs := &syncBuf{}
	proxyLogger := slog.New(slog.NewJSONHandler(proxyLogs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	cfg := &config.Config{
		ListenAddr:          "127.0.0.1:0",
		BackendAddr:         backendAddr,
		HandshakeTimeout:    5 * time.Second,
		ShutdownGracePeriod: 3 * time.Second,
	}
	authClient := auth.NewClient(portalURL+"/api/v1/auth", auth.WithMaxRetries(2))
	handler := pgproto.NewFromConfig(proxyLogger, nil, authClient, nil, pgproto.ClientAuthSCRAM, cfg)
	proxySrv, err := proxy.NewWithOptions(cfg, handler, proxyLogger, proxy.Options{ForcePlainListener: true})
	if err != nil {
		t.Fatal(err)
	}
	proxyCtx, cancel := context.WithCancel(ctx)
	proxyDone := make(chan struct{})
	go func() { _ = proxySrv.Serve(proxyCtx); close(proxyDone) }()
	t.Cleanup(func() { cancel(); <-proxyDone })

	proxyAddr := proxySrv.Addr().String()

	dsn := fmt.Sprintf("postgres://alice:%s@%s/%s?sslmode=disable", portalPW, proxyAddr, testDB)
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

	db.Close()

	if !waitForLog(t, portalLogs, "auth_granted", 2*time.Second) {
		t.Error("portal did not log auth_granted")
	}
	if !waitForLog(t, proxyLogs, "backend authenticated", 2*time.Second) {
		t.Error("proxy did not reach backend auth")
	}

	delReq, _ := http.NewRequest(http.MethodDelete, fmt.Sprintf("%s/api/v1/grants/%s", portalURL, grant.ID), nil)
	dresp, err := http.DefaultClient.Do(delReq)
	if err != nil {
		t.Fatal(err)
	}
	dresp.Body.Close()

	gg, _ := portalStoreRef.GetGrant(ctx, grant.ID)
	if gg.Status != portal.GrantRevoked {
		t.Fatalf("grant not revoked in store: %s", gg.Status)
	}

	db2, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	if err := db2.Ping(); err == nil {
		t.Error("expected ping to fail after revoke")
	}
	if !waitForLog(t, portalLogs, "auth_denied", 2*time.Second) {
		t.Error("portal did not log auth_denied after revocation")
	}
}
