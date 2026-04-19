//go:build e2e

package e2e

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/babs/poc-proxies/internal/audit"
	"github.com/babs/poc-proxies/internal/auth"
	"github.com/babs/poc-proxies/internal/config"
	pgproto "github.com/babs/poc-proxies/internal/protocol/postgres"
	"github.com/babs/poc-proxies/internal/proxy"

	"github.com/babs/poc-proxies/portal"
)

// TestAudit_ProxyShipsToPortal: connect through the PG proxy, run a few
// queries, and verify the portal's audit store saw them. Exercises the full
// chain: proxy local slog + POST /api/v1/audit/query → portal store.
func TestAudit_ProxyShipsToPortal(t *testing.T) {
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

	// Seed user / backend / account / grant.
	postJSONOrFail(t, portalURL+"/api/v1/users", map[string]string{"username": "alice"}).Body.Close()
	postJSONOrFail(t, portalURL+"/api/v1/backends", map[string]any{
		"name": "pg-audit-test", "type": "postgres",
		"host": host, "port": port.Int(),
	}).Body.Close()

	// Find the backend ID to seed its account.
	backends, _ := portalStoreRef.(interface {
		ListBackends(context.Context) ([]portal.Backend, error)
	}).ListBackends(ctx)
	if len(backends) != 1 {
		t.Fatalf("want 1 backend, got %d", len(backends))
	}
	postJSONOrFail(t, fmt.Sprintf("%s/api/v1/backends/%s/accounts", portalURL, backends[0].ID),
		map[string]string{"role": "app", "username": backendUser, "password": backendPass}).Body.Close()

	userResp := postJSONOrFail(t, portalURL+"/api/v1/grants", map[string]any{
		"user_id":            lookupUserID(t, portalStoreRef, "alice"),
		"backend_addr":       backendAddr,
		"role":               "app",
		"database":           testDB,
		"portal_password":    portalPW,
	})
	userResp.Body.Close()

	// Build audit client pointed at the portal.
	auditClient := audit.New(audit.Config{
		URL:           portalURL + "/api/v1/audit/query",
		MaxBatch:      4,
		FlushInterval: 200 * time.Millisecond,
	}, portalLogger)

	proxyLogs := &syncBuf{}
	proxyLogger := slog.New(slog.NewJSONHandler(proxyLogs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	cfg := &config.Config{
		ListenAddr:          "127.0.0.1:0",
		BackendAddr:         backendAddr,
		HandshakeTimeout:    5 * time.Second,
		ShutdownGracePeriod: 3 * time.Second,
	}
	authClient := auth.NewClient(portalURL+"/api/v1/auth", auth.WithMaxRetries(2))
	handler := pgproto.NewFromConfig(proxyLogger, nil, authClient, auditClient, pgproto.ClientAuthSCRAM, cfg)
	proxySrv, err := proxy.NewWithOptions(cfg, handler, proxyLogger, proxy.Options{ForcePlainListener: true})
	if err != nil {
		t.Fatal(err)
	}
	proxyCtx, cancel := context.WithCancel(ctx)
	proxyDone := make(chan struct{})
	go func() { _ = proxySrv.Serve(proxyCtx); close(proxyDone) }()
	t.Cleanup(func() {
		cancel()
		<-proxyDone
		_ = auditClient.Shutdown(context.Background())
	})

	// Connect + run queries that should land in audit.
	dsn := fmt.Sprintf("postgres://alice:%s@%s/%s?sslmode=disable", portalPW, proxySrv.Addr().String(), testDB)
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
	for _, q := range []string{
		"SELECT 1 AS audit_marker_one",
		"SELECT 2 AS audit_marker_two",
		"SELECT 3 AS audit_marker_three",
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("exec %q: %v", q, err)
		}
	}
	db.Close()

	// Wait for the audit batcher to flush to the portal.
	if !waitForLog(t, portalLogs, "audit_batch_accepted", 3*time.Second) {
		t.Fatalf("portal never logged audit_batch_accepted; proxy logs:\n%s\nportal logs:\n%s",
			proxyLogs.String(), portalLogs.String())
	}

	// Verify the stored audit entries include our markers.
	af := portal.AuditFilter{Username: "alice"}
	entries, err := portalStoreRef.ListAudit(ctx, af)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) < 3 {
		t.Fatalf("want ≥3 audit entries for alice, got %d", len(entries))
	}
	var sawOne, sawTwo, sawThree bool
	for _, e := range entries {
		if strings.Contains(e.Query, "audit_marker_one") {
			sawOne = true
		}
		if strings.Contains(e.Query, "audit_marker_two") {
			sawTwo = true
		}
		if strings.Contains(e.Query, "audit_marker_three") {
			sawThree = true
		}
	}
	if !sawOne || !sawTwo || !sawThree {
		t.Errorf("audit markers missing: one=%v two=%v three=%v entries=%+v", sawOne, sawTwo, sawThree, entries)
	}

	// And the local proxy slog should also carry them — dual sink is intentional.
	for _, marker := range []string{"audit_marker_one", "audit_marker_two", "audit_marker_three"} {
		if !strings.Contains(proxyLogs.String(), marker) {
			t.Errorf("proxy local logs missing %q", marker)
		}
	}
}

// lookupUserID is a tiny helper that finds a user by username on the portal
// store interface so the test doesn't need to parse create-user responses.
func lookupUserID(t *testing.T, s portal.Store, username string) string {
	t.Helper()
	u, err := s.GetUserByUsername(context.Background(), username)
	if err != nil {
		t.Fatal(err)
	}
	return u.ID
}
