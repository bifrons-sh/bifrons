//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go/modules/mongodb"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/babs/poc-proxies/internal/auth"
	"github.com/babs/poc-proxies/internal/config"
	mongoproto "github.com/babs/poc-proxies/internal/protocol/mongo"
	"github.com/babs/poc-proxies/internal/proxy"

	"github.com/babs/poc-proxies/portal"
)

// startPortal boots the real portal in-process via httptest.
// Returns URL + store so the test can seed/inspect state.
func startPortal(t *testing.T, logger *slog.Logger) (url string, s portal.Store) {
	t.Helper()
	s = portal.NewMemoryStore()
	srv := httptest.NewServer(portal.NewHandler(&portal.Config{}, s, logger))
	t.Cleanup(srv.Close)
	return srv.URL, s
}

// postJSONOrFail POSTs and fails the test on non-2xx.
func postJSONOrFail(t *testing.T, url string, body any) *http.Response {
	t.Helper()
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("POST %s → %d: %s", url, resp.StatusCode, body)
	}
	return resp
}

// TestPortal_MongoE2E: portal + proxy + real mongo end-to-end.
//
// Scenario:
//  1. Boot real MongoDB (with backend credentials).
//  2. Boot real portal.
//  3. Seed user, backend (matching the container), backend account (matching container creds).
//  4. Create approved grant with portal_password=alicePassword.
//  5. Boot mongo proxy pointing at portal.
//  6. Driver connects with alice/alicePassword → works (ping, insert, find).
//  7. Revoke grant via DELETE → next connection denied with 401-style auth failure.
func TestPortal_MongoE2E(t *testing.T) {
	ctx := context.Background()

	const backendUser = "backendadmin"
	const backendPass = "backendSecret!"

	ctr, err := mongodb.Run(ctx, "mongo:7",
		mongodb.WithUsername(backendUser),
		mongodb.WithPassword(backendPass),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ctr.Terminate(ctx) })

	host, _ := ctr.Host(ctx)
	port, _ := ctr.MappedPort(ctx, "27017/tcp")
	backendAddr := fmt.Sprintf("%s:%s", host, port.Port())

	portalLogs := &syncBuf{}
	portalLogger := slog.New(slog.NewJSONHandler(portalLogs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	portalURL, portalStoreRef := startPortal(t, portalLogger)

	// Seed portal.
	userResp := postJSONOrFail(t, portalURL+"/api/v1/users", map[string]string{"username": "alice"})
	defer userResp.Body.Close()
	var user struct {
		ID string `json:"id"`
	}
	_ = json.NewDecoder(userResp.Body).Decode(&user)

	backendResp := postJSONOrFail(t, portalURL+"/api/v1/backends", map[string]any{
		"name": "mongo-under-test", "type": "mongo",
		"host": host, "port": port.Int(),
	})
	defer backendResp.Body.Close()
	var backend struct {
		ID string `json:"id"`
	}
	_ = json.NewDecoder(backendResp.Body).Decode(&backend)

	acctResp := postJSONOrFail(t, fmt.Sprintf("%s/api/v1/backends/%s/accounts", portalURL, backend.ID),
		map[string]string{"role": "app", "username": backendUser, "password": backendPass})
	defer acctResp.Body.Close()

	const portalPW = "alicePassword"
	grantResp := postJSONOrFail(t, portalURL+"/api/v1/grants", map[string]any{
		"user_id":            user.ID,
		"backend_addr":       backendAddr,
		"role":               "app",
		"database":           "testdb",
		"requested_duration": "1h",
		"portal_password":    portalPW,
	})
	defer grantResp.Body.Close()
	var grant struct {
		ID string `json:"id"`
	}
	_ = json.NewDecoder(grantResp.Body).Decode(&grant)

	// Boot mongo proxy pointing at portal.
	proxyLogs := &syncBuf{}
	proxyLogger := slog.New(slog.NewJSONHandler(proxyLogs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	cfg := &config.Config{
		ListenAddr:          "127.0.0.1:0",
		BackendAddr:         backendAddr,
		HandshakeTimeout:    5 * time.Second,
		ShutdownGracePeriod: 3 * time.Second,
	}
	authClient := auth.NewClient(portalURL+"/api/v1/auth", auth.WithMaxRetries(2))
	handler := mongoproto.NewFromConfig(proxyLogger, authClient, nil, cfg)
	proxySrv, err := proxy.New(cfg, handler, proxyLogger)
	if err != nil {
		t.Fatal(err)
	}
	proxyCtx, cancelProxy := context.WithCancel(ctx)
	proxyDone := make(chan struct{})
	go func() { _ = proxySrv.Serve(proxyCtx); close(proxyDone) }()
	t.Cleanup(func() {
		cancelProxy()
		<-proxyDone
	})

	proxyAddr := proxySrv.Addr().String()

	// Client connects with alice/alicePassword.
	connectCtx, connectCancel := context.WithTimeout(ctx, 20*time.Second)
	defer connectCancel()

	uri := fmt.Sprintf("mongodb://alice:%s@%s/?directConnection=true&authSource=admin&authMechanism=SCRAM-SHA-256&serverSelectionTimeoutMS=5000",
		portalPW, proxyAddr)
	client, err := mongo.Connect(options.Client().ApplyURI(uri))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Disconnect(context.Background()) })

	if err := client.Ping(connectCtx, nil); err != nil {
		t.Fatalf("ping: %v", err)
	}
	coll := client.Database("testdb").Collection("portal_e2e")
	if _, err := coll.InsertOne(connectCtx, bson.D{{Key: "marker", Value: "portal_e2e_ok"}}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	var doc bson.D
	if err := coll.FindOne(connectCtx, bson.D{{Key: "marker", Value: "portal_e2e_ok"}}).Decode(&doc); err != nil {
		t.Fatalf("find: %v", err)
	}

	_ = client.Disconnect(connectCtx)

	if !waitForLog(t, portalLogs, "auth_granted", 2*time.Second) {
		t.Error("portal did not log auth_granted")
	}
	if !waitForLog(t, proxyLogs, "backend authenticated", 2*time.Second) {
		t.Error("proxy did not reach backend auth")
	}

	// Revoke + reconnect must fail.
	delReq, _ := http.NewRequest(http.MethodDelete, fmt.Sprintf("%s/api/v1/grants/%s", portalURL, grant.ID), nil)
	dresp, err := http.DefaultClient.Do(delReq)
	if err != nil {
		t.Fatal(err)
	}
	dresp.Body.Close()

	// Sanity: grant is revoked in store.
	gg, _ := portalStoreRef.GetGrant(ctx, grant.ID)
	if gg.Status != "REVOKED" {
		t.Fatalf("grant not revoked in store: %s", gg.Status)
	}

	denyCtx, denyCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer denyCancel()
	deniedClient, err := mongo.Connect(options.Client().ApplyURI(uri))
	if err == nil {
		defer deniedClient.Disconnect(denyCtx)
		if pingErr := deniedClient.Ping(denyCtx, nil); pingErr == nil {
			t.Error("expected ping to fail after grant revoked")
		}
	}
	if !waitForLog(t, portalLogs, "auth_denied", 2*time.Second) {
		t.Error("portal did not log auth_denied after revocation")
	}
}
