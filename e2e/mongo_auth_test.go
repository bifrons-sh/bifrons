//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
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
)

func TestMongoProxyAuthRemapping(t *testing.T) {
	ctx := context.Background()

	// Backend credentials
	const backendUser = "backendadmin"
	const backendPass = "backendSecret123"

	// Proxy-facing credentials (what the client uses)
	const proxyUser = "alice"
	const proxyPass = "alicePassword456"

	// Start MongoDB container WITH auth enabled
	ctr, err := mongodb.Run(ctx, "mongo:7",
		mongodb.WithUsername(backendUser),
		mongodb.WithPassword(backendPass),
	)
	if err != nil {
		t.Fatal("start mongo container:", err)
	}
	t.Cleanup(func() { ctr.Terminate(ctx) })

	backendHost, err := ctr.Host(ctx)
	if err != nil {
		t.Fatal("get container host:", err)
	}
	backendPort, err := ctr.MappedPort(ctx, "27017/tcp")
	if err != nil {
		t.Fatal("get container port:", err)
	}
	backendAddr := fmt.Sprintf("%s:%s", backendHost, backendPort.Port())

	// Mock auth API verifies the portal contract (§5.1) — username, source_ip,
	// proxy_type, backend_server must all be present.
	var gotReq auth.LookupRequest
	authAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotReq)

		if gotReq.Username == proxyUser {
			json.NewEncoder(w).Encode(auth.AuthResponse{
				Password:    proxyPass,
				BackendUser: backendUser,
				BackendPass: backendPass,
			})
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	defer authAPI.Close()

	// Start proxy with auth re-mapping
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	authClient := auth.NewClient(authAPI.URL)
	cfg := &config.Config{
		ListenAddr:  "127.0.0.1:0",
		BackendAddr: backendAddr,
	}
	handler := mongoproto.NewFromConfig(logger, authClient, nil, cfg)
	srv, err := proxy.New(cfg, handler, logger)
	if err != nil {
		t.Fatal("create proxy:", err)
	}

	proxyCtx, proxyCancel := context.WithCancel(ctx)
	defer proxyCancel()
	go srv.Serve(proxyCtx)

	proxyAddr := srv.Addr().String()
	t.Logf("proxy listening on %s, backend on %s, auth API on %s", proxyAddr, backendAddr, authAPI.URL)

	// Connect through proxy using proxy credentials (alice/alicePassword456)
	uri := fmt.Sprintf("mongodb://%s:%s@%s/?directConnection=true&authSource=admin&authMechanism=SCRAM-SHA-256", proxyUser, proxyPass, proxyAddr)
	client, err := mongo.Connect(options.Client().ApplyURI(uri))
	if err != nil {
		t.Fatal("connect mongo:", err)
	}
	defer client.Disconnect(ctx)

	// Ping
	pingCtx, pingCancel := context.WithTimeout(ctx, 15*time.Second)
	defer pingCancel()
	if err := client.Ping(pingCtx, nil); err != nil {
		t.Fatal("ping:", err)
	}

	// Insert a document
	coll := client.Database("testdb").Collection("auth_test")
	_, err = coll.InsertOne(ctx, bson.D{{Key: "marker", Value: "auth_remapping_works"}})
	if err != nil {
		t.Fatal("insert:", err)
	}

	// Find it back
	var doc bson.D
	err = coll.FindOne(ctx, bson.D{{Key: "marker", Value: "auth_remapping_works"}}).Decode(&doc)
	if err != nil {
		t.Fatal("find:", err)
	}

	// Disconnect and stop
	client.Disconnect(ctx)
	proxyCancel()
	time.Sleep(100 * time.Millisecond)

	// Verify logs
	logs := logBuf.String()
	t.Logf("proxy logs:\n%s", logs)

	if !strings.Contains(logs, "client authenticated") {
		t.Error("logs should contain 'client authenticated'")
	}
	if !strings.Contains(logs, "backend authenticated") {
		t.Error("logs should contain 'backend authenticated'")
	}
	if !strings.Contains(logs, "auth remapping complete") {
		t.Error("logs should contain 'auth remapping complete'")
	}
	if !strings.Contains(logs, "insert") {
		t.Error("logs should contain 'insert' command after auth")
	}

	// Portal contract fields must all have been populated.
	if gotReq.Username != proxyUser {
		t.Errorf("portal saw username=%q, want %q", gotReq.Username, proxyUser)
	}
	if gotReq.ProxyType != "mongo" {
		t.Errorf("portal saw proxy_type=%q, want mongo", gotReq.ProxyType)
	}
	if gotReq.BackendServer != backendAddr {
		t.Errorf("portal saw backend_server=%q, want %q", gotReq.BackendServer, backendAddr)
	}
	if gotReq.SourceIP == "" {
		t.Error("portal saw empty source_ip")
	}
}
