//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go/modules/mongodb"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/babs/poc-proxies/internal/config"
	mongoproto "github.com/babs/poc-proxies/internal/protocol/mongo"
	"github.com/babs/poc-proxies/internal/proxy"
)

func TestMongoProxy(t *testing.T) {
	ctx := context.Background()

	// Start MongoDB container (no auth for simplicity)
	ctr, err := mongodb.Run(ctx, "mongo:7")
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

	// Start proxy
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	cfg := &config.Config{
		ListenAddr:  "127.0.0.1:0",
		BackendAddr: backendAddr,
	}
	handler := mongoproto.NewHandler(logger, nil)
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
	uri := fmt.Sprintf("mongodb://%s/?directConnection=true", proxyAddr)
	client, err := mongo.Connect(options.Client().ApplyURI(uri))
	if err != nil {
		t.Fatal("connect mongo:", err)
	}
	defer client.Disconnect(ctx)

	// Ping
	pingCtx, pingCancel := context.WithTimeout(ctx, 10*time.Second)
	defer pingCancel()
	if err := client.Ping(pingCtx, nil); err != nil {
		t.Fatal("ping:", err)
	}

	// Insert a document
	coll := client.Database("testdb").Collection("e2e_test")
	_, err = coll.InsertOne(ctx, bson.D{{Key: "marker", Value: "hello_from_e2e_test"}})
	if err != nil {
		t.Fatal("insert:", err)
	}

	// Find the document
	var doc bson.D
	err = coll.FindOne(ctx, bson.D{{Key: "marker", Value: "hello_from_e2e_test"}}).Decode(&doc)
	if err != nil {
		t.Fatal("find:", err)
	}

	// Close and stop proxy to flush logs
	client.Disconnect(ctx)
	proxyCancel()
	time.Sleep(100 * time.Millisecond)

	// Verify logs contain commands
	logs := logBuf.String()
	t.Logf("proxy logs:\n%s", logs)

	if !strings.Contains(logs, `"msg":"command"`) {
		t.Error("logs should contain command events")
	}
	if !strings.Contains(logs, "insert") {
		t.Error("logs should contain 'insert' command")
	}
	if !strings.Contains(logs, "find") {
		t.Error("logs should contain 'find' command")
	}
	if !strings.Contains(logs, `"msg":"connect"`) {
		t.Error("logs should contain connect event")
	}
}
