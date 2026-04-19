//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"

	"github.com/babs/poc-proxies/internal/config"
	mongoproto "github.com/babs/poc-proxies/internal/protocol/mongo"
	"github.com/babs/poc-proxies/internal/proxy"
)

// TestMongoReplicaSet_DirectConnectionOnly stands up a real 3-node mongo:7
// replica set on a user-defined docker network, fronts the primary with the
// mongo proxy, and verifies the Phase 4.3a documented behaviour:
//
//   - `directConnection=true&replicaSet=rs0` via the proxy works for writes
//     and primary reads.
//   - `readPreference=secondary` fails, because the proxy only fronts the
//     primary and does NOT rewrite the `hosts`/`primary`/`me` fields in the
//     replica-set hello response (see specs/phase-4-protocol-gaps.md §4.3b —
//     full topology proxying is planned, not implemented).
func TestMongoReplicaSet_DirectConnectionOnly(t *testing.T) {
	skipIfNoDocker(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Shared user-defined network so the three replica-set members can reach
	// each other by the hostnames embedded in rs.initiate(). Without this the
	// replica set never comes up — members fail to dial each other.
	net, err := network.New(ctx)
	if err != nil {
		t.Skipf("create docker network: %v", err)
	}
	t.Cleanup(func() {
		cctx, cc := context.WithTimeout(context.Background(), 30*time.Second)
		defer cc()
		_ = net.Remove(cctx)
	})
	netName := net.Name

	const rsName = "rs0"
	hostnames := []string{"mongo1", "mongo2", "mongo3"}
	containers := make([]testcontainers.Container, 0, len(hostnames))

	for _, host := range hostnames {
		req := testcontainers.ContainerRequest{
			Image:        "mongo:7",
			ExposedPorts: []string{"27017/tcp"},
			Cmd:          []string{"--replSet", rsName, "--bind_ip_all", "--port", "27017"},
			Networks:     []string{netName},
			NetworkAliases: map[string][]string{
				netName: {host},
			},
			Hostname:   host,
			WaitingFor: wait.ForLog("Waiting for connections").WithStartupTimeout(90 * time.Second),
		}
		c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
			ContainerRequest: req,
			Started:          true,
		})
		if err != nil {
			t.Skipf("start mongo container %s: %v", host, err)
		}
		t.Cleanup(func() {
			cctx, cc := context.WithTimeout(context.Background(), 30*time.Second)
			defer cc()
			_ = testcontainers.TerminateContainer(c, testcontainers.StopContext(cctx))
		})
		containers = append(containers, c)
	}

	// Initiate the replica set from mongo1. The config refers to members by
	// their network aliases so inter-node traffic flows over the user-defined
	// docker network, not through the host's mapped ports.
	initJS := fmt.Sprintf(
		`rs.initiate({_id:"%s",members:[{_id:0,host:"%s:27017"},{_id:1,host:"%s:27017"},{_id:2,host:"%s:27017"}]})`,
		rsName, hostnames[0], hostnames[1], hostnames[2],
	)
	if err := execMongosh(ctx, t, containers[0], initJS); err != nil {
		t.Fatalf("rs.initiate: %v", err)
	}

	// Poll until mongo1 self-reports as PRIMARY. Election normally settles in
	// a few seconds on a fresh 3-node RS; give it up to 60s on slow CI.
	if err := waitForPrimary(ctx, t, containers[0], 60*time.Second); err != nil {
		t.Fatalf("wait for primary: %v", err)
	}

	// Proxy points at mongo1's host-mapped port (the "primary" from the
	// test's vantage point). The other two members are unreachable from the
	// test host — only the proxy fronts a single member.
	primaryHost, err := containers[0].Host(ctx)
	if err != nil {
		t.Fatal(err)
	}
	primaryPort, err := containers[0].MappedPort(ctx, "27017/tcp")
	if err != nil {
		t.Fatal(err)
	}
	backendAddr := fmt.Sprintf("%s:%s", primaryHost, primaryPort.Port())

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfg := &config.Config{
		ListenAddr:          "127.0.0.1:0",
		BackendAddr:         backendAddr,
		HandshakeTimeout:    15 * time.Second,
		BackendDialTimeout:  5 * time.Second,
		ShutdownGracePeriod: 3 * time.Second,
	}
	handler := mongoproto.NewHandler(logger, nil)
	srv, err := proxy.New(cfg, handler, logger)
	if err != nil {
		t.Fatal(err)
	}
	proxyCtx, proxyCancel := context.WithCancel(ctx)
	defer proxyCancel()
	go srv.Serve(proxyCtx)
	proxyAddr := srv.Addr().String()
	t.Logf("proxy %s -> backend %s (rs primary)", proxyAddr, backendAddr)

	// --- Happy path: directConnection=true + replicaSet=rs0 ---
	// Phase 4.3a contract: this is the supported mode. The driver treats the
	// proxy address as the single topology member and does not try to dial
	// `mongo1`/`mongo2`/`mongo3` directly.
	primaryURI := fmt.Sprintf(
		"mongodb://%s/?directConnection=true&replicaSet=%s&serverSelectionTimeoutMS=10000",
		proxyAddr, rsName,
	)
	primaryClient, err := mongo.Connect(options.Client().ApplyURI(primaryURI))
	if err != nil {
		t.Fatalf("connect primary: %v", err)
	}
	defer primaryClient.Disconnect(ctx)

	coll := primaryClient.Database("testdb").Collection("rs_e2e")
	if _, err := coll.InsertOne(ctx, bson.D{{Key: "marker", Value: "rs_write_ok"}}); err != nil {
		t.Fatalf("insert via proxy (directConnection=true): %v", err)
	}
	var got bson.D
	if err := coll.FindOne(ctx, bson.D{{Key: "marker", Value: "rs_write_ok"}}).Decode(&got); err != nil {
		t.Fatalf("primary read via proxy: %v", err)
	}

	// --- Documented limitation: readPreference=secondary must NOT work ---
	// The proxy fronts only the primary; the `hello` response still advertises
	// `mongo2`/`mongo3` as the other members, which are unreachable from the
	// test host. A secondary-preferred read must therefore fail — either
	// because the driver can't reach the secondaries, or (with
	// directConnection=true) because it refuses to route a secondary read to
	// a primary-only topology view. Either failure mode confirms "full
	// topology proxying is not implemented" (spec §4.3b).
	secURI := fmt.Sprintf(
		"mongodb://%s/?replicaSet=%s&readPreference=secondary&serverSelectionTimeoutMS=5000&connectTimeoutMS=3000",
		proxyAddr, rsName,
	)
	secOpts := options.Client().
		ApplyURI(secURI).
		SetReadPreference(readpref.Secondary())
	secClient, err := mongo.Connect(secOpts)
	if err != nil {
		// Connect is lazy; surface via the read below.
		t.Logf("connect (secondary pref): %v", err)
	} else {
		defer secClient.Disconnect(ctx)
	}
	readCtx, readCancel := context.WithTimeout(ctx, 20*time.Second)
	defer readCancel()
	err = secClient.Database("testdb").Collection("rs_e2e").
		FindOne(readCtx, bson.D{{Key: "marker", Value: "rs_write_ok"}}).Err()
	if err == nil {
		t.Fatal("expected secondary-preferred read to fail (proxy only fronts primary); " +
			"this would mean topology proxying was implemented — update phase-4-protocol-gaps.md §4.3b")
	}
	t.Logf("secondary-pref read failed as expected (proxy fronts primary only): %v", err)
	msg := strings.ToLower(err.Error())
	// Any of: server selection timeout, no servers available, connection refused to mongo2/mongo3.
	// We don't pin a specific string — different driver versions phrase it
	// differently — but we confirm it's a *topology* failure, not e.g. an
	// auth error (which would mean a different bug).
	if strings.Contains(msg, "auth") {
		t.Fatalf("unexpected auth failure — test is broken, not demonstrating topology limit: %v", err)
	}
}

// execMongosh runs a JS snippet inside the given container via `mongosh --eval`.
// Returns a non-nil error on non-zero exit or unreadable stdout.
func execMongosh(ctx context.Context, t *testing.T, c testcontainers.Container, js string) error {
	t.Helper()
	// Retry: mongosh may not be listening immediately after "Waiting for
	// connections". 10 attempts x 2s covers slow CI.
	var lastErr error
	for i := 0; i < 10; i++ {
		code, reader, err := c.Exec(ctx, []string{"mongosh", "--quiet", "--eval", js})
		if err != nil {
			lastErr = err
		} else {
			out := ""
			if reader != nil {
				buf := make([]byte, 4096)
				n, _ := reader.Read(buf)
				out = string(buf[:n])
			}
			if code == 0 {
				return nil
			}
			lastErr = fmt.Errorf("exit %d: %s", code, out)
		}
		time.Sleep(2 * time.Second)
	}
	return lastErr
}

// waitForPrimary polls `rs.isMaster().ismaster` inside the container until it
// reports true or timeout expires.
func waitForPrimary(ctx context.Context, t *testing.T, c testcontainers.Container, timeout time.Duration) error {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		// `rs.isMaster().ismaster` prints "true" on the current primary.
		code, reader, err := c.Exec(ctx, []string{
			"mongosh", "--quiet", "--eval",
			"db.hello().isWritablePrimary ? 'PRIMARY' : 'NOT-YET'",
		})
		if err == nil && code == 0 && reader != nil {
			buf := make([]byte, 4096)
			n, _ := reader.Read(buf)
			if strings.Contains(string(buf[:n]), "PRIMARY") {
				return nil
			}
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("timed out after %s", timeout)
}
