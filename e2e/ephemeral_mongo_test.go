//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go/modules/mongodb"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/babs/poc-proxies/portal"
)

// TestEphemeral_MongoE2E boots a real MongoDB 7, provisions a per-grant user
// via the ephemeral package, verifies authentication works, then revokes and
// asserts authentication now fails.
func TestEphemeral_MongoE2E(t *testing.T) {
	skipIfNoDocker(t)
	ctx := context.Background()

	const (
		dbaUser = "backendadmin"
		dbaPass = "backendSecret!"
		testDB  = "app"
	)

	ctr, err := mongodb.Run(ctx, "mongo:7",
		mongodb.WithUsername(dbaUser),
		mongodb.WithPassword(dbaPass),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ctr.Terminate(ctx) })

	host, _ := ctr.Host(ctx)
	port, _ := ctr.MappedPort(ctx, "27017/tcp")

	lookup := func(context.Context, string) (portal.EphemeralDBACredential, error) {
		return portal.EphemeralDBACredential{Username: dbaUser, Password: dbaPass}, nil
	}
	p := portal.NewMongoProvisioner(lookup)

	req := portal.EphemeralProvisionReq{
		BackendType: portal.EphemeralBackendMongo,
		BackendID:   "b-test", Host: host, Port: port.Int(),
		Database: testDB, Role: "readWrite", GrantID: "g-test",
	}
	acct, err := p.Provision(ctx, req)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}

	uri := fmt.Sprintf("mongodb://%s:%s@%s:%s/?authSource=%s",
		acct.Username, acct.Password, host, port.Port(), testDB)
	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	client, err := mongo.Connect(options.Client().ApplyURI(uri))
	if err != nil {
		t.Fatalf("connect as ephemeral: %v", err)
	}
	if err := client.Ping(pingCtx, nil); err != nil {
		_ = client.Disconnect(ctx)
		t.Fatalf("ephemeral user ping: %v", err)
	}
	// Role check: connectionStatus returns the current user's grants.
	result := client.Database("admin").RunCommand(pingCtx, bson.D{{Key: "connectionStatus", Value: 1}})
	if err := result.Err(); err != nil {
		_ = client.Disconnect(ctx)
		t.Fatalf("connectionStatus: %v", err)
	}
	_ = client.Disconnect(ctx)

	if err := p.Revoke(ctx, acct); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if err := p.Revoke(ctx, acct); err != nil {
		t.Errorf("re-revoke must be idempotent: %v", err)
	}

	deadCtx, dcancel := context.WithTimeout(ctx, 5*time.Second)
	defer dcancel()
	deadClient, err := mongo.Connect(options.Client().ApplyURI(uri))
	if err != nil {
		t.Fatalf("post-revoke connect: %v", err)
	}
	defer deadClient.Disconnect(context.Background())
	if err := deadClient.Ping(deadCtx, nil); err == nil {
		t.Error("expected auth failure after revoke")
	}
}
