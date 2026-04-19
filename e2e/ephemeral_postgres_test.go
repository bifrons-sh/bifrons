//go:build e2e

package e2e

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/babs/poc-proxies/portal"
)

// TestEphemeral_PostgresE2E boots a real postgres, provisions a per-grant
// user via the ephemeral package, asserts the user can auth + inherits the
// target role, then revokes and verifies login now fails.
//
// The test talks to the provisioner directly — the goal is to prove the
// package's SQL works against a live Postgres, not re-exercise the handler
// path (covered by unit tests in portal/internal/api).
func TestEphemeral_PostgresE2E(t *testing.T) {
	skipIfNoDocker(t)
	ctx := context.Background()

	const (
		dbaUser  = "postgres"
		dbaPass  = "dbapw!"
		appRole  = "app_ro"
		testDB   = "app"
		grantTTL = 15 * time.Minute
	)

	ctr, err := postgres.Run(ctx, "postgres:16-alpine",
		postgres.WithDatabase(testDB),
		postgres.WithUsername(dbaUser),
		postgres.WithPassword(dbaPass),
		postgres.BasicWaitStrategies(),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ctr.Terminate(ctx) })

	host, _ := ctr.Host(ctx)
	port, _ := ctr.MappedPort(ctx, "5432/tcp")

	dsn := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
		dbaUser, dbaPass, host, port.Port(), testDB)
	rootDB, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer rootDB.Close()
	if err := rootDB.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := rootDB.ExecContext(ctx,
		fmt.Sprintf(`CREATE ROLE %s NOLOGIN`, appRole)); err != nil {
		t.Fatal(err)
	}

	lookup := func(context.Context, string) (portal.EphemeralDBACredential, error) {
		return portal.EphemeralDBACredential{Username: dbaUser, Password: dbaPass}, nil
	}
	p := portal.NewPostgresProvisioner(lookup)

	req := portal.EphemeralProvisionReq{
		BackendType: portal.EphemeralBackendPostgres,
		BackendID:   "b-test", Host: host, Port: port.Int(),
		Database: testDB, Role: "app_ro", GrantID: "g-test",
		TTL: grantTTL,
	}
	acct, err := p.Provision(ctx, req)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	t.Logf("provisioned user %s", acct.Username)

	userDSN := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
		acct.Username, acct.Password, host, port.Port(), testDB)
	userDB, err := sql.Open("pgx", userDSN)
	if err != nil {
		t.Fatal(err)
	}
	if err := userDB.PingContext(ctx); err != nil {
		t.Fatalf("user ping: %v", err)
	}
	var inRole bool
	err = userDB.QueryRowContext(ctx,
		`SELECT pg_has_role(current_user, $1, 'MEMBER')`, appRole,
	).Scan(&inRole)
	userDB.Close()
	if err != nil {
		t.Fatalf("role check: %v", err)
	}
	if !inRole {
		t.Errorf("ephemeral user is not a member of %s", appRole)
	}

	if err := p.Revoke(ctx, acct); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if err := p.Revoke(ctx, acct); err != nil {
		t.Errorf("re-revoke must be idempotent: %v", err)
	}

	bogusDB, err := sql.Open("pgx", userDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer bogusDB.Close()
	if err := bogusDB.PingContext(ctx); err == nil {
		t.Error("expected login failure after revoke")
	}
}

// TestEphemeral_PostgresE2E_RevokeReassignOwned verifies the REASSIGN OWNED +
// DROP OWNED + DROP ROLE sequence so the revoke succeeds even when the
// ephemeral user has created objects (tables, sequences, …). Without
// REASSIGN, DROP ROLE would 2BP01 because of the dangling dependency.
func TestEphemeral_PostgresE2E_RevokeReassignOwned(t *testing.T) {
	skipIfNoDocker(t)
	ctx := context.Background()

	const (
		dbaUser = "postgres"
		dbaPass = "dbapw!"
		appRole = "app_rw"
		testDB  = "app"
	)

	ctr, err := postgres.Run(ctx, "postgres:16-alpine",
		postgres.WithDatabase(testDB),
		postgres.WithUsername(dbaUser),
		postgres.WithPassword(dbaPass),
		postgres.BasicWaitStrategies(),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ctr.Terminate(ctx) })

	host, _ := ctr.Host(ctx)
	port, _ := ctr.MappedPort(ctx, "5432/tcp")

	dsn := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
		dbaUser, dbaPass, host, port.Port(), testDB)
	rootDB, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer rootDB.Close()
	if err := rootDB.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	// Grant the inherited role full schema-create privilege so the ephemeral
	// user can plant a table.
	if _, err := rootDB.ExecContext(ctx,
		fmt.Sprintf(`CREATE ROLE %s NOLOGIN; GRANT CREATE ON SCHEMA public TO %s`, appRole, appRole)); err != nil {
		t.Fatal(err)
	}

	lookup := func(context.Context, string) (portal.EphemeralDBACredential, error) {
		return portal.EphemeralDBACredential{Username: dbaUser, Password: dbaPass}, nil
	}
	p := portal.NewPostgresProvisioner(lookup)

	acct, err := p.Provision(ctx, portal.EphemeralProvisionReq{
		BackendType: portal.EphemeralBackendPostgres,
		BackendID:   "b-test", Host: host, Port: port.Int(),
		Database: testDB, Role: appRole, GrantID: "g-reassign",
		TTL: 15 * time.Minute,
	})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}

	// Ephemeral user creates a table — under the old DROP-only path this
	// would wedge the revoke with "role cannot be dropped because some
	// objects depend on it" (2BP01).
	userDSN := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
		acct.Username, acct.Password, host, port.Port(), testDB)
	userDB, err := sql.Open("pgx", userDSN)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := userDB.ExecContext(ctx, `CREATE TABLE t_revoke (id INT)`); err != nil {
		userDB.Close()
		t.Fatalf("CREATE TABLE as ephemeral user: %v", err)
	}
	userDB.Close()

	if err := p.Revoke(ctx, acct); err != nil {
		t.Fatalf("Revoke after CREATE TABLE: %v (should REASSIGN OWNED then DROP)", err)
	}
}

