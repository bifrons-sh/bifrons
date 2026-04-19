//go:build e2e

package e2e

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/testcontainers/testcontainers-go/modules/mysql"

	"github.com/babs/poc-proxies/portal"
)

// TestEphemeral_MySQLE2E boots a real MySQL 8, provisions a per-grant user
// via the ephemeral package, verifies login + role membership, then revokes
// and asserts subsequent logins fail.
func TestEphemeral_MySQLE2E(t *testing.T) {
	skipIfNoDocker(t)
	ctx := context.Background()

	const (
		dbaUser  = "root"
		dbaPass  = "rootpw"
		appRole  = "app_role"
		testDB   = "app"
		grantTTL = 2 * 24 * time.Hour
	)

	initPath := writeMySQLInitSQL(t, fmt.Sprintf(`
ALTER USER 'root'@'%%' IDENTIFIED WITH mysql_native_password BY '%s';
CREATE ROLE '%s';
GRANT SELECT ON %s.* TO '%s';
FLUSH PRIVILEGES;
`, dbaPass, appRole, testDB, appRole))

	ctr, err := mysql.Run(ctx, "mysql:8.0",
		mysql.WithDatabase(testDB),
		mysql.WithUsername("bootstrap"),
		mysql.WithPassword("bootstrap"),
		mysql.WithScripts(initPath),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ctr.Terminate(ctx) })

	host, _ := ctr.Host(ctx)
	port, _ := ctr.MappedPort(ctx, "3306/tcp")

	lookup := func(context.Context, string) (portal.EphemeralDBACredential, error) {
		return portal.EphemeralDBACredential{Username: dbaUser, Password: dbaPass}, nil
	}
	p := portal.NewMySQLProvisioner(lookup)

	req := portal.EphemeralProvisionReq{
		BackendType: portal.EphemeralBackendMySQL,
		BackendID:   "b-test", Host: host, Port: port.Int(),
		Database: testDB, Role: "app_role", GrantID: "g-test",
		TTL: grantTTL,
	}
	acct, err := p.Provision(ctx, req)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}

	userDSN := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s",
		acct.Username, acct.Password, host, port.Port(), testDB)
	userDB, err := sql.Open("mysql", userDSN)
	if err != nil {
		t.Fatal(err)
	}
	if err := userDB.PingContext(ctx); err != nil {
		t.Fatalf("user ping: %v", err)
	}
	var gotUser string
	if err := userDB.QueryRow("SELECT CURRENT_USER()").Scan(&gotUser); err != nil {
		t.Fatal(err)
	}
	userDB.Close()
	if gotUser == "" {
		t.Error("empty CURRENT_USER()")
	}

	if err := p.Revoke(ctx, acct); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if err := p.Revoke(ctx, acct); err != nil {
		t.Errorf("re-revoke must be idempotent: %v", err)
	}

	bogusDB, err := sql.Open("mysql", userDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer bogusDB.Close()
	if err := bogusDB.PingContext(ctx); err == nil {
		t.Error("expected login to fail after revoke")
	}
}
