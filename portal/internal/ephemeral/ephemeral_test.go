package ephemeral

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/babs/poc-proxies/portal/internal/domain"
)

// deterministicRNG returns a reader that yields a repeating byte pattern so
// newUsername / newPassword produce predictable output in assertions.
type deterministicRNG struct{ seed byte }

func (r *deterministicRNG) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = r.seed
	}
	return len(p), nil
}

// recordingPGExec captures every ExecContext call so tests can assert the
// exact SQL shape emitted by the provisioner.
type recordingPGExec struct {
	stmts []string
	fail  error
}

func (r *recordingPGExec) ExecContext(_ context.Context, q string, _ ...any) (sql.Result, error) {
	r.stmts = append(r.stmts, q)
	if r.fail != nil {
		return nil, r.fail
	}
	return nil, nil
}

func (r *recordingPGExec) Close() error { return nil }

func stubLookup(u, p string, err error) DBALookup {
	return func(context.Context, string) (DBACredential, error) {
		if err != nil {
			return DBACredential{}, err
		}
		return DBACredential{Username: u, Password: p}, nil
	}
}

func TestNewUsername_Deterministic(t *testing.T) {
	SetUsernameRNG(&deterministicRNG{seed: 0xAB})
	t.Cleanup(func() { SetUsernameRNG(nil) })
	got, err := newUsername()
	if err != nil {
		t.Fatalf("newUsername: %v", err)
	}
	want := "portal_grant_abababababababab"
	if got != want {
		t.Errorf("got %q want %q", got, want)
	}
}

func TestNewPassword_Length(t *testing.T) {
	SetUsernameRNG(bytes.NewReader(bytes.Repeat([]byte{0xCD}, 64)))
	t.Cleanup(func() { SetUsernameRNG(nil) })
	pw, err := newPassword()
	if err != nil {
		t.Fatalf("newPassword: %v", err)
	}
	if len(pw) != 64 {
		t.Errorf("pw length %d, want 64", len(pw))
	}
	for _, c := range pw {
		if !strings.ContainsRune("0123456789abcdef", c) {
			t.Errorf("non-hex char in password: %q", c)
			break
		}
	}
}

func TestPostgresProvisioner_Provision_SQLShape(t *testing.T) {
	SetUsernameRNG(&deterministicRNG{seed: 0x11})
	t.Cleanup(func() { SetUsernameRNG(nil) })

	rec := &recordingPGExec{}
	c := func(context.Context, string, int, string, DBACredential) (PostgresExec, error) {
		return rec, nil
	}
	p := NewPostgresProvisioner(stubLookup("dba", "dbapw", nil), c)
	acct, err := p.Provision(context.Background(), ProvisionRequest{
		BackendType: BackendPostgres,
		BackendID:   "b-1",
		Host:        "h", Port: 5432, Database: "orders",
		Role: domain.RoleApp, GrantID: "g-1",
		TTL: 30 * time.Minute,
	})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if acct.Username != "portal_grant_1111111111111111" {
		t.Errorf("username=%q", acct.Username)
	}
	if acct.BackendType != BackendPostgres {
		t.Errorf("backendType=%q", acct.BackendType)
	}
	if len(rec.stmts) != 1 {
		t.Fatalf("stmts=%d want 1: %v", len(rec.stmts), rec.stmts)
	}
	stmt := rec.stmts[0]
	// Sanity-check: identifier double-quoted, password in single quotes, role
	// present, VALID UNTIL literal there.
	checks := []string{
		`CREATE ROLE "portal_grant_1111111111111111"`,
		`LOGIN PASSWORD '`,
		`VALID UNTIL '`,
		`IN ROLE "app"`,
	}
	for _, want := range checks {
		if !strings.Contains(stmt, want) {
			t.Errorf("stmt missing %q:\n%s", want, stmt)
		}
	}
}

func TestPostgresProvisioner_Revoke_Idempotent(t *testing.T) {
	pgMissing := newPgUndefinedRole()
	rec := &recordingPGExec{fail: pgMissing}
	c := func(context.Context, string, int, string, DBACredential) (PostgresExec, error) {
		return rec, nil
	}
	p := NewPostgresProvisioner(stubLookup("dba", "dbapw", nil), c)
	err := p.Revoke(context.Background(), ProvisionedAccount{
		Username: "portal_grant_dead", BackendID: "b-1",
		BackendType: BackendPostgres, Host: "h", Port: 5432,
	})
	if err != nil {
		t.Errorf("expected nil on 42704, got %v", err)
	}
	// Both DROP OWNED and DROP ROLE are issued before the first error is
	// surfaced; because we use isPGUndefinedRole both bail with nil, so we
	// see both statements in the recorder.
	if len(rec.stmts) != 2 {
		t.Errorf("want 2 stmts, got %d: %v", len(rec.stmts), rec.stmts)
	}
}

func TestPostgresProvisioner_Revoke_NoDBASkipsSilently(t *testing.T) {
	p := NewPostgresProvisioner(stubLookup("", "", ErrNoDBACredential), nil)
	err := p.Revoke(context.Background(), ProvisionedAccount{Username: "u", BackendID: "b"})
	if !errors.Is(err, ErrNoDBACredential) {
		t.Errorf("want ErrNoDBACredential, got %v", err)
	}
}

// recordingMySQLExec mirrors the pg recorder for MySQL assertions.
type recordingMySQLExec struct {
	stmts []string
	fail  error
}

func (r *recordingMySQLExec) ExecContext(_ context.Context, q string, _ ...any) (sql.Result, error) {
	r.stmts = append(r.stmts, q)
	if r.fail != nil {
		return nil, r.fail
	}
	return nil, nil
}

func (r *recordingMySQLExec) Close() error { return nil }

func TestMySQLProvisioner_Provision_SQLShape(t *testing.T) {
	SetUsernameRNG(&deterministicRNG{seed: 0x22})
	t.Cleanup(func() { SetUsernameRNG(nil) })

	rec := &recordingMySQLExec{}
	c := func(context.Context, string, int, string, DBACredential) (MySQLExec, error) {
		return rec, nil
	}
	p := NewMySQLProvisioner(stubLookup("dba", "pw", nil), c)
	_, err := p.Provision(context.Background(), ProvisionRequest{
		BackendType: BackendMySQL,
		BackendID:   "b-1", Host: "h", Port: 3306,
		Role: domain.RoleApp, GrantID: "g-1",
		TTL: 48 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if len(rec.stmts) != 3 {
		t.Fatalf("want 3 stmts, got %d: %v", len(rec.stmts), rec.stmts)
	}
	create := rec.stmts[0]
	if !strings.Contains(create, "CREATE USER `portal_grant_2222222222222222`@'%'") {
		t.Errorf("bad CREATE shape: %s", create)
	}
	if !strings.Contains(create, "PASSWORD EXPIRE INTERVAL 2 DAY") {
		t.Errorf("want 2-day interval, got: %s", create)
	}
	grant := rec.stmts[1]
	if !strings.Contains(grant, "GRANT `app` TO `portal_grant_2222222222222222`@'%'") {
		t.Errorf("bad GRANT shape: %s", grant)
	}
	defaultRole := rec.stmts[2]
	if !strings.Contains(defaultRole, "SET DEFAULT ROLE `app` TO `portal_grant_2222222222222222`@'%'") {
		t.Errorf("bad DEFAULT ROLE shape: %s", defaultRole)
	}
}

func TestMySQLProvisioner_TTLRoundUp(t *testing.T) {
	SetUsernameRNG(&deterministicRNG{seed: 0x33})
	t.Cleanup(func() { SetUsernameRNG(nil) })

	rec := &recordingMySQLExec{}
	c := func(context.Context, string, int, string, DBACredential) (MySQLExec, error) {
		return rec, nil
	}
	p := NewMySQLProvisioner(stubLookup("dba", "pw", nil), c)
	_, err := p.Provision(context.Background(), ProvisionRequest{
		BackendType: BackendMySQL, Host: "h", Port: 3306,
		Role: domain.RoleApp, TTL: 30 * time.Minute,
	})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if !strings.Contains(rec.stmts[0], "INTERVAL 1 DAY") {
		t.Errorf("sub-day TTL should round up to 1 DAY, got: %s", rec.stmts[0])
	}
}

// recordingMongoCommander captures the bson.D the provisioner sends.
type recordingMongoCommander struct {
	cmds []bson.D
	fail error
}

func (r *recordingMongoCommander) RunCommand(ctx context.Context, cmd any, _ ...options.Lister[options.RunCmdOptions]) *mongo.SingleResult {
	d, _ := cmd.(bson.D)
	r.cmds = append(r.cmds, d)
	if r.fail != nil {
		return mongo.NewSingleResultFromDocument(bson.D{}, r.fail, nil)
	}
	return mongo.NewSingleResultFromDocument(bson.D{{Key: "ok", Value: 1}}, nil, nil)
}

func (r *recordingMongoCommander) Close(context.Context) error { return nil }

func TestMongoProvisioner_Provision_CommandShape(t *testing.T) {
	SetUsernameRNG(&deterministicRNG{seed: 0x44})
	t.Cleanup(func() { SetUsernameRNG(nil) })

	rec := &recordingMongoCommander{}
	c := func(context.Context, string, int, string, DBACredential) (MongoCommander, error) {
		return rec, nil
	}
	p := NewMongoProvisioner(stubLookup("dba", "pw", nil), c)
	_, err := p.Provision(context.Background(), ProvisionRequest{
		BackendType: BackendMongo, BackendID: "b-1", Host: "h", Port: 27017,
		Database: "orders", Role: domain.RoleApp, GrantID: "g-1",
	})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if len(rec.cmds) != 1 {
		t.Fatalf("want 1 cmd, got %d", len(rec.cmds))
	}
	cmd := rec.cmds[0]
	gotKey := cmd[0].Key
	if gotKey != "createUser" {
		t.Errorf("first key = %q, want createUser", gotKey)
	}
	// The username lives at [0].Value — value is the username.
	if got := cmd[0].Value.(string); got != "portal_grant_4444444444444444" {
		t.Errorf("createUser value = %q", got)
	}
	// Roles is a bson.A; assert role name.
	roles := cmd[2].Value.(bson.A)
	if len(roles) != 1 {
		t.Fatalf("roles = %v", roles)
	}
	r := roles[0].(bson.D)
	if r[0].Value != "app" {
		t.Errorf("role[0] = %v", r[0])
	}
	if r[1].Value != "orders" {
		t.Errorf("db[1] = %v", r[1])
	}
}

func TestManager_Metrics_ProvisionSuccess(t *testing.T) {
	m := NewMetrics()
	mgr := NewManager(map[BackendType]Provisioner{
		BackendPostgres: &fakeProv{},
	}, m, nil)
	_, err := mgr.Provision(context.Background(), ProvisionRequest{BackendType: BackendPostgres})
	if err != nil {
		t.Fatal(err)
	}
	prov, _, _, _ := m.Snapshot()
	if prov != 1 {
		t.Errorf("provisioned=%d", prov)
	}
}

func TestManager_Metrics_RevokeFailureCounted(t *testing.T) {
	m := NewMetrics()
	mgr := NewManager(map[BackendType]Provisioner{
		BackendMySQL: &fakeProv{revokeErr: errors.New("boom")},
	}, m, nil)
	err := mgr.Revoke(context.Background(), BackendMySQL, ProvisionedAccount{})
	if err == nil {
		t.Fatal("expected error")
	}
	_, _, revFail, _ := m.Snapshot()
	if revFail != 1 {
		t.Errorf("revoke_failed=%d", revFail)
	}
}

func TestMapBackendType(t *testing.T) {
	cases := map[domain.ProxyType]BackendType{
		domain.ProxyPostgres: BackendPostgres,
		domain.ProxyMySQL:    BackendMySQL,
		domain.ProxyMongo:    BackendMongo,
		"unknown":            "",
	}
	for in, want := range cases {
		if got := MapBackendType(in); got != want {
			t.Errorf("MapBackendType(%q)=%q want %q", in, got, want)
		}
	}
}

// fakeProv is a minimal Provisioner for Manager tests.
type fakeProv struct {
	provErr   error
	revokeErr error
}

func (f *fakeProv) Provision(context.Context, ProvisionRequest) (ProvisionedAccount, error) {
	return ProvisionedAccount{Username: "u", Password: "p"}, f.provErr
}
func (f *fakeProv) Revoke(context.Context, ProvisionedAccount) error { return f.revokeErr }

// ensureReadError asserts io.EOF-style short reads don't crash newUsername.
func TestNewUsername_RNGError(t *testing.T) {
	SetUsernameRNG(iotest.ErrReader(fmt.Errorf("boom")))
	t.Cleanup(func() { SetUsernameRNG(nil) })
	if _, err := newUsername(); err == nil {
		t.Fatal("expected error")
	}
}

// iotest.ErrReader isn't imported elsewhere in the portal; inline the trivial
// helper to avoid a dep on testing/iotest for one symbol.
var iotest = struct {
	ErrReader func(error) io.Reader
}{
	ErrReader: func(e error) io.Reader { return errReader{e} },
}

type errReader struct{ e error }

func (r errReader) Read([]byte) (int, error) { return 0, r.e }
