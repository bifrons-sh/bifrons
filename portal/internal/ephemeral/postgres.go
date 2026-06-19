package ephemeral

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// PostgresExec is the minimal execution surface a Postgres provisioner needs.
// Satisfied by *sql.DB and *sql.Conn; abstracted so unit tests can assert the
// exact SQL emitted without round-tripping a real server.
type PostgresExec interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	Close() error
}

// PostgresConnector opens a new admin connection for a given backend.
// Concrete implementations carry whatever state is needed (driver, TLS
// config); the test connector records calls instead of opening a real DB.
type PostgresConnector func(ctx context.Context, host string, port int, database string, dba DBACredential) (PostgresExec, error)

// DefaultPostgresConnector opens a pgx-backed *sql.DB against the target
// backend. Uses the `pgx` driver already registered by the portal's postgres
// store package (no extra init needed in cmd/portal).
//
// Connections are short-lived: each Provision / Revoke call gets its own
// handle so we don't keep a DBA-privileged pool warm between grants.
func DefaultPostgresConnector(ctx context.Context, host string, port int, database string, dba DBACredential) (PostgresExec, error) {
	if database == "" {
		database = "postgres"
	}
	// Security: the DBA credential is the most privileged secret in the system
	// and travels the portal->DB path on every Provision/Revoke. Default to
	// `verify-full` so the connection is encrypted AND the server cert is
	// validated against the hostname (no MITM, no silent cleartext downgrade
	// the way `prefer` allows). Operators can relax it via PORTAL_PG_SSLMODE
	// for local-dev compose (e.g. `disable` / `prefer`) where there's no PKI —
	// but a non-verifying value is gated behind PORTAL_ALLOW_INSECURE_DBA_TLS.
	sslmode := pgSSLMode(os.Getenv("PORTAL_PG_SSLMODE"), host)
	// connect_timeout bounds the libpq handshake so a wedged master fails fast
	// (see connectTimeout). PingContext below is also ctx-bounded — the caller
	// passes a deadline-carrying context — so both the TCP/auth handshake and
	// the round-trip probe are capped.
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s&connect_timeout=%d",
		escapeUserinfo(dba.Username, userinfoReserved), escapeUserinfo(dba.Password, userinfoReserved),
		host, port, database, sslmode, connectTimeout)
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open pg admin conn: %w", err)
	}
	// Invariant: MaxOpenConns(1) pins every ExecContext on this handle to the
	// SAME physical connection. Revoke relies on this to make its
	// BEGIN/.../COMMIT span one session — see Revoke for why we frame the tx
	// with explicit SQL rather than *sql.Tx (the PostgresExec abstraction the
	// test connector implements has no Begin). Do not raise this above 1.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(30 * time.Second)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping pg admin conn: %w", err)
	}
	return db, nil
}

// pgNonVerifyingSSLModes are the libpq sslmode values that do NOT validate the
// server certificate against the hostname: `disable` (no TLS at all), `allow` /
// `prefer` (opportunistic, silently downgrades to cleartext), and `require`
// (encrypts but skips cert+hostname checks → MITM-able). `verify-ca` /
// `verify-full` are the only verifying modes.
var pgNonVerifyingSSLModes = map[string]struct{}{
	"disable": {}, "allow": {}, "prefer": {}, "require": {},
}

// pgSSLMode resolves the effective sslmode from the operator override. Empty
// keeps the secure `verify-full` default. A verifying override passes through.
// A NON-verifying override is honoured only when PORTAL_ALLOW_INSECURE_DBA_TLS
// is set — and either way emits an auditable Warn: one for the honoured opt-out
// (so a relaxed prod connection can't hide), one for the ignored override (so
// an operator who expected it to take effect notices the gate).
func pgSSLMode(override, host string) string {
	const secure = "verify-full"
	if override == "" {
		return secure
	}
	if _, nonVerifying := pgNonVerifyingSSLModes[override]; !nonVerifying {
		return override
	}
	if !insecureDBATLSAllowed() {
		warnInsecureDBATLS(string(BackendPostgres), host, "PORTAL_PG_SSLMODE", override,
			"override ignored: set PORTAL_ALLOW_INSECURE_DBA_TLS=true to take effect")
		return secure
	}
	warnInsecureDBATLS(string(BackendPostgres), host, "PORTAL_PG_SSLMODE", override,
		"explicit opt-in via PORTAL_ALLOW_INSECURE_DBA_TLS")
	return override
}

// PostgresProvisioner creates LOGIN roles scoped to the grant's role and TTL.
// DBA creds are resolved per call via the DBALookup so the handler never
// caches them, and so operators can rotate DBA passwords hot.
type PostgresProvisioner struct {
	lookup    DBALookup
	connector PostgresConnector
}

// NewPostgresProvisioner wires a Postgres driver. Passing a nil connector
// defaults to DefaultPostgresConnector.
func NewPostgresProvisioner(lookup DBALookup, c PostgresConnector) *PostgresProvisioner {
	if c == nil {
		c = DefaultPostgresConnector
	}
	return &PostgresProvisioner{lookup: lookup, connector: c}
}

// Provision creates a LOGIN role "portal_grant_<hex>" that inherits from the
// grant's Role (e.g. `app`, `dba`) so all privileges come from a pre-existing
// backend role. We issue:
//
//	CREATE ROLE <user> LOGIN INHERIT PASSWORD '<pw>' VALID UNTIL '<ts>' IN ROLE <role>
//
// VALID UNTIL gives us a hard backend-side deadline even if the portal never
// revokes — defence in depth against a crashed portal that never reaches the
// Revoke path.
func (p *PostgresProvisioner) Provision(ctx context.Context, req ProvisionRequest) (ProvisionedAccount, error) {
	dba, err := p.lookup(ctx, req.BackendID)
	if err != nil {
		return ProvisionedAccount{}, err
	}
	conn, err := p.connector(ctx, req.Host, req.Port, req.Database, dba)
	if err != nil {
		return ProvisionedAccount{}, err
	}
	defer conn.Close()

	user, pw, idempotent, err := req.resolveCreds()
	if err != nil {
		return ProvisionedAccount{}, err
	}

	// Identifiers aren't parametrizable in Postgres DDL, and role names are
	// generated locally (hex only), so quoting is sufficient. The password
	// literal goes through single-quote escaping — belt and braces, since
	// hex output can't produce a quote today.
	validUntil := time.Now().UTC().Add(req.TTL).Format(time.RFC3339)
	if req.TTL <= 0 {
		// "infinity" is a postgres sentinel — no backend-side expiry, the
		// portal's Revoke path is the only way out. Acceptable when the
		// caller has set ExpiresAt=nil on the grant.
		validUntil = "infinity"
	}

	// INHERIT is stated explicitly rather than relying on the cluster default:
	// the temp user must automatically wield the parent role's privileges with
	// no SET ROLE. A backend whose default flipped to NOINHERIT (PG16+) would
	// otherwise hand out a login with zero privileges.
	stmts := pgProvisionStmts(user, pw, validUntil, string(req.Role), idempotent)
	for _, stmt := range stmts {
		if _, err := conn.ExecContext(ctx, stmt); err != nil {
			return ProvisionedAccount{}, fmt.Errorf("pg create role: %w", err)
		}
	}
	return ProvisionedAccount{
		Username:    user,
		Password:    pw,
		BackendID:   req.BackendID,
		BackendType: BackendPostgres,
		Host:        req.Host,
		Port:        req.Port,
		Database:    req.Database,
		GrantID:     req.GrantID,
		CreatedAt:   time.Now().UTC(),
	}, nil
}

// pgProvisionStmts returns the DDL to provision a LOGIN role.
//
// Legacy path (idempotent=false, random creds): a single CREATE ROLE — kept
// byte-for-byte so the existing SQL-shape assertions and the all-or-nothing
// behaviour are unchanged.
//
// Idempotent path (idempotent=true, deterministic creds from the worker): a
// DO-block guarded CREATE ROLE that no-ops when the role already exists
// (catching duplicate_object), followed by an ALTER ROLE that ALWAYS
// (re)applies the password + VALID UNTIL. This is what makes a lease-takeover
// converge (spec §8.4): worker B re-runs the same intent, the CREATE is a
// no-op, and the ALTER canonicalises whatever password a crashed worker A
// left so the DB and the outbox agree.
func pgProvisionStmts(user, pw, validUntil, role string, idempotent bool) []string {
	qUser := pgQuoteIdent(user)
	qRole := pgQuoteIdent(role)
	qPw := pgQuoteLiteral(pw)
	qValid := pgQuoteLiteral(validUntil)
	if !idempotent {
		return []string{fmt.Sprintf(
			`CREATE ROLE %s LOGIN INHERIT PASSWORD %s VALID UNTIL %s IN ROLE %s`,
			qUser, qPw, qValid, qRole,
		)}
	}
	// The DO-block body references the role name as a string literal (for the
	// IF NOT EXISTS guard) and as an identifier (for CREATE ROLE). The literal
	// uses the role-name string, quoted; the identifier uses qUser. duplicate_
	// object is the SQLSTATE 42710 a racing CREATE ROLE would raise — caught so
	// two workers creating concurrently both succeed.
	createGuarded := fmt.Sprintf(
		`DO $$ BEGIN `+
			`IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = %s) THEN `+
			`CREATE ROLE %s LOGIN INHERIT IN ROLE %s; `+
			`END IF; `+
			`EXCEPTION WHEN duplicate_object THEN NULL; `+
			`END $$`,
		pgQuoteLiteral(user), qUser, qRole,
	)
	// ALTER always runs: canonicalises password + expiry regardless of whether
	// this worker or a previous one created the role.
	alter := fmt.Sprintf(
		`ALTER ROLE %s WITH LOGIN PASSWORD %s VALID UNTIL %s`,
		qUser, qPw, qValid,
	)
	return []string{createGuarded, alter}
}

// Revoke drops the role. Idempotent: if the role is already gone (42704) we
// return nil so a double-fire from handler + sweeper doesn't alert.
//
// REASSIGN OWNED runs first so any tables/sequences/views the transient user
// created get re-parented to the DBA (rather than blocking the DROP). The
// three DDLs run in a single transaction so a crash / dropped conn partway
// through won't leave the ephemeral user with some objects reassigned and
// others not. Idempotent on SQLSTATE 42704 (role already gone).
func (p *PostgresProvisioner) Revoke(ctx context.Context, acct ProvisionedAccount) error {
	dba, err := p.lookup(ctx, acct.BackendID)
	if err != nil {
		return err
	}
	conn, err := p.connector(ctx, acct.Host, acct.Port, acct.Database, dba)
	if err != nil {
		return err
	}
	defer conn.Close()

	user := pgQuoteIdent(acct.Username)
	dbaRef := pgQuoteIdent(dba.Username)
	stmts := []string{
		fmt.Sprintf(`REASSIGN OWNED BY %s TO %s`, user, dbaRef),
		fmt.Sprintf(`DROP OWNED BY %s`, user),
		fmt.Sprintf(`DROP ROLE %s`, user),
	}

	// Production path: when the connector handed us a real *sql.DB, use a
	// proper BeginTx-bound *sql.Tx. This pins all three DDLs to one pooled
	// connection at the database/sql layer (not just by convention), so the
	// atomicity guarantee survives any future change to pool sizing.
	if db, ok := conn.(*sql.DB); ok {
		return revokePGTx(ctx, db, stmts)
	}

	// Fallback for connectors that only expose the minimal PostgresExec
	// surface (the unit-test recorder). Atomicity holds because the connector
	// is opened with MaxOpenConns(1) — see DefaultPostgresConnector — so every
	// ExecContext here lands on the same session. The explicit BEGIN/COMMIT
	// frames the tx without needing a Begin method on the interface.
	if _, err := conn.ExecContext(ctx, "BEGIN"); err != nil {
		return fmt.Errorf("pg revoke: begin: %w", err)
	}
	for _, stmt := range stmts {
		if _, err := conn.ExecContext(ctx, stmt); err != nil {
			_, _ = conn.ExecContext(ctx, "ROLLBACK")
			if isPGUndefinedRole(err) {
				// Role already gone — Revoke is idempotent, swallow and exit.
				return nil
			}
			return fmt.Errorf("pg revoke (%s): %w", firstWord(stmt), err)
		}
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		_, _ = conn.ExecContext(ctx, "ROLLBACK")
		return fmt.Errorf("pg revoke: commit: %w", err)
	}
	return nil
}

// revokePGTx runs the revoke DDLs inside a real *sql.Tx. Rollback-on-error is
// implicit via the deferred Rollback (a no-op after Commit). A 42704 on any
// statement means the role is already gone — Revoke is idempotent, so we roll
// back the (empty) tx and report success.
func revokePGTx(ctx context.Context, db *sql.DB, stmts []string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("pg revoke: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, stmt := range stmts {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			if isPGUndefinedRole(err) {
				return nil
			}
			return fmt.Errorf("pg revoke (%s): %w", firstWord(stmt), err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("pg revoke: commit: %w", err)
	}
	return nil
}

// firstWord returns the leading whitespace-delimited token. Used to label
// pg revoke errors with the offending statement family (REASSIGN/DROP)
// without echoing the full DDL — quoted identifier embeds the user name.
func firstWord(s string) string {
	for i, c := range s {
		if c == ' ' || c == '\t' {
			return s[:i]
		}
	}
	return s
}

// isPGUndefinedRole catches SQLSTATE 42704 (undefined object). Makes Revoke
// idempotent: if the account is already gone we report success.
func isPGUndefinedRole(err error) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return false
	}
	return pgErr.Code == "42704"
}

// pgQuoteIdent returns a double-quoted identifier, doubling any embedded
// quotes. Local generator enforces [a-z0-9_]+ names so this is belt-and-
// braces only.
func pgQuoteIdent(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

// pgQuoteLiteral single-quotes a string literal with embedded quote escaping.
// Used for password + VALID UNTIL timestamp — both locally generated.
func pgQuoteLiteral(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}
