package ephemeral

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
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
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=prefer",
		pgEscapeUserinfo(dba.Username), pgEscapeUserinfo(dba.Password), host, port, database)
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open pg admin conn: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(30 * time.Second)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping pg admin conn: %w", err)
	}
	return db, nil
}

// pgEscapeUserinfo URL-escapes the reserved userinfo characters so an
// operator using a DBA password with `@ : /` can still form a valid DSN.
// Keeping it inline avoids dragging net/url in for a tiny subset of rules.
func pgEscapeUserinfo(s string) string {
	const reserved = "@:/?# "
	b := strings.Builder{}
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if strings.IndexByte(reserved, c) >= 0 {
			fmt.Fprintf(&b, "%%%02X", c)
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
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
//	CREATE ROLE <user> LOGIN PASSWORD '<pw>' VALID UNTIL '<ts>' IN ROLE <role>
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

	user, err := newUsername()
	if err != nil {
		return ProvisionedAccount{}, err
	}
	pw, err := newPassword()
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

	stmt := fmt.Sprintf(
		`CREATE ROLE %s LOGIN PASSWORD %s VALID UNTIL %s IN ROLE %s`,
		pgQuoteIdent(user),
		pgQuoteLiteral(pw),
		pgQuoteLiteral(validUntil),
		pgQuoteIdent(string(req.Role)),
	)
	if _, err := conn.ExecContext(ctx, stmt); err != nil {
		return ProvisionedAccount{}, fmt.Errorf("pg create role: %w", err)
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
	// Group into a single tx via explicit BEGIN/COMMIT so we don't need to
	// widen the PostgresExec interface (keeps test connectors simple). If any
	// DDL fails mid-sequence, ROLLBACK undoes the partial work; the caller
	// can retry the whole sequence idempotently.
	if _, err := conn.ExecContext(ctx, "BEGIN"); err != nil {
		if isPGUndefinedRole(err) {
			return nil // role already gone — nothing to revoke.
		}
		return fmt.Errorf("pg revoke: begin: %w", err)
	}
	stmts := []string{
		fmt.Sprintf(`REASSIGN OWNED BY %s TO %s`, user, dbaRef),
		fmt.Sprintf(`DROP OWNED BY %s`, user),
		fmt.Sprintf(`DROP ROLE %s`, user),
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
