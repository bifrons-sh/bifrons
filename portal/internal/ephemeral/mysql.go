package ephemeral

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	mysqldrv "github.com/go-sql-driver/mysql"
)

// MySQLExec mirrors PostgresExec for the MySQL path.
type MySQLExec interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	Close() error
}

// MySQLConnector opens an admin connection to the target MySQL instance.
type MySQLConnector func(ctx context.Context, host string, port int, database string, dba DBACredential) (MySQLExec, error)

// DefaultMySQLConnector uses go-sql-driver/mysql to open a short-lived admin
// conn.
func DefaultMySQLConnector(ctx context.Context, host string, port int, database string, dba DBACredential) (MySQLExec, error) {
	cfg := mysqldrv.NewConfig()
	cfg.User = dba.Username
	cfg.Passwd = dba.Password
	cfg.Net = "tcp"
	cfg.Addr = fmt.Sprintf("%s:%d", host, port)
	cfg.DBName = database
	cfg.ParseTime = true
	// Bound the handshake + every read/write so a wedged master fails fast
	// rather than pinning the worker (see connectTimeout). DialTimeout caps the
	// initial connect; Read/WriteTimeout cap subsequent round-trips — safe to
	// set because Provision/Revoke issue only short DDL, no long-running queries.
	cfg.Timeout = connectTimeout * time.Second
	cfg.ReadTimeout = connectTimeout * time.Second
	cfg.WriteTimeout = connectTimeout * time.Second
	// Security: encrypt the DBA credential on the portal->MySQL path by
	// default. The driver ships TLS OFF, so a forgotten `?tls=true` would send
	// admin creds in cleartext. "true" requires the server to present a cert
	// the host trusts (full verification). PORTAL_MYSQL_TLS=false opts out for
	// local-dev compose where the backend has no TLS endpoint — but the opt-out
	// only takes effect behind the PORTAL_ALLOW_INSECURE_DBA_TLS gate.
	if mysqlTLSEnabled(cfg.Addr) {
		cfg.TLSConfig = "true"
	}
	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		return nil, fmt.Errorf("open mysql admin conn: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(30 * time.Second)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping mysql admin conn: %w", err)
	}
	return db, nil
}

// mysqlTLSEnabled reports whether to enable full-verification TLS. TLS stays on
// (the secure default) unless PORTAL_MYSQL_TLS=false AND the insecure-TLS gate
// is set. A bare PORTAL_MYSQL_TLS=false without the gate is ignored — we keep
// TLS on and Warn — so disabling cert verification on the master cred is always
// a deliberate two-step. Either way the disable path emits an auditable Warn.
func mysqlTLSEnabled(host string) bool {
	if envBoolDefault("PORTAL_MYSQL_TLS", true) {
		return true
	}
	if !insecureDBATLSAllowed() {
		warnInsecureDBATLS(string(BackendMySQL), host, "PORTAL_MYSQL_TLS", "false",
			"override ignored: set PORTAL_ALLOW_INSECURE_DBA_TLS=true to take effect")
		return true
	}
	warnInsecureDBATLS(string(BackendMySQL), host, "PORTAL_MYSQL_TLS", "false",
		"explicit opt-in via PORTAL_ALLOW_INSECURE_DBA_TLS")
	return false
}

// MySQLProvisioner creates grants-bound MySQL users. The SQL shape is:
//
//	CREATE USER '<user>'@'%' IDENTIFIED BY '<pw>' PASSWORD EXPIRE INTERVAL <n> DAY
//	GRANT <role> TO '<user>'@'%'
//
// The "role" here is a MySQL 8+ pre-defined role — the portal never creates
// roles itself, it just binds a transient user to one.
type MySQLProvisioner struct {
	lookup    DBALookup
	connector MySQLConnector
}

// NewMySQLProvisioner wires a MySQL driver. nil connector defaults to the
// go-sql-driver/mysql impl.
func NewMySQLProvisioner(lookup DBALookup, c MySQLConnector) *MySQLProvisioner {
	if c == nil {
		c = DefaultMySQLConnector
	}
	return &MySQLProvisioner{lookup: lookup, connector: c}
}

// Provision creates a fresh backend user.
func (p *MySQLProvisioner) Provision(ctx context.Context, req ProvisionRequest) (ProvisionedAccount, error) {
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

	// PASSWORD EXPIRE INTERVAL is COARSE and is NOT a hard expiry. Unlike
	// Postgres VALID UNTIL (which locks the role at a precise timestamp), this
	// only prompts a password CHANGE at the next authentication once the whole-
	// day interval elapses: the account stays usable until then, an already-open
	// session is unaffected, and there is no backend-side hard deadline. So
	// MySQL ephemeral users have no real backend cleanup — the portal's Revoke +
	// orphan sweeper are the only prompt teardown; this interval is a coarse,
	// best-effort backstop. The unit is whole days and we round UP, so any
	// sub-day TTL becomes 1 (also satisfying MySQL's required positive integer).
	days := int(math.Ceil(req.TTL.Hours() / 24))
	if days < 1 {
		days = 1
	}

	if idempotent {
		// Deterministic-cred path (spec §8.4): CREATE USER IF NOT EXISTS no-ops
		// when a crashed worker already created the user, then ALTER USER always
		// (re)sets the password so the DB matches the outbox on a lease-takeover.
		// CREATE alone can't set the password idempotently — IF NOT EXISTS skips
		// the whole statement (and its IDENTIFIED BY) when the user is present.
		createStmt := fmt.Sprintf(
			`CREATE USER IF NOT EXISTS %s@%s IDENTIFIED BY %s PASSWORD EXPIRE INTERVAL %d DAY`,
			mysqlQuoteIdent(user), mysqlQuoteLiteral("%"), mysqlQuoteLiteral(pw), days,
		)
		if _, err := conn.ExecContext(ctx, createStmt); err != nil {
			return ProvisionedAccount{}, fmt.Errorf("mysql create user: %w", err)
		}
		alterStmt := fmt.Sprintf(
			`ALTER USER %s@%s IDENTIFIED BY %s PASSWORD EXPIRE INTERVAL %d DAY`,
			mysqlQuoteIdent(user), mysqlQuoteLiteral("%"), mysqlQuoteLiteral(pw), days,
		)
		if _, err := conn.ExecContext(ctx, alterStmt); err != nil {
			return ProvisionedAccount{}, fmt.Errorf("mysql alter user: %w", err)
		}
	} else {
		createStmt := fmt.Sprintf(
			`CREATE USER %s@%s IDENTIFIED BY %s PASSWORD EXPIRE INTERVAL %d DAY`,
			mysqlQuoteIdent(user), mysqlQuoteLiteral("%"), mysqlQuoteLiteral(pw), days,
		)
		if _, err := conn.ExecContext(ctx, createStmt); err != nil {
			return ProvisionedAccount{}, fmt.Errorf("mysql create user: %w", err)
		}
	}

	grantStmt := fmt.Sprintf(
		`GRANT %s TO %s@%s`,
		mysqlQuoteIdent(string(req.Role)),
		mysqlQuoteIdent(user), mysqlQuoteLiteral("%"),
	)
	if _, err := conn.ExecContext(ctx, grantStmt); err != nil {
		// Best-effort cleanup — roll back the user if the GRANT fails. If
		// this rollback also fails we surface the GRANT error, which is the
		// useful one for operators.
		drop := fmt.Sprintf(`DROP USER %s@%s`, mysqlQuoteIdent(user), mysqlQuoteLiteral("%"))
		_, _ = conn.ExecContext(ctx, drop)
		return ProvisionedAccount{}, fmt.Errorf("mysql grant role: %w", err)
	}

	// Activate the role on login — MySQL 8 roles are inert until either the
	// client issues SET ROLE or the user has a default role. We make the
	// grant's role the default so downstream tooling doesn't have to care.
	defaultStmt := fmt.Sprintf(
		`SET DEFAULT ROLE %s TO %s@%s`,
		mysqlQuoteIdent(string(req.Role)),
		mysqlQuoteIdent(user), mysqlQuoteLiteral("%"),
	)
	if _, err := conn.ExecContext(ctx, defaultStmt); err != nil {
		drop := fmt.Sprintf(`DROP USER %s@%s`, mysqlQuoteIdent(user), mysqlQuoteLiteral("%"))
		_, _ = conn.ExecContext(ctx, drop)
		return ProvisionedAccount{}, fmt.Errorf("mysql set default role: %w", err)
	}

	return ProvisionedAccount{
		Username:    user,
		Password:    pw,
		BackendID:   req.BackendID,
		BackendType: BackendMySQL,
		Host:        req.Host,
		Port:        req.Port,
		Database:    req.Database,
		GrantID:     req.GrantID,
		CreatedAt:   time.Now().UTC(),
	}, nil
}

// Revoke drops the user. Idempotent: MySQL error 1396 (OP_CANT_DROP_USER)
// means the user is already gone; we treat it as success.
func (p *MySQLProvisioner) Revoke(ctx context.Context, acct ProvisionedAccount) error {
	dba, err := p.lookup(ctx, acct.BackendID)
	if err != nil {
		return err
	}
	conn, err := p.connector(ctx, acct.Host, acct.Port, acct.Database, dba)
	if err != nil {
		return err
	}
	defer conn.Close()

	drop := fmt.Sprintf(`DROP USER %s@%s`, mysqlQuoteIdent(acct.Username), mysqlQuoteLiteral("%"))
	if _, err := conn.ExecContext(ctx, drop); err != nil && !isMySQLMissingUser(err) {
		return fmt.Errorf("mysql drop user: %w", err)
	}
	return nil
}

// isMySQLMissingUser returns true for MySQL error 1396 — "Operation DROP USER
// failed for ..." when the user doesn't exist.
func isMySQLMissingUser(err error) bool {
	var my *mysqldrv.MySQLError
	if !errors.As(err, &my) {
		return false
	}
	return my.Number == 1396
}

// mysqlQuoteIdent backtick-quotes a user/role identifier. Local generator
// enforces hex-only names, so escaping is belt-and-braces.
func mysqlQuoteIdent(s string) string {
	return "`" + strings.ReplaceAll(s, "`", "``") + "`"
}

// mysqlQuoteLiteral single-quotes a literal with backslash+quote escaping.
// Good enough for hex passwords and the fixed '%' host spec.
func mysqlQuoteLiteral(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "'", `\'`)
	return "'" + s + "'"
}
