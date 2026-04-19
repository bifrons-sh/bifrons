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

	user, err := newUsername()
	if err != nil {
		return ProvisionedAccount{}, err
	}
	pw, err := newPassword()
	if err != nil {
		return ProvisionedAccount{}, err
	}

	days := int(math.Ceil(req.TTL.Hours() / 24))
	if days < 1 {
		// MySQL requires a positive integer for PASSWORD EXPIRE INTERVAL.
		// Short TTLs (< 1 day) round up to 1 so we still get a backend-side
		// expiry, even if the portal's own ExpiresAt is sooner.
		days = 1
	}

	createStmt := fmt.Sprintf(
		`CREATE USER %s@%s IDENTIFIED BY %s PASSWORD EXPIRE INTERVAL %d DAY`,
		mysqlQuoteIdent(user), mysqlQuoteLiteral("%"), mysqlQuoteLiteral(pw), days,
	)
	if _, err := conn.ExecContext(ctx, createStmt); err != nil {
		return ProvisionedAccount{}, fmt.Errorf("mysql create user: %w", err)
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
