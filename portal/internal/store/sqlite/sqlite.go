// Package sqlite implements store.Store against an embedded SQLite database
// using the pure-Go modernc.org/sqlite driver (no cgo). It is the default
// persistent backend for small / single-node portal deployments.
package sqlite

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/babs/poc-proxies/portal/internal/domain"
	"github.com/babs/poc-proxies/portal/internal/store"

	_ "modernc.org/sqlite" // registers the "sqlite" driver (pure-Go, CGO-free)
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Driver registration: importing this package plugs the "sqlite" scheme into
// store.NewFromURL. The DSN accepted by Open is a raw sqlite DSN — the factory
// supplies pragmas for file-backed URLs, and ":memory:" for in-memory URLs.
func init() {
	store.Register("sqlite", func(dsn string) (store.Store, error) {
		if dsn == "" {
			return nil, fmt.Errorf("sqlite: empty DSN")
		}
		if dsn == ":memory:" {
			return Open(":memory:")
		}
		// `sqlite:///path.db` → dsn is `/path.db`. Add durability pragmas:
		//   foreign_keys=1    → enforce FKs (sqlite default is OFF)
		//   journal_mode=wal  → concurrent readers during writes
		//   busy_timeout=5000 → wait up to 5s on "database is locked"
		return Open(fmt.Sprintf("file:%s?_pragma=foreign_keys(1)&_pragma=journal_mode(wal)&_pragma=busy_timeout(5000)", dsn))
	})
}

// Store is the SQLite-backed implementation of store.Store.
type Store struct {
	db *sql.DB
}

// Open opens a SQLite database at the given DSN (a driver-level DSN, not a
// URL). Typical callers route through store.NewFromURL.
func Open(dsn string) (*Store, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	// A single connection avoids "database is locked" on :memory: (each
	// connection in modernc.org/sqlite gets a fresh in-memory DB) and keeps
	// things simple for small deployments. For high-throughput file-backed
	// stores with WAL enabled, lift this cap.
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping sqlite: %w", err)
	}
	s := &Store{db: db}
	if err := s.migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Close releases the underlying database handle.
func (s *Store) Close() error { return s.db.Close() }

// DB exposes the underlying sql.DB for advanced tests. Avoid in handlers.
func (s *Store) DB() *sql.DB { return s.db }

// migrate applies every embedded migration that hasn't been recorded yet. We
// use a hand-rolled runner rather than pull in goose/golang-migrate — the
// project keeps deps lean, the migration surface here is tiny, and we get the
// exact semantics we want (single-transaction-per-migration, deterministic
// ordering from sorted filenames).
func (s *Store) migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		id         INTEGER PRIMARY KEY,
		name       TEXT NOT NULL UNIQUE,
		applied_at TEXT NOT NULL
	)`); err != nil {
		return fmt.Errorf("bootstrap schema_migrations: %w", err)
	}

	applied := map[string]bool{}
	rows, err := s.db.QueryContext(ctx, `SELECT name FROM schema_migrations`)
	if err != nil {
		return fmt.Errorf("read schema_migrations: %w", err)
	}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			rows.Close()
			return err
		}
		applied[n] = true
	}
	rows.Close()

	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("read migrations: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	for _, name := range names {
		if applied[name] {
			continue
		}
		body, err := migrationsFS.ReadFile("migrations/" + name)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", name, err)
		}
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("begin tx for %s: %w", name, err)
		}
		if _, err := tx.ExecContext(ctx, string(body)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("apply %s: %w", name, err)
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO schema_migrations(name, applied_at) VALUES(?, ?)`,
			name, fmtTime(time.Now()),
		); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("record %s: %w", name, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit %s: %w", name, err)
		}
	}
	return nil
}

// --- helpers ---

// fmtTime emits a fixed-width RFC3339-nano variant with all 9 fractional
// digits. RFC3339Nano strips trailing zeros, which breaks lexicographic
// ordering used by `timestamp < ?` comparisons in sqlite (TEXT columns) when
// a timestamp with zero nanos (emitted as "...Z") sorts *after* one with
// non-zero nanos ("....123Z"), because '.' < 'Z'. Padding to constant width
// keeps lex ordering aligned with chronological ordering.
const sqliteTimeLayout = "2006-01-02T15:04:05.000000000Z07:00"

func fmtTime(t time.Time) string {
	return t.UTC().Format(sqliteTimeLayout)
}

// parseTime accepts both the padded and unpadded forms so rows written before
// the padding fix still read back cleanly.
func parseTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	return time.Parse(time.RFC3339Nano, s)
}

func nullableTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return fmtTime(*t)
}

func scanNullableTime(ns sql.NullString) (*time.Time, error) {
	if !ns.Valid || ns.String == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339Nano, ns.String)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// isUniqueErr detects a sqlite UNIQUE constraint violation. modernc.org/sqlite
// wraps errors as a *sqlite.Error which we can't reach without importing that
// driver's internal types; string-match is fragile but adequate given the
// driver's stable error text.
func isUniqueErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "UNIQUE constraint failed") ||
		strings.Contains(msg, "constraint failed: UNIQUE")
}

// --- users ---

func (s *Store) CreateUser(ctx context.Context, u domain.User) error {
	// NULL-encode empty ExternalID so the partial UNIQUE index doesn't treat
	// multiple non-OIDC users as duplicates of the empty string.
	var extID any
	if u.ExternalID != "" {
		extID = u.ExternalID
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO users(id, username, password_hash, display_name, email, external_id, is_admin, status, created_at, updated_at)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		u.ID, u.Username, u.PasswordHash, u.DisplayName, u.Email, extID, boolToInt(u.IsAdmin), u.Status,
		fmtTime(u.CreatedAt), fmtTime(u.UpdatedAt),
	)
	if isUniqueErr(err) {
		return store.ErrConflict
	}
	if err != nil {
		return fmt.Errorf("insert user: %w", err)
	}
	return nil
}

func (s *Store) GetUser(ctx context.Context, id string) (domain.User, error) {
	return s.getUser(ctx, `WHERE id = ?`, id)
}

func (s *Store) GetUserByUsername(ctx context.Context, username string) (domain.User, error) {
	return s.getUser(ctx, `WHERE username = ?`, username)
}

func (s *Store) GetUserByExternalID(ctx context.Context, externalID string) (domain.User, error) {
	return s.getUser(ctx, `WHERE external_id = ?`, externalID)
}

func (s *Store) getUser(ctx context.Context, where string, arg any) (domain.User, error) {
	var u domain.User
	var isAdmin int
	var extID sql.NullString
	var createdAt, updatedAt string
	err := s.db.QueryRowContext(ctx, `
		SELECT id, username, password_hash, display_name, email, external_id, is_admin, status, created_at, updated_at
		FROM users `+where, arg,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.DisplayName, &u.Email, &extID, &isAdmin, &u.Status, &createdAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.User{}, store.ErrNotFound
	}
	if err != nil {
		return domain.User{}, err
	}
	u.IsAdmin = isAdmin != 0
	if extID.Valid {
		u.ExternalID = extID.String
	}
	if u.CreatedAt, err = parseTime(createdAt); err != nil {
		return domain.User{}, err
	}
	if u.UpdatedAt, err = parseTime(updatedAt); err != nil {
		return domain.User{}, err
	}
	return u, nil
}

// --- backends ---

func (s *Store) CreateBackend(ctx context.Context, b domain.Backend) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO backends(id, name, type, host, port, databases, created_at, updated_at)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?)`,
		b.ID, b.Name, string(b.Type), b.Host, b.Port,
		strings.Join(b.Databases, ","),
		fmtTime(b.CreatedAt), fmtTime(b.UpdatedAt),
	)
	if isUniqueErr(err) {
		return store.ErrConflict
	}
	if err != nil {
		return fmt.Errorf("insert backend: %w", err)
	}
	return nil
}

func (s *Store) GetBackendByAddress(ctx context.Context, addr string) (domain.Backend, error) {
	host, port, err := splitAddr(addr)
	if err != nil {
		return domain.Backend{}, store.ErrNotFound
	}
	return s.scanBackendRow(s.db.QueryRowContext(ctx, `
		SELECT id, name, type, host, port, databases, created_at, updated_at
		FROM backends WHERE host = ? AND port = ?`, host, port))
}

func (s *Store) ListBackends(ctx context.Context) ([]domain.Backend, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, type, host, port, databases, created_at, updated_at
		FROM backends ORDER BY name ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []domain.Backend{}
	for rows.Next() {
		b, err := scanBackend(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

type rowScanner interface {
	Scan(dest ...any) error
}

func (s *Store) scanBackendRow(row *sql.Row) (domain.Backend, error) {
	b, err := scanBackend(row)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Backend{}, store.ErrNotFound
	}
	return b, err
}

func scanBackend(r rowScanner) (domain.Backend, error) {
	var b domain.Backend
	var bType, databases, createdAt, updatedAt string
	if err := r.Scan(&b.ID, &b.Name, &bType, &b.Host, &b.Port, &databases, &createdAt, &updatedAt); err != nil {
		return domain.Backend{}, err
	}
	b.Type = domain.ProxyType(bType)
	if databases != "" {
		b.Databases = strings.Split(databases, ",")
	}
	var err error
	if b.CreatedAt, err = parseTime(createdAt); err != nil {
		return domain.Backend{}, err
	}
	if b.UpdatedAt, err = parseTime(updatedAt); err != nil {
		return domain.Backend{}, err
	}
	return b, nil
}

func splitAddr(addr string) (string, int, error) {
	i := strings.LastIndex(addr, ":")
	if i <= 0 || i == len(addr)-1 {
		return "", 0, fmt.Errorf("bad address %q", addr)
	}
	host := addr[:i]
	var port int
	if _, err := fmt.Sscanf(addr[i+1:], "%d", &port); err != nil {
		return "", 0, fmt.Errorf("bad port in %q: %w", addr, err)
	}
	return host, port, nil
}

// --- backend accounts ---

func (s *Store) UpsertBackendAccount(ctx context.Context, a domain.BackendAccount) error {
	// SQLite's ON CONFLICT needs the conflict target to match a UNIQUE index.
	// We have UNIQUE(backend_id, role) — upsert on that pair.
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO backend_accounts(id, backend_id, role, username, password, created_at, updated_at)
		VALUES(?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(backend_id, role) DO UPDATE SET
			username   = excluded.username,
			password   = excluded.password,
			updated_at = excluded.updated_at`,
		a.ID, a.BackendID, string(a.Role), a.Username, a.Password, //nolint:staticcheck // legacy plaintext column; secrets layer prefers PasswordRef.
		fmtTime(a.CreatedAt), fmtTime(a.UpdatedAt),
	)
	if err != nil {
		return fmt.Errorf("upsert backend_account: %w", err)
	}
	return nil
}

func (s *Store) GetBackendAccount(ctx context.Context, backendID string, role domain.Role) (domain.BackendAccount, error) {
	var a domain.BackendAccount
	var roleStr, createdAt, updatedAt string
	err := s.db.QueryRowContext(ctx, `
		SELECT id, backend_id, role, username, password, created_at, updated_at
		FROM backend_accounts WHERE backend_id = ? AND role = ?`,
		backendID, string(role),
	).Scan(&a.ID, &a.BackendID, &roleStr, &a.Username, &a.Password, &createdAt, &updatedAt) //nolint:staticcheck // legacy plaintext column.
	if errors.Is(err, sql.ErrNoRows) {
		return domain.BackendAccount{}, store.ErrNotFound
	}
	if err != nil {
		return domain.BackendAccount{}, err
	}
	a.Role = domain.Role(roleStr)
	if a.CreatedAt, err = parseTime(createdAt); err != nil {
		return domain.BackendAccount{}, err
	}
	if a.UpdatedAt, err = parseTime(updatedAt); err != nil {
		return domain.BackendAccount{}, err
	}
	return a, nil
}

// --- grants ---

func (s *Store) CreateGrant(ctx context.Context, g domain.Grant) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO grants(id, user_id, backend_id, database, role, status, reason, portal_password,
			approved_by, requested_at, approved_at, expires_at, revoked_at,
			connection_ttl_seconds, created_at, updated_at)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		g.ID, g.UserID, g.BackendID, g.Database, string(g.Role), string(g.Status),
		g.Reason, g.PortalPassword, g.ApprovedBy,
		fmtTime(g.RequestedAt), nullableTime(g.ApprovedAt),
		nullableTime(g.ExpiresAt), nullableTime(g.RevokedAt),
		g.ConnectionTTLSec, fmtTime(g.CreatedAt), fmtTime(g.UpdatedAt),
	)
	if isUniqueErr(err) {
		return store.ErrConflict
	}
	if err != nil {
		return fmt.Errorf("insert grant: %w", err)
	}
	return nil
}

func (s *Store) GetGrant(ctx context.Context, id string) (domain.Grant, error) {
	row := s.db.QueryRowContext(ctx, grantSelectSQL+` WHERE id = ?`, id)
	g, err := scanGrant(row)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Grant{}, store.ErrNotFound
	}
	return g, err
}

func (s *Store) UpdateGrant(ctx context.Context, g domain.Grant) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE grants SET
			user_id = ?, backend_id = ?, database = ?, role = ?, status = ?, reason = ?,
			portal_password = ?, approved_by = ?, requested_at = ?, approved_at = ?,
			expires_at = ?, revoked_at = ?, connection_ttl_seconds = ?, updated_at = ?
		WHERE id = ?`,
		g.UserID, g.BackendID, g.Database, string(g.Role), string(g.Status), g.Reason,
		g.PortalPassword, g.ApprovedBy, fmtTime(g.RequestedAt), nullableTime(g.ApprovedAt),
		nullableTime(g.ExpiresAt), nullableTime(g.RevokedAt), g.ConnectionTTLSec,
		fmtTime(g.UpdatedAt), g.ID,
	)
	if err != nil {
		return fmt.Errorf("update grant: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

// ExpireStaleGrants flips APPROVED grants past ExpiresAt to EXPIRED in one
// statement. Skips rows that already carry revoked_at — protects against
// reclassifying a manually-set (APPROVED, revoked_at!=NULL) corner case
// and clobbering the revoke signal.
func (s *Store) ExpireStaleGrants(ctx context.Context, now time.Time) (int, error) {
	res, err := s.db.ExecContext(ctx, `
		UPDATE grants SET status = ?, updated_at = ?
		WHERE status = ? AND expires_at IS NOT NULL AND expires_at < ?
		  AND revoked_at IS NULL`,
		string(domain.GrantExpired), fmtTime(now), string(domain.GrantApproved), fmtTime(now),
	)
	if err != nil {
		return 0, fmt.Errorf("expire grants: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// UpdateGrantIfStatus is the CAS variant: only writes when status still
// matches expect. Distinguishes ErrNotFound (row gone) from ErrConflict
// (row present but status drifted, e.g. concurrent approve/deny race).
func (s *Store) UpdateGrantIfStatus(ctx context.Context, g domain.Grant, expect domain.GrantStatus) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE grants SET
			user_id = ?, backend_id = ?, database = ?, role = ?, status = ?, reason = ?,
			portal_password = ?, approved_by = ?, requested_at = ?, approved_at = ?,
			expires_at = ?, revoked_at = ?, connection_ttl_seconds = ?, updated_at = ?
		WHERE id = ? AND status = ?`,
		g.UserID, g.BackendID, g.Database, string(g.Role), string(g.Status), g.Reason,
		g.PortalPassword, g.ApprovedBy, fmtTime(g.RequestedAt), nullableTime(g.ApprovedAt),
		nullableTime(g.ExpiresAt), nullableTime(g.RevokedAt), g.ConnectionTTLSec,
		fmtTime(g.UpdatedAt), g.ID, string(expect),
	)
	if err != nil {
		return fmt.Errorf("update grant: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 1 {
		return nil
	}
	// Disambiguate ErrNotFound vs ErrConflict with a cheap existence check.
	var cur string
	qerr := s.db.QueryRowContext(ctx, `SELECT status FROM grants WHERE id = ?`, g.ID).Scan(&cur)
	if errors.Is(qerr, sql.ErrNoRows) {
		return store.ErrNotFound
	}
	if qerr != nil {
		return qerr
	}
	return store.ErrConflict
}

func (s *Store) ListGrants(ctx context.Context, f store.GrantFilter) ([]domain.Grant, error) {
	var (
		args    []any
		clauses []string
	)
	if f.UserID != "" {
		clauses = append(clauses, "user_id = ?")
		args = append(args, f.UserID)
	}
	if f.BackendID != "" {
		clauses = append(clauses, "backend_id = ?")
		args = append(args, f.BackendID)
	}
	if len(f.Statuses) > 0 {
		ph := make([]string, len(f.Statuses))
		for i, st := range f.Statuses {
			ph[i] = "?"
			args = append(args, string(st))
		}
		clauses = append(clauses, "status IN ("+strings.Join(ph, ",")+")")
	}
	q := grantSelectSQL
	if len(clauses) > 0 {
		q += " WHERE " + strings.Join(clauses, " AND ")
	}
	q += " ORDER BY created_at DESC"
	if f.Limit > 0 {
		q += fmt.Sprintf(" LIMIT %d", f.Limit)
	}
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []domain.Grant{}
	for rows.Next() {
		g, err := scanGrant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

const grantSelectSQL = `SELECT id, user_id, backend_id, database, role, status, reason, portal_password,
	approved_by, requested_at, approved_at, expires_at, revoked_at, connection_ttl_seconds,
	created_at, updated_at FROM grants`

func scanGrant(r rowScanner) (domain.Grant, error) {
	var (
		g                                               domain.Grant
		role, status                                    string
		requestedAt, createdAt, updatedAt               string
		approvedAt, expiresAt, revokedAt                sql.NullString
	)
	if err := r.Scan(&g.ID, &g.UserID, &g.BackendID, &g.Database, &role, &status, &g.Reason,
		&g.PortalPassword, &g.ApprovedBy, &requestedAt, &approvedAt, &expiresAt, &revokedAt,
		&g.ConnectionTTLSec, &createdAt, &updatedAt); err != nil {
		return domain.Grant{}, err
	}
	g.Role = domain.Role(role)
	g.Status = domain.GrantStatus(status)
	var err error
	if g.RequestedAt, err = parseTime(requestedAt); err != nil {
		return domain.Grant{}, err
	}
	if g.CreatedAt, err = parseTime(createdAt); err != nil {
		return domain.Grant{}, err
	}
	if g.UpdatedAt, err = parseTime(updatedAt); err != nil {
		return domain.Grant{}, err
	}
	if g.ApprovedAt, err = scanNullableTime(approvedAt); err != nil {
		return domain.Grant{}, err
	}
	if g.ExpiresAt, err = scanNullableTime(expiresAt); err != nil {
		return domain.Grant{}, err
	}
	if g.RevokedAt, err = scanNullableTime(revokedAt); err != nil {
		return domain.Grant{}, err
	}
	return g, nil
}

// --- audit ---

func (s *Store) AppendAudit(ctx context.Context, entries []domain.AuditEntry) error {
	if len(entries) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO audit(timestamp, grant_id, username, proxy_type, backend_server,
			database, query, truncated, source_ip, duration_ms, trace_id)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()
	for _, e := range entries {
		if _, err := stmt.ExecContext(ctx,
			fmtTime(e.Timestamp), e.GrantID, e.Username, string(e.ProxyType),
			e.BackendServer, e.Database, e.Query, boolToInt(e.Truncated),
			e.SourceIP, e.DurationMs, e.TraceID,
		); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) ListAudit(ctx context.Context, f store.AuditFilter) ([]domain.AuditEntry, error) {
	var (
		args    []any
		clauses []string
	)
	if f.GrantID != "" {
		clauses = append(clauses, "grant_id = ?")
		args = append(args, f.GrantID)
	}
	if f.Username != "" {
		clauses = append(clauses, "username = ?")
		args = append(args, f.Username)
	}
	q := `SELECT timestamp, grant_id, username, proxy_type, backend_server, database, query,
		truncated, source_ip, duration_ms, trace_id FROM audit`
	if len(clauses) > 0 {
		q += " WHERE " + strings.Join(clauses, " AND ")
	}
	q += " ORDER BY timestamp DESC, id DESC"
	if f.Limit > 0 {
		q += fmt.Sprintf(" LIMIT %d", f.Limit)
	}
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []domain.AuditEntry{}
	for rows.Next() {
		var (
			e         domain.AuditEntry
			ts, ptype string
			truncated int
		)
		if err := rows.Scan(&ts, &e.GrantID, &e.Username, &ptype, &e.BackendServer,
			&e.Database, &e.Query, &truncated, &e.SourceIP, &e.DurationMs, &e.TraceID); err != nil {
			return nil, err
		}
		e.Timestamp, err = parseTime(ts)
		if err != nil {
			return nil, err
		}
		e.ProxyType = domain.ProxyType(ptype)
		e.Truncated = truncated != 0
		out = append(out, e)
	}
	return out, rows.Err()
}

// PruneAudit applies the retention policy. Strategy:
//  1. Drop everything strictly older than cutoff in one statement.
//  2. If the remaining row count still exceeds the hard cap, drop the oldest
//     rows by id (AUTOINCREMENT makes id monotonic with insertion order, which
//     tracks wall-clock timestamps closely enough for a cap).
func (s *Store) PruneAudit(ctx context.Context, cutoff time.Time, maxEntries int) (int, int, error) {
	var pruned int
	res, err := s.db.ExecContext(ctx, `DELETE FROM audit WHERE timestamp < ?`, fmtTime(cutoff))
	if err != nil {
		return 0, 0, fmt.Errorf("prune audit by age: %w", err)
	}
	n, _ := res.RowsAffected()
	pruned += int(n)

	if maxEntries > 0 {
		var total int
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit`).Scan(&total); err != nil {
			return pruned, 0, fmt.Errorf("count audit: %w", err)
		}
		if total > maxEntries {
			// Find the id of the `maxEntries`-th newest row; delete everything
			// with a smaller id. This keeps the cap robust against clock skew
			// on the entry timestamps — id is monotonic, timestamp may not be.
			var cutID int64
			if err := s.db.QueryRowContext(ctx,
				`SELECT id FROM audit ORDER BY id DESC LIMIT 1 OFFSET ?`, maxEntries-1,
			).Scan(&cutID); err != nil {
				return pruned, total, fmt.Errorf("cap pivot: %w", err)
			}
			res, err := s.db.ExecContext(ctx, `DELETE FROM audit WHERE id < ?`, cutID)
			if err != nil {
				return pruned, total, fmt.Errorf("prune audit by cap: %w", err)
			}
			m, _ := res.RowsAffected()
			pruned += int(m)
		}
	}

	var remaining int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit`).Scan(&remaining); err != nil {
		return pruned, 0, fmt.Errorf("count remaining: %w", err)
	}
	return pruned, remaining, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
