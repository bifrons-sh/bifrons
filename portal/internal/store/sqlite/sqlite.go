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
	"github.com/babs/poc-proxies/portal/internal/store/sqlbase"

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

// Store is the SQLite-backed implementation of store.Store. It embeds
// sqlbase.Common for the dialect-independent methods (Close, DB) and keeps its
// own db field — pointing at the same handle — for the many dialect-specific
// methods that bind ?-placeholders and TEXT-encoded timestamps.
type Store struct {
	sqlbase.Common
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
	s := &Store{Common: sqlbase.Common{DBHandle: db}, db: db}
	if err := s.migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// migrate applies every embedded migration that hasn't been recorded yet. We
// use a hand-rolled runner rather than pull in goose/golang-migrate — the
// project keeps deps lean, the migration surface here is tiny, and we get the
// exact semantics we want (single-transaction-per-migration, deterministic
// ordering from sorted filenames).
//
// Pre-deployment squash note: 0001_initial.sql was rewritten to fold what was
// previously 0002–0004 into the baseline schema. CREATE TABLE IF NOT EXISTS
// means a dev DB seeded against the older 0001 will silently keep its
// out-of-date users / grants tables. Drop the dev DB file (or migrate its
// schema_migrations row to look like a fresh install) before running this
// build against an old database.
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
	var validatorID any
	if u.ValidatorUserID != "" {
		validatorID = u.ValidatorUserID
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO users(id, username, password_hash, display_name, email, external_id, validator_user_id, is_operator, status, created_at, updated_at)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		u.ID, u.Username, u.PasswordHash, u.DisplayName, u.Email, extID, validatorID, boolToInt(u.IsOperator), u.Status,
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

// SetUserValidator persists the validator link. "" clears the FK. The caller is
// expected to have validated that validatorUserID exists; the FK does the
// enforcement at the DB level regardless.
func (s *Store) SetUserValidator(ctx context.Context, userID, validatorUserID string) error {
	var validatorID any
	if validatorUserID != "" {
		validatorID = validatorUserID
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE users SET validator_user_id = ?, updated_at = ? WHERE id = ?`,
		validatorID, fmtTime(time.Now()), userID,
	)
	if err != nil {
		return fmt.Errorf("update user validator: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return store.ErrNotFound
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
	var isOperator int
	var extID, mgrID sql.NullString
	var createdAt, updatedAt string
	err := s.db.QueryRowContext(ctx, `
		SELECT id, username, password_hash, display_name, email, external_id, validator_user_id, is_operator, status, created_at, updated_at
		FROM users `+where, arg,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.DisplayName, &u.Email, &extID, &mgrID, &isOperator, &u.Status, &createdAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.User{}, store.ErrNotFound
	}
	if err != nil {
		return domain.User{}, err
	}
	u.IsOperator = isOperator != 0
	if extID.Valid {
		u.ExternalID = extID.String
	}
	if mgrID.Valid {
		u.ValidatorUserID = mgrID.String
	}
	if u.CreatedAt, err = parseTime(createdAt); err != nil {
		return domain.User{}, err
	}
	if u.UpdatedAt, err = parseTime(updatedAt); err != nil {
		return domain.User{}, err
	}
	return u, nil
}

// UpdateUser reconciles the mutable scalar attributes. Identity columns
// (id, username, password_hash, validator_user_id, created_at) are left
// alone — validator changes go through SetUserValidator and username is the
// stable identity. CAS on u.UpdatedAt: concurrent patches race cleanly,
// loser gets ErrNotFound (same shape as a missing row). ExternalID
// collisions surface as ErrConflict.
func (s *Store) UpdateUser(ctx context.Context, u domain.User) error {
	var extID any
	if u.ExternalID != "" {
		extID = u.ExternalID
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE users SET
			display_name = ?,
			email        = ?,
			external_id  = ?,
			is_operator     = ?,
			status       = ?,
			updated_at   = ?
		WHERE id = ? AND updated_at = ?`,
		u.DisplayName, u.Email, extID, boolToInt(u.IsOperator), u.Status, fmtTime(time.Now()), u.ID, fmtTime(u.UpdatedAt),
	)
	if isUniqueErr(err) {
		return store.ErrConflict
	}
	if err != nil {
		return fmt.Errorf("update user: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

// UpdateUserDemote runs the same CAS update as UpdateUser, but inside a tx
// that first locks in the active-admin count. SQLite serialises writers per
// database, so a BEGIN IMMEDIATE here would be redundant — the implicit
// upgrade on the UPDATE step prevents two writers from both passing the count
// check. Returns ErrLastAdmin when demoting the only remaining admin.
func (s *Store) UpdateUserDemote(ctx context.Context, u domain.User) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin demote tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var curIsAdmin int
	var curStatus string
	if err := tx.QueryRowContext(ctx, `SELECT is_operator, status FROM users WHERE id = ?`, u.ID).Scan(&curIsAdmin, &curStatus); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return store.ErrNotFound
		}
		return fmt.Errorf("read is_operator: %w", err)
	}
	// Only enforce the guard when the row currently *counts* as an active
	// admin. Demoting a disabled admin doesn't reduce the active-admin tally,
	// so blocking that case would be a false positive.
	if curIsAdmin == 1 && curStatus == "active" && !u.IsOperator {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE is_operator = 1 AND status = 'active'`).Scan(&n); err != nil {
			return fmt.Errorf("count admins: %w", err)
		}
		if n <= 1 {
			return store.ErrLastAdmin
		}
	}
	var extID any
	if u.ExternalID != "" {
		extID = u.ExternalID
	}
	res, err := tx.ExecContext(ctx, `
		UPDATE users SET
			display_name = ?,
			email        = ?,
			external_id  = ?,
			is_operator     = ?,
			status       = ?,
			updated_at   = ?
		WHERE id = ? AND updated_at = ?`,
		u.DisplayName, u.Email, extID, boolToInt(u.IsOperator), u.Status, fmtTime(time.Now()), u.ID, fmtTime(u.UpdatedAt),
	)
	if isUniqueErr(err) {
		return store.ErrConflict
	}
	if err != nil {
		return fmt.Errorf("update user: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return store.ErrNotFound
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit demote tx: %w", err)
	}
	return nil
}

// CountAdmins counts active users with is_operator = 1.
func (s *Store) CountAdmins(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE is_operator = 1 AND status = 'active'`).Scan(&n)
	return n, err
}

// ListUsers returns every user, ordered by username.
func (s *Store) ListUsers(ctx context.Context) ([]domain.User, error) {
	return sqlbase.QueryList(ctx, s.db, `
		SELECT id, username, password_hash, display_name, email, external_id, validator_user_id, is_operator, status, created_at, updated_at
		FROM users ORDER BY username`, s.scanUserRow)
}

// --- groups ---

func (s *Store) UpsertGroup(ctx context.Context, g domain.Group) error {
	var extID any
	if g.ExternalID != "" {
		extID = g.ExternalID
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO groups(id, slug, display_name, external_id, created_at, updated_at)
		VALUES(?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			slug         = excluded.slug,
			display_name = excluded.display_name,
			external_id  = excluded.external_id,
			updated_at   = excluded.updated_at`,
		g.ID, g.Slug, g.DisplayName, extID, fmtTime(g.CreatedAt), fmtTime(g.UpdatedAt),
	)
	if isUniqueErr(err) {
		return store.ErrConflict
	}
	if err != nil {
		return fmt.Errorf("upsert group: %w", err)
	}
	return nil
}

func (s *Store) GetGroup(ctx context.Context, id string) (domain.Group, error) {
	return s.scanGroupRow(s.db.QueryRowContext(ctx,
		`SELECT id, slug, display_name, external_id, created_at, updated_at FROM groups WHERE id = ?`, id))
}

func (s *Store) GetGroupBySlug(ctx context.Context, slug string) (domain.Group, error) {
	return s.scanGroupRow(s.db.QueryRowContext(ctx,
		`SELECT id, slug, display_name, external_id, created_at, updated_at FROM groups WHERE slug = ?`, slug))
}

func (s *Store) ListGroups(ctx context.Context) ([]domain.Group, error) {
	return sqlbase.QueryList(ctx, s.db,
		`SELECT id, slug, display_name, external_id, created_at, updated_at FROM groups ORDER BY slug`, s.scanGroupRow)
}

func (s *Store) DeleteGroup(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM groups WHERE id = ?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (s *Store) scanGroupRow(r sqlbase.Scannable) (domain.Group, error) {
	var g domain.Group
	var extID sql.NullString
	var createdAt, updatedAt string
	err := r.Scan(&g.ID, &g.Slug, &g.DisplayName, &extID, &createdAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Group{}, store.ErrNotFound
	}
	if err != nil {
		return domain.Group{}, err
	}
	if extID.Valid {
		g.ExternalID = extID.String
	}
	if g.CreatedAt, err = parseTime(createdAt); err != nil {
		return domain.Group{}, err
	}
	if g.UpdatedAt, err = parseTime(updatedAt); err != nil {
		return domain.Group{}, err
	}
	return g, nil
}

// AddGroupMember is idempotent via ON CONFLICT DO NOTHING so the syncer
// doesn't have to diff existing membership.
func (s *Store) AddGroupMember(ctx context.Context, groupID, userID string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO group_members(group_id, user_id, joined_at) VALUES(?, ?, ?)
		ON CONFLICT(group_id, user_id) DO NOTHING`,
		groupID, userID, fmtTime(time.Now()),
	)
	if err != nil {
		return fmt.Errorf("add group member: %w", err)
	}
	return nil
}

func (s *Store) RemoveGroupMember(ctx context.Context, groupID, userID string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM group_members WHERE group_id = ? AND user_id = ?`,
		groupID, userID)
	return err
}

func (s *Store) ListGroupMembers(ctx context.Context, groupID string) ([]domain.User, error) {
	// Precondition: group must exist — otherwise we'd silently return an
	// empty list, hiding stale group-id references in the syncer.
	if _, err := s.GetGroup(ctx, groupID); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT u.id, u.username, u.password_hash, u.display_name, u.email, u.external_id, u.validator_user_id, u.is_operator, u.status, u.created_at, u.updated_at
		FROM users u
		JOIN group_members gm ON gm.user_id = u.id
		WHERE gm.group_id = ?
		ORDER BY u.username`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]domain.User, 0)
	for rows.Next() {
		u, err := s.scanUserRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Store) ListUserGroups(ctx context.Context, userID string) ([]domain.Group, error) {
	if _, err := s.GetUser(ctx, userID); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT g.id, g.slug, g.display_name, g.external_id, g.created_at, g.updated_at
		FROM groups g
		JOIN group_members gm ON gm.group_id = g.id
		WHERE gm.user_id = ?
		ORDER BY g.slug`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]domain.Group, 0)
	for rows.Next() {
		g, err := s.scanGroupRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func (s *Store) scanUserRow(r sqlbase.Scannable) (domain.User, error) {
	var u domain.User
	var isOperator int
	var extID, mgrID sql.NullString
	var createdAt, updatedAt string
	err := r.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.DisplayName, &u.Email, &extID, &mgrID, &isOperator, &u.Status, &createdAt, &updatedAt)
	if err != nil {
		return domain.User{}, err
	}
	u.IsOperator = isOperator != 0
	if extID.Valid {
		u.ExternalID = extID.String
	}
	if mgrID.Valid {
		u.ValidatorUserID = mgrID.String
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
		INSERT INTO backends(id, name, type, host, port, databases, approval_mode, t2_group_slug, created_at, updated_at)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		b.ID, b.Name, string(b.Type), b.Host, b.Port,
		strings.Join(b.Databases, ","),
		sqlbase.ApprovalModeOrDefault(b.ApprovalMode),
		b.T2GroupSlug,
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
	host, port, err := sqlbase.SplitAddr(addr)
	if err != nil {
		return domain.Backend{}, store.ErrNotFound
	}
	return s.scanBackendRow(s.db.QueryRowContext(ctx, `
		SELECT id, name, type, host, port, databases, approval_mode, t2_group_slug, created_at, updated_at
		FROM backends WHERE host = ? AND port = ?`, host, port))
}

// GetBackendByName resolves a backend by alias. Used by the trio policy.
func (s *Store) GetBackendByName(ctx context.Context, name string) (domain.Backend, error) {
	return s.scanBackendRow(s.db.QueryRowContext(ctx, `
		SELECT id, name, type, host, port, databases, approval_mode, t2_group_slug, created_at, updated_at
		FROM backends WHERE name = ?`, name))
}

// GetBackend resolves a backend by its primary-key id.
func (s *Store) GetBackend(ctx context.Context, id string) (domain.Backend, error) {
	return s.scanBackendRow(s.db.QueryRowContext(ctx, `
		SELECT id, name, type, host, port, databases, approval_mode, t2_group_slug, created_at, updated_at
		FROM backends WHERE id = ?`, id))
}

func (s *Store) ListBackends(ctx context.Context) ([]domain.Backend, error) {
	return sqlbase.QueryList(ctx, s.db, `
		SELECT id, name, type, host, port, databases, approval_mode, t2_group_slug, created_at, updated_at
		FROM backends ORDER BY name ASC`, scanBackend)
}

// rowScanner aliases the shared scannable interface so the free scan helpers
// (scanBackend, scanGrant) work against both *sql.Row and *sql.Rows as well as
// the generic sqlbase.QueryList helper.
type rowScanner = sqlbase.Scannable

func (s *Store) scanBackendRow(row *sql.Row) (domain.Backend, error) {
	b, err := scanBackend(row)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Backend{}, store.ErrNotFound
	}
	return b, err
}

func scanBackend(r rowScanner) (domain.Backend, error) {
	var b domain.Backend
	var bType, databases, approvalMode, createdAt, updatedAt string
	if err := r.Scan(&b.ID, &b.Name, &bType, &b.Host, &b.Port, &databases, &approvalMode, &b.T2GroupSlug, &createdAt, &updatedAt); err != nil {
		return domain.Backend{}, err
	}
	b.Type = domain.ProxyType(bType)
	if databases != "" {
		b.Databases = strings.Split(databases, ",")
	}
	b.ApprovalMode = domain.ApprovalMode(approvalMode)
	var err error
	if b.CreatedAt, err = parseTime(createdAt); err != nil {
		return domain.Backend{}, err
	}
	if b.UpdatedAt, err = parseTime(updatedAt); err != nil {
		return domain.Backend{}, err
	}
	return b, nil
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
		a.ID, a.BackendID, string(a.Role), a.Username, a.Password,
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
	).Scan(&a.ID, &a.BackendID, &roleStr, &a.Username, &a.Password, &createdAt, &updatedAt)
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
			t2_approved_by, requested_at, t2_approved_at, expires_at, revoked_at,
			connection_ttl_seconds, ephemeral_username, ephemeral_password,
			t1_subject, t1_approved_by, t1_approved_at, t1_approved_on_behalf, t1_on_behalf_reason,
			request_expires_at, claim_expires_at, policy_mode,
			created_at, updated_at)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		g.ID, g.UserID, g.BackendID, g.Database, string(g.Role), string(g.Status),
		g.Reason, g.PortalPassword, g.T2ApprovedBy,
		fmtTime(g.RequestedAt), nullableTime(g.T2ApprovedAt),
		nullableTime(g.ExpiresAt), nullableTime(g.RevokedAt),
		g.ConnectionTTLSec, g.EphemeralUsername, g.EphemeralPassword,
		g.T1Subject, g.T1ApprovedBy, nullableTime(g.T1ApprovedAt), g.T1ApprovedOnBehalf, g.T1OnBehalfReason,
		nullableTime(g.RequestExpiresAt), nullableTime(g.ClaimExpiresAt), g.PolicyMode,
		fmtTime(g.CreatedAt), fmtTime(g.UpdatedAt),
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
			portal_password = ?, t2_approved_by = ?, requested_at = ?, t2_approved_at = ?,
			expires_at = ?, revoked_at = ?, connection_ttl_seconds = ?,
			ephemeral_username = ?, ephemeral_password = ?,
			t1_subject = ?, t1_approved_by = ?, t1_approved_at = ?,
			t1_approved_on_behalf = ?, t1_on_behalf_reason = ?,
			request_expires_at = ?, claim_expires_at = ?, policy_mode = ?,
			updated_at = ?
		WHERE id = ?`,
		g.UserID, g.BackendID, g.Database, string(g.Role), string(g.Status), g.Reason,
		g.PortalPassword, g.T2ApprovedBy, fmtTime(g.RequestedAt), nullableTime(g.T2ApprovedAt),
		nullableTime(g.ExpiresAt), nullableTime(g.RevokedAt), g.ConnectionTTLSec,
		g.EphemeralUsername, g.EphemeralPassword,
		g.T1Subject, g.T1ApprovedBy, nullableTime(g.T1ApprovedAt),
		g.T1ApprovedOnBehalf, g.T1OnBehalfReason,
		nullableTime(g.RequestExpiresAt), nullableTime(g.ClaimExpiresAt), g.PolicyMode,
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

// ListEphemeralOrphans returns terminal-state grants that still carry an
// ephemeral backend user. The sweeper revokes these to catch crashes between
// status flip and provisioner.Revoke().
func (s *Store) ListEphemeralOrphans(ctx context.Context) ([]domain.Grant, error) {
	rows, err := s.db.QueryContext(ctx, grantSelectSQL+`
		WHERE ephemeral_username <> '' AND status IN (?, ?, ?)`,
		string(domain.GrantDenied), string(domain.GrantRevoked), string(domain.GrantExpired),
	)
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

// ExpireStaleGrants flips ACTIVE grants past ExpiresAt to EXPIRED in one
// statement. Skips rows that already carry revoked_at — protects against
// reclassifying a manually-set (ACTIVE, revoked_at!=NULL) corner case
// and clobbering the revoke signal.
func (s *Store) ExpireStaleGrants(ctx context.Context, now time.Time) (int, error) {
	res, err := s.db.ExecContext(ctx, `
		UPDATE grants SET status = ?, updated_at = ?
		WHERE status = ? AND expires_at IS NOT NULL AND expires_at < ?
		  AND revoked_at IS NULL`,
		string(domain.GrantExpired), fmtTime(now), string(domain.GrantActive), fmtTime(now),
	)
	if err != nil {
		return 0, fmt.Errorf("expire grants: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// ExpireUnclaimedGrants combines the two pre-credential expiry passes in a
// single round-trip: PENDING|VALIDATOR_APPROVED past request_expires_at, plus
// APPROVED past claim_expires_at. Both transition straight to EXPIRED — no
// ephemeral creds were ever provisioned.
func (s *Store) ExpireUnclaimedGrants(ctx context.Context, now time.Time) (int, error) {
	res, err := s.db.ExecContext(ctx, `
		UPDATE grants SET status = ?, updated_at = ?
		WHERE revoked_at IS NULL AND (
			(status IN (?, ?) AND request_expires_at IS NOT NULL AND request_expires_at < ?)
			OR (status = ? AND claim_expires_at IS NOT NULL AND claim_expires_at < ?)
		)`,
		string(domain.GrantExpired), fmtTime(now),
		string(domain.GrantPending), string(domain.GrantValidatorApproved), fmtTime(now),
		string(domain.GrantApproved), fmtTime(now),
	)
	if err != nil {
		return 0, fmt.Errorf("expire unclaimed grants: %w", err)
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
			portal_password = ?, t2_approved_by = ?, requested_at = ?, t2_approved_at = ?,
			expires_at = ?, revoked_at = ?, connection_ttl_seconds = ?,
			ephemeral_username = ?, ephemeral_password = ?,
			t1_subject = ?, t1_approved_by = ?, t1_approved_at = ?,
			t1_approved_on_behalf = ?, t1_on_behalf_reason = ?,
			request_expires_at = ?, claim_expires_at = ?, policy_mode = ?,
			updated_at = ?
		WHERE id = ? AND status = ?`,
		g.UserID, g.BackendID, g.Database, string(g.Role), string(g.Status), g.Reason,
		g.PortalPassword, g.T2ApprovedBy, fmtTime(g.RequestedAt), nullableTime(g.T2ApprovedAt),
		nullableTime(g.ExpiresAt), nullableTime(g.RevokedAt), g.ConnectionTTLSec,
		g.EphemeralUsername, g.EphemeralPassword,
		g.T1Subject, g.T1ApprovedBy, nullableTime(g.T1ApprovedAt),
		g.T1ApprovedOnBehalf, g.T1OnBehalfReason,
		nullableTime(g.RequestExpiresAt), nullableTime(g.ClaimExpiresAt), g.PolicyMode,
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

// SetGrantEphemeral stamps (or clears, when both strings are empty) the
// ephemeral backend credential for an existing grant. Dedicated statement so
// the hot handler path doesn't have to round-trip the full grant row just to
// persist two columns.
func (s *Store) SetGrantEphemeral(ctx context.Context, id, username, password string) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE grants SET ephemeral_username = ?, ephemeral_password = ?, updated_at = ?
		WHERE id = ?`,
		username, password, fmtTime(time.Now().UTC()), id,
	)
	if err != nil {
		return fmt.Errorf("set grant ephemeral: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (s *Store) ListGrants(ctx context.Context, f store.GrantFilter) ([]domain.Grant, error) {
	var (
		args    []any
		clauses []string
	)
	// Bridge for scope=validator (phase-7 §7.4): subquery against the
	// single-validator users.validator_user_id column. Mutually exclusive
	// with f.UserID — when both are set ValidatorUserID wins (see store.go
	// GrantFilter doc). Replaced by a JOIN on grant_validators when the
	// snapshot table lands.
	if f.ValidatorUserID != "" {
		clauses = append(clauses, "user_id IN (SELECT id FROM users WHERE validator_user_id = ?)")
		args = append(args, f.ValidatorUserID)
	} else if f.UserID != "" {
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
	t2_approved_by, requested_at, t2_approved_at, expires_at, revoked_at, connection_ttl_seconds,
	ephemeral_username, ephemeral_password,
	t1_subject, t1_approved_by, t1_approved_at, t1_approved_on_behalf, t1_on_behalf_reason,
	request_expires_at, claim_expires_at, policy_mode,
	created_at, updated_at FROM grants`

func scanGrant(r rowScanner) (domain.Grant, error) {
	var (
		g                                              domain.Grant
		role, status                                   string
		requestedAt, createdAt, updatedAt              string
		t2ApprovedAt, expiresAt, revokedAt             sql.NullString
		t1ApprovedAt, requestExpiresAt, claimExpiresAt sql.NullString
		t1OnBehalf                                     int
	)
	if err := r.Scan(&g.ID, &g.UserID, &g.BackendID, &g.Database, &role, &status, &g.Reason,
		&g.PortalPassword, &g.T2ApprovedBy, &requestedAt, &t2ApprovedAt, &expiresAt, &revokedAt,
		&g.ConnectionTTLSec, &g.EphemeralUsername, &g.EphemeralPassword,
		&g.T1Subject, &g.T1ApprovedBy, &t1ApprovedAt, &t1OnBehalf, &g.T1OnBehalfReason,
		&requestExpiresAt, &claimExpiresAt, &g.PolicyMode,
		&createdAt, &updatedAt); err != nil {
		return domain.Grant{}, err
	}
	g.Role = domain.Role(role)
	g.Status = domain.GrantStatus(status)
	g.T1ApprovedOnBehalf = t1OnBehalf != 0
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
	if g.T2ApprovedAt, err = scanNullableTime(t2ApprovedAt); err != nil {
		return domain.Grant{}, err
	}
	if g.ExpiresAt, err = scanNullableTime(expiresAt); err != nil {
		return domain.Grant{}, err
	}
	if g.RevokedAt, err = scanNullableTime(revokedAt); err != nil {
		return domain.Grant{}, err
	}
	if g.T1ApprovedAt, err = scanNullableTime(t1ApprovedAt); err != nil {
		return domain.Grant{}, err
	}
	if g.RequestExpiresAt, err = scanNullableTime(requestExpiresAt); err != nil {
		return domain.Grant{}, err
	}
	if g.ClaimExpiresAt, err = scanNullableTime(claimExpiresAt); err != nil {
		return domain.Grant{}, err
	}
	return g, nil
}

// --- provisioning outbox ---

const intentSelectSQL = `SELECT id, grant_id, kind, backend_id, database, role,
	requested_duration_seconds, target_username, status, worker_id, lease_expires_at,
	result_username, result_password, error_class, error_detail, retry_count,
	created_at, updated_at, completed_at FROM provision_intents`

// InsertIntent is idempotent — ON CONFLICT(id) DO NOTHING makes a producer
// retry a no-op success rather than ErrConflict (the id is deterministic).
func (s *Store) InsertIntent(ctx context.Context, in domain.Intent) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO provision_intents(id, grant_id, kind, backend_id, database, role,
			requested_duration_seconds, target_username, status, worker_id, lease_expires_at,
			result_username, result_password, error_class, error_detail, retry_count,
			created_at, updated_at, completed_at)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO NOTHING`,
		in.ID, in.GrantID, string(in.Kind), in.BackendID, in.Database, string(in.Role),
		in.RequestedDurationSec, in.TargetUsername, string(in.Status), in.WorkerID, nullableTime(in.LeaseExpiresAt),
		in.ResultUsername, in.ResultPassword, in.ErrorClass, in.ErrorDetail, in.RetryCount,
		fmtTime(in.CreatedAt), fmtTime(in.UpdatedAt), nullableTime(in.CompletedAt),
	)
	if err != nil {
		return fmt.Errorf("insert intent: %w", err)
	}
	return nil
}

// ClaimPendingIntents leases eligible rows under sqlite's single-writer
// discipline. We select eligible ids in claim order inside a tx, then UPDATE
// them to in_flight — the MaxOpenConns(1) cap plus the implicit write lock on
// the UPDATE serialise this against any other writer, so no other worker can
// claim the same rows. Returns the rows as they now read.
func (s *Store) ClaimPendingIntents(ctx context.Context, workerID string, instanceWhitelist []string, lease time.Duration, limit int) ([]domain.Intent, error) {
	now := time.Now().UTC()
	nowStr := fmtTime(now)
	leaseStr := fmtTime(now.Add(lease))

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin claim tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Eligible = pending OR (in_flight with a lapsed lease). Order revoke
	// before provision, then oldest first.
	args := []any{nowStr}
	q := `SELECT id FROM provision_intents
		WHERE (status = 'pending' OR (status = 'in_flight' AND lease_expires_at IS NOT NULL AND lease_expires_at < ?))`
	if len(instanceWhitelist) > 0 {
		ph := make([]string, len(instanceWhitelist))
		for i, b := range instanceWhitelist {
			ph[i] = "?"
			args = append(args, b)
		}
		q += " AND backend_id IN (" + strings.Join(ph, ",") + ")"
	}
	// CASE orders revoke (0) ahead of provision (1).
	q += " ORDER BY CASE kind WHEN 'revoke' THEN 0 ELSE 1 END ASC, created_at ASC, id ASC"
	if limit > 0 {
		q += fmt.Sprintf(" LIMIT %d", limit)
	}

	rows, err := tx.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("select claimable intents: %w", err)
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return []domain.Intent{}, tx.Commit()
	}

	for _, id := range ids {
		if _, err := tx.ExecContext(ctx, `
			UPDATE provision_intents
			SET status = 'in_flight', worker_id = ?, lease_expires_at = ?, updated_at = ?
			WHERE id = ?`,
			workerID, leaseStr, nowStr, id,
		); err != nil {
			return nil, fmt.Errorf("claim intent %s: %w", id, err)
		}
	}

	ph := make([]string, len(ids))
	selArgs := make([]any, len(ids))
	for i, id := range ids {
		ph[i] = "?"
		selArgs[i] = id
	}
	selRows, err := tx.QueryContext(ctx,
		intentSelectSQL+" WHERE id IN ("+strings.Join(ph, ",")+
			") ORDER BY CASE kind WHEN 'revoke' THEN 0 ELSE 1 END ASC, created_at ASC, id ASC",
		selArgs...)
	if err != nil {
		return nil, fmt.Errorf("read claimed intents: %w", err)
	}
	out := make([]domain.Intent, 0, len(ids))
	for selRows.Next() {
		in, err := scanIntent(selRows)
		if err != nil {
			selRows.Close()
			return nil, err
		}
		out = append(out, in)
	}
	selRows.Close()
	if err := selRows.Err(); err != nil {
		return nil, err
	}
	return out, tx.Commit()
}

// HeartbeatIntentLease extends the lease only while the row is still owned and
// in_flight. The WHERE clause enforces both — zero rows affected ⇒ ErrNotFound.
func (s *Store) HeartbeatIntentLease(ctx context.Context, id, workerID string, lease time.Duration) error {
	now := time.Now().UTC()
	res, err := s.db.ExecContext(ctx, `
		UPDATE provision_intents SET lease_expires_at = ?, updated_at = ?
		WHERE id = ? AND worker_id = ? AND status = 'in_flight'`,
		fmtTime(now.Add(lease)), fmtTime(now), id, workerID,
	)
	if err != nil {
		return fmt.Errorf("heartbeat intent: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

// CompleteIntent marks an owned, in-flight row done with its result.
func (s *Store) CompleteIntent(ctx context.Context, id, workerID, resultUsername, resultPassword string) error {
	now := time.Now().UTC()
	res, err := s.db.ExecContext(ctx, `
		UPDATE provision_intents
		SET status = 'done', result_username = ?, result_password = ?, completed_at = ?, updated_at = ?
		WHERE id = ? AND worker_id = ? AND status = 'in_flight'`,
		resultUsername, resultPassword, fmtTime(now), fmtTime(now), id, workerID,
	)
	if err != nil {
		return fmt.Errorf("complete intent: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

// FailIntent marks an owned, in-flight row failed with its error bookkeeping.
func (s *Store) FailIntent(ctx context.Context, id, workerID, errorClass, errorDetail string, retryCount int) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE provision_intents
		SET status = 'failed', error_class = ?, error_detail = ?, retry_count = ?, updated_at = ?
		WHERE id = ? AND worker_id = ? AND status = 'in_flight'`,
		errorClass, errorDetail, retryCount, fmtTime(time.Now().UTC()), id, workerID,
	)
	if err != nil {
		return fmt.Errorf("fail intent: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

// ResetIntentForRetry flips a failed row back to pending, clearing the
// worker/lease/error columns. The status = 'failed' guard in the WHERE clause
// makes it idempotent and race-safe: zero rows affected (already re-claimed or
// gone) ⇒ ErrNotFound.
func (s *Store) ResetIntentForRetry(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE provision_intents
		SET status = 'pending', worker_id = '', lease_expires_at = NULL,
			error_class = '', error_detail = '', retry_count = 0, updated_at = ?
		WHERE id = ? AND status = 'failed'`,
		fmtTime(time.Now().UTC()), id,
	)
	if err != nil {
		return fmt.Errorf("reset intent for retry: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (s *Store) GetIntent(ctx context.Context, id string) (domain.Intent, error) {
	row := s.db.QueryRowContext(ctx, intentSelectSQL+` WHERE id = ?`, id)
	in, err := scanIntent(row)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Intent{}, store.ErrNotFound
	}
	return in, err
}

func (s *Store) GetLatestIntentForGrant(ctx context.Context, grantID string, kind domain.IntentKind) (domain.Intent, error) {
	row := s.db.QueryRowContext(ctx,
		intentSelectSQL+` WHERE grant_id = ? AND kind = ? ORDER BY created_at DESC, id DESC LIMIT 1`,
		grantID, string(kind))
	in, err := scanIntent(row)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Intent{}, store.ErrNotFound
	}
	return in, err
}

func scanIntent(r rowScanner) (domain.Intent, error) {
	var (
		in           domain.Intent
		kind, role   string
		status       string
		leaseExpires sql.NullString
		completedAt  sql.NullString
		createdAt    string
		updatedAt    string
	)
	if err := r.Scan(&in.ID, &in.GrantID, &kind, &in.BackendID, &in.Database, &role,
		&in.RequestedDurationSec, &in.TargetUsername, &status, &in.WorkerID, &leaseExpires,
		&in.ResultUsername, &in.ResultPassword, &in.ErrorClass, &in.ErrorDetail, &in.RetryCount,
		&createdAt, &updatedAt, &completedAt); err != nil {
		return domain.Intent{}, err
	}
	in.Kind = domain.IntentKind(kind)
	in.Role = domain.Role(role)
	in.Status = domain.IntentStatus(status)
	var err error
	if in.CreatedAt, err = parseTime(createdAt); err != nil {
		return domain.Intent{}, err
	}
	if in.UpdatedAt, err = parseTime(updatedAt); err != nil {
		return domain.Intent{}, err
	}
	if in.LeaseExpiresAt, err = scanNullableTime(leaseExpires); err != nil {
		return domain.Intent{}, err
	}
	if in.CompletedAt, err = scanNullableTime(completedAt); err != nil {
		return domain.Intent{}, err
	}
	return in, nil
}

// --- worker liveness ---

// UpsertWorkerHeartbeat inserts on first beat, updates thereafter. ON CONFLICT
// deliberately omits started_at from the SET list so the original insert's
// value survives — a later beat must not reset process uptime. Instances /
// Health are stored as JSON text (the DEFAULT '[]' columns).
func (s *Store) UpsertWorkerHeartbeat(ctx context.Context, hb domain.WorkerHeartbeat) error {
	instances, health, err := sqlbase.MarshalHeartbeatSlices(hb)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO provisioning_workers(worker_id, instances, health, version, started_at, last_seen_at)
		VALUES(?, ?, ?, ?, ?, ?)
		ON CONFLICT(worker_id) DO UPDATE SET
			instances = excluded.instances,
			health = excluded.health,
			version = excluded.version,
			last_seen_at = excluded.last_seen_at`,
		hb.WorkerID, instances, health, hb.Version, fmtTime(hb.StartedAt), fmtTime(hb.LastSeenAt),
	)
	if err != nil {
		return fmt.Errorf("upsert worker heartbeat: %w", err)
	}
	return nil
}

func (s *Store) ListWorkerHeartbeats(ctx context.Context) ([]domain.WorkerHeartbeat, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT worker_id, instances, health, version, started_at, last_seen_at
		FROM provisioning_workers ORDER BY worker_id`)
	if err != nil {
		return nil, fmt.Errorf("list worker heartbeats: %w", err)
	}
	defer rows.Close()
	out := []domain.WorkerHeartbeat{}
	for rows.Next() {
		var (
			hb                  domain.WorkerHeartbeat
			instances, health   string
			startedAt, lastSeen string
		)
		if err := rows.Scan(&hb.WorkerID, &instances, &health, &hb.Version, &startedAt, &lastSeen); err != nil {
			return nil, err
		}
		if err := sqlbase.UnmarshalHeartbeatSlices(&hb, instances, health); err != nil {
			return nil, err
		}
		if hb.StartedAt, err = parseTime(startedAt); err != nil {
			return nil, err
		}
		if hb.LastSeenAt, err = parseTime(lastSeen); err != nil {
			return nil, err
		}
		out = append(out, hb)
	}
	return out, rows.Err()
}

// PruneStaleWorkers deletes rows last seen strictly before cutoff. The `<`
// comparison matches domain.WorkerHeartbeat.IsStale — a row exactly at the
// cutoff is not yet stale.
func (s *Store) PruneStaleWorkers(ctx context.Context, cutoff time.Time) (int, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM provisioning_workers WHERE last_seen_at < ?`, fmtTime(cutoff))
	if err != nil {
		return 0, fmt.Errorf("prune stale workers: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
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

// --- oidc sessions ---

// CreateSession inserts an OIDC session row. UNIQUE(id) surfaces as
// ErrConflict; collisions on a 256-bit random id are astronomically unlikely
// but the error path is cheap.
func (s *Store) CreateSession(ctx context.Context, r store.SessionRecord) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO oidc_sessions(id, subject, email, name, is_operator, portal_user_id, expires_at)
		VALUES(?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.Subject, r.Email, r.Name, boolToInt(r.IsOperator), r.PortalUserID, fmtTime(r.ExpiresAt),
	)
	if isUniqueErr(err) {
		return store.ErrConflict
	}
	if err != nil {
		return fmt.Errorf("insert oidc session: %w", err)
	}
	return nil
}

// GetSession returns the row by id or ErrNotFound. Expiry checking is the
// caller's job — matches the memory impl's contract.
func (s *Store) GetSession(ctx context.Context, id string) (store.SessionRecord, error) {
	var (
		r          store.SessionRecord
		isOperator int
		expiresAt  string
	)
	err := s.db.QueryRowContext(ctx, `
		SELECT id, subject, email, name, is_operator, portal_user_id, expires_at
		FROM oidc_sessions WHERE id = ?`, id,
	).Scan(&r.ID, &r.Subject, &r.Email, &r.Name, &isOperator, &r.PortalUserID, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return store.SessionRecord{}, store.ErrNotFound
	}
	if err != nil {
		return store.SessionRecord{}, err
	}
	r.IsOperator = isOperator != 0
	if r.ExpiresAt, err = parseTime(expiresAt); err != nil {
		return store.SessionRecord{}, err
	}
	return r, nil
}

// DeleteSession is a no-op for unknown IDs — matches the memory impl.
func (s *Store) DeleteSession(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM oidc_sessions WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete oidc session: %w", err)
	}
	return nil
}

// PruneExpiredSessions deletes rows whose expires_at predates now. Single
// statement, no separate count — the RowsAffected return is authoritative.
func (s *Store) PruneExpiredSessions(ctx context.Context, now time.Time) (int, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM oidc_sessions WHERE expires_at < ?`, fmtTime(now))
	if err != nil {
		return 0, fmt.Errorf("prune oidc sessions: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}
