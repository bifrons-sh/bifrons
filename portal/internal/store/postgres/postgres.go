// Package postgres implements store.Store against PostgreSQL via the
// jackc/pgx/v5 driver exposed through database/sql. Intended for multi-node
// deployments where SQLite's single-writer model isn't enough.
package postgres

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"math/rand/v2"
	"sort"
	"strings"
	"time"

	"github.com/babs/poc-proxies/portal/internal/domain"
	"github.com/babs/poc-proxies/portal/internal/store"
	"github.com/babs/poc-proxies/portal/internal/store/sqlbase"
	"github.com/jackc/pgx/v5/pgconn"

	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" driver
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// The factory strips the `postgres://` prefix before dispatching. pgx accepts
// both the canonical URL form and key-value form; reassemble so either the user
// provided `postgres://user:pass@host/db` or `postgresql://…` both work.
func init() {
	opener := func(prefix string) store.OpenFunc {
		return func(dsn string) (store.Store, error) {
			if dsn == "" {
				return nil, fmt.Errorf("postgres: empty DSN")
			}
			return Open(prefix + "://" + dsn)
		}
	}
	store.Register("postgres", opener("postgres"))
	store.Register("postgresql", opener("postgresql"))
}

// Store is the PostgreSQL-backed implementation of store.Store. It embeds
// sqlbase.Common for the dialect-independent methods (Close, DB) and keeps its
// own db field — pointing at the same handle — for the many dialect-specific
// methods that bind $N-placeholders and native time.Time values.
type Store struct {
	sqlbase.Common
	db *sql.DB
}

// Open connects to the given DSN (full URL, e.g. "postgres://u:p@host/db").
// Typical callers route through store.NewFromURL.
//
// Retries the initial Ping up to 10 times with a 1s gap — accommodates a
// postgres instance still warming up behind the portal's init (common under
// Kubernetes or docker-compose) without infinitely retrying a mis-configured
// DSN. After retries are exhausted, fails loud so the supervisor restarts.
func Open(dsn string) (*Store, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(4)
	db.SetConnMaxIdleTime(5 * time.Minute)
	// Bound the lifetime of each pooled connection — protects against
	// PgBouncer/LB silently recycling the backend, which otherwise shows up
	// as "unexpected EOF" on the first query after an idle period.
	db.SetConnMaxLifetime(30 * time.Minute)

	var pingErr error
	for attempt := 0; attempt < 10; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		pingErr = db.PingContext(ctx)
		cancel()
		if pingErr == nil {
			break
		}
		time.Sleep(time.Second)
	}
	if pingErr != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping postgres (10 attempts): %w", pingErr)
	}

	s := &Store{Common: sqlbase.Common{DBHandle: db}, db: db}
	if err := s.migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// migrate applies every embedded migration that hasn't been recorded yet.
// Mirrors the sqlite impl — one tx per migration, deterministic ordering.
//
// Holds a postgres advisory lock for the duration so concurrent portal
// instances can't both try to apply the same migration (one would UNIQUE-
// conflict on schema_migrations and crash-loop). The lock id is a stable
// hash — arbitrary but deterministic across processes.
//
// Pre-deployment squash note: 0001_initial.sql was rewritten to fold what was
// previously 0002–0004 into the baseline schema. CREATE TABLE IF NOT EXISTS
// means a dev DB seeded against the older 0001 will silently keep its
// out-of-date users / grants tables. Drop the dev DB (or wipe schema_migrations
// + run from scratch) before running this build against an old database.
const migrationAdvisoryLockID int64 = 0x504F5254414C4D47 // "PORTALMG"

func (s *Store) migrate(ctx context.Context) error {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("acquire conn for migrate: %w", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, migrationAdvisoryLockID); err != nil {
		return fmt.Errorf("acquire migration advisory lock: %w", err)
	}
	defer func() {
		// Best-effort release — if the conn is already busted we'll lose the
		// lock on close anyway.
		_, _ = conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock($1)`, migrationAdvisoryLockID)
	}()

	if _, err := conn.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		id         BIGSERIAL PRIMARY KEY,
		name       TEXT NOT NULL UNIQUE,
		applied_at TIMESTAMPTZ NOT NULL
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
			`INSERT INTO schema_migrations(name, applied_at) VALUES($1, $2)`,
			name, time.Now().UTC(),
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

// isUniqueErr detects postgres UNIQUE violations (SQLSTATE 23505).
func isUniqueErr(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23505"
	}
	return false
}

// isSerializationErr detects postgres serialization failures (SQLSTATE 40001).
// Surfaces under serializable isolation when two transactions touch overlapping
// rows; the loser must retry. Mapping it to store.ErrConflict lets the handler
// return 409 (retry) instead of 500 (opaque server error).
func isSerializationErr(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "40001"
	}
	return false
}

// --- users ---

func (s *Store) CreateUser(ctx context.Context, u domain.User) error {
	// Store NULL for empty ExternalID so the partial UNIQUE index doesn't
	// collide across multiple admin-created users without an IdP binding.
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
		VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		u.ID, u.Username, u.PasswordHash, u.DisplayName, u.Email, extID, validatorID, u.IsOperator, u.Status,
		u.CreatedAt.UTC(), u.UpdatedAt.UTC(),
	)
	if isUniqueErr(err) {
		return store.ErrConflict
	}
	if err != nil {
		return fmt.Errorf("insert user: %w", err)
	}
	return nil
}

// SetUserValidator persists the validator link. "" clears the FK.
func (s *Store) SetUserValidator(ctx context.Context, userID, validatorUserID string) error {
	var validatorID any
	if validatorUserID != "" {
		validatorID = validatorUserID
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE users SET validator_user_id = $1, updated_at = $2 WHERE id = $3`,
		validatorID, time.Now().UTC(), userID,
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
	return s.getUser(ctx, `WHERE id = $1`, id)
}

func (s *Store) GetUserByUsername(ctx context.Context, username string) (domain.User, error) {
	return s.getUser(ctx, `WHERE username = $1`, username)
}

func (s *Store) GetUserByExternalID(ctx context.Context, externalID string) (domain.User, error) {
	return s.getUser(ctx, `WHERE external_id = $1`, externalID)
}

func (s *Store) getUser(ctx context.Context, where string, arg any) (domain.User, error) {
	var u domain.User
	var extID, mgrID sql.NullString
	err := s.db.QueryRowContext(ctx, `
		SELECT id, username, password_hash, display_name, email, external_id, validator_user_id, is_operator, status, created_at, updated_at
		FROM users `+where, arg,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.DisplayName, &u.Email, &extID, &mgrID, &u.IsOperator, &u.Status, &u.CreatedAt, &u.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.User{}, store.ErrNotFound
	}
	if err != nil {
		return domain.User{}, err
	}
	if extID.Valid {
		u.ExternalID = extID.String
	}
	if mgrID.Valid {
		u.ValidatorUserID = mgrID.String
	}
	return u, nil
}

// UpdateUser reconciles mutable scalar attributes (display_name, email,
// external_id, is_operator, status). Identity columns are left alone.
// CAS on updated_at — see store.Store.UpdateUser. TIMESTAMPTZ comparisons
// are microsecond-exact and pgx round-trips time.Time losslessly.
// ExternalID collisions surface as ErrConflict via SQLSTATE 23505.
func (s *Store) UpdateUser(ctx context.Context, u domain.User) error {
	var extID any
	if u.ExternalID != "" {
		extID = u.ExternalID
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE users SET
			display_name = $1,
			email        = $2,
			external_id  = $3,
			is_operator     = $4,
			status       = $5,
			updated_at   = $6
		WHERE id = $7 AND updated_at = $8`,
		u.DisplayName, u.Email, extID, u.IsOperator, u.Status, time.Now().UTC(), u.ID, u.UpdatedAt.UTC(),
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

// UpdateUserDemote runs the same CAS update as UpdateUser inside a serializable
// transaction that first reads the row's current is_operator and (when relevant)
// the active-admin count. Serializable isolation makes two concurrent demotes
// of different admins serialise: the loser fails to commit and surfaces the
// retryable serialisation error, which the handler surfaces as 409. Returns
// ErrLastAdmin when demoting the only remaining admin.
func (s *Store) UpdateUserDemote(ctx context.Context, u domain.User) error {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return fmt.Errorf("begin demote tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var curIsAdmin bool
	var curStatus string
	if err := tx.QueryRowContext(ctx, `SELECT is_operator, status FROM users WHERE id = $1`, u.ID).Scan(&curIsAdmin, &curStatus); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return store.ErrNotFound
		}
		return fmt.Errorf("read is_operator: %w", err)
	}
	// Only enforce the guard when the row currently *counts* as an active
	// admin. Demoting a disabled admin doesn't reduce the active-admin tally,
	// so blocking that case would be a false positive.
	if curIsAdmin && curStatus == "active" && !u.IsOperator {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE is_operator = TRUE AND status = 'active'`).Scan(&n); err != nil {
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
			display_name = $1,
			email        = $2,
			external_id  = $3,
			is_operator     = $4,
			status       = $5,
			updated_at   = $6
		WHERE id = $7 AND updated_at = $8`,
		u.DisplayName, u.Email, extID, u.IsOperator, u.Status, time.Now().UTC(), u.ID, u.UpdatedAt.UTC(),
	)
	if isUniqueErr(err) {
		return store.ErrConflict
	}
	if isSerializationErr(err) {
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
		if isSerializationErr(err) {
			return store.ErrConflict
		}
		return fmt.Errorf("commit demote tx: %w", err)
	}
	return nil
}

// CountAdmins counts active users with is_operator = TRUE.
func (s *Store) CountAdmins(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE is_operator = TRUE AND status = 'active'`).Scan(&n)
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
		VALUES($1, $2, $3, $4, $5, $6)
		ON CONFLICT(id) DO UPDATE SET
			slug         = EXCLUDED.slug,
			display_name = EXCLUDED.display_name,
			external_id  = EXCLUDED.external_id,
			updated_at   = EXCLUDED.updated_at`,
		g.ID, g.Slug, g.DisplayName, extID, g.CreatedAt.UTC(), g.UpdatedAt.UTC(),
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
		`SELECT id, slug, display_name, external_id, created_at, updated_at FROM groups WHERE id = $1`, id))
}

func (s *Store) GetGroupBySlug(ctx context.Context, slug string) (domain.Group, error) {
	return s.scanGroupRow(s.db.QueryRowContext(ctx,
		`SELECT id, slug, display_name, external_id, created_at, updated_at FROM groups WHERE slug = $1`, slug))
}

func (s *Store) ListGroups(ctx context.Context) ([]domain.Group, error) {
	return sqlbase.QueryList(ctx, s.db,
		`SELECT id, slug, display_name, external_id, created_at, updated_at FROM groups ORDER BY slug`, s.scanGroupRow)
}

func (s *Store) DeleteGroup(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM groups WHERE id = $1`, id)
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
	err := r.Scan(&g.ID, &g.Slug, &g.DisplayName, &extID, &g.CreatedAt, &g.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Group{}, store.ErrNotFound
	}
	if err != nil {
		return domain.Group{}, err
	}
	if extID.Valid {
		g.ExternalID = extID.String
	}
	return g, nil
}

// AddGroupMember is idempotent via ON CONFLICT DO NOTHING.
func (s *Store) AddGroupMember(ctx context.Context, groupID, userID string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO group_members(group_id, user_id, joined_at) VALUES($1, $2, $3)
		ON CONFLICT(group_id, user_id) DO NOTHING`,
		groupID, userID, time.Now().UTC(),
	)
	if err != nil {
		return fmt.Errorf("add group member: %w", err)
	}
	return nil
}

func (s *Store) RemoveGroupMember(ctx context.Context, groupID, userID string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM group_members WHERE group_id = $1 AND user_id = $2`,
		groupID, userID)
	return err
}

func (s *Store) ListGroupMembers(ctx context.Context, groupID string) ([]domain.User, error) {
	if _, err := s.GetGroup(ctx, groupID); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT u.id, u.username, u.password_hash, u.display_name, u.email, u.external_id, u.validator_user_id, u.is_operator, u.status, u.created_at, u.updated_at
		FROM users u
		JOIN group_members gm ON gm.user_id = u.id
		WHERE gm.group_id = $1
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
		WHERE gm.user_id = $1
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
	var extID, mgrID sql.NullString
	err := r.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.DisplayName, &u.Email, &extID, &mgrID, &u.IsOperator, &u.Status, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return domain.User{}, err
	}
	if extID.Valid {
		u.ExternalID = extID.String
	}
	if mgrID.Valid {
		u.ValidatorUserID = mgrID.String
	}
	return u, nil
}

// --- backends ---

func (s *Store) CreateBackend(ctx context.Context, b domain.Backend) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO backends(id, name, type, host, port, databases, approval_mode, t2_group_slug, created_at, updated_at)
		VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		b.ID, b.Name, string(b.Type), b.Host, b.Port,
		strings.Join(b.Databases, ","),
		sqlbase.ApprovalModeOrDefault(b.ApprovalMode),
		b.T2GroupSlug,
		b.CreatedAt.UTC(), b.UpdatedAt.UTC(),
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
	row := s.db.QueryRowContext(ctx, `
		SELECT id, name, type, host, port, databases, approval_mode, t2_group_slug, created_at, updated_at
		FROM backends WHERE host = $1 AND port = $2`, host, port)
	b, err := scanBackend(row)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Backend{}, store.ErrNotFound
	}
	return b, err
}

// GetBackendByName resolves a backend by its alias / display name.
func (s *Store) GetBackendByName(ctx context.Context, name string) (domain.Backend, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, name, type, host, port, databases, approval_mode, t2_group_slug, created_at, updated_at
		FROM backends WHERE name = $1`, name)
	b, err := scanBackend(row)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Backend{}, store.ErrNotFound
	}
	return b, err
}

// GetBackend resolves a backend by its primary-key id.
func (s *Store) GetBackend(ctx context.Context, id string) (domain.Backend, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, name, type, host, port, databases, approval_mode, t2_group_slug, created_at, updated_at
		FROM backends WHERE id = $1`, id)
	b, err := scanBackend(row)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Backend{}, store.ErrNotFound
	}
	return b, err
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

func scanBackend(r rowScanner) (domain.Backend, error) {
	var b domain.Backend
	var bType, databases, approvalMode string
	if err := r.Scan(&b.ID, &b.Name, &bType, &b.Host, &b.Port, &databases, &approvalMode, &b.T2GroupSlug, &b.CreatedAt, &b.UpdatedAt); err != nil {
		return domain.Backend{}, err
	}
	b.Type = domain.ProxyType(bType)
	if databases != "" {
		b.Databases = strings.Split(databases, ",")
	}
	b.ApprovalMode = domain.ApprovalMode(approvalMode)
	return b, nil
}

// --- backend accounts ---

func (s *Store) UpsertBackendAccount(ctx context.Context, a domain.BackendAccount) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO backend_accounts(id, backend_id, role, username, password, created_at, updated_at)
		VALUES($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT(backend_id, role) DO UPDATE SET
			username   = EXCLUDED.username,
			password   = EXCLUDED.password,
			updated_at = EXCLUDED.updated_at`,
		a.ID, a.BackendID, string(a.Role), a.Username, a.Password,
		a.CreatedAt.UTC(), a.UpdatedAt.UTC(),
	)
	if err != nil {
		return fmt.Errorf("upsert backend_account: %w", err)
	}
	return nil
}

func (s *Store) GetBackendAccount(ctx context.Context, backendID string, role domain.Role) (domain.BackendAccount, error) {
	var a domain.BackendAccount
	var roleStr string
	err := s.db.QueryRowContext(ctx, `
		SELECT id, backend_id, role, username, password, created_at, updated_at
		FROM backend_accounts WHERE backend_id = $1 AND role = $2`,
		backendID, string(role),
	).Scan(&a.ID, &a.BackendID, &roleStr, &a.Username, &a.Password, &a.CreatedAt, &a.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.BackendAccount{}, store.ErrNotFound
	}
	if err != nil {
		return domain.BackendAccount{}, err
	}
	a.Role = domain.Role(roleStr)
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
		VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26)`,
		g.ID, g.UserID, g.BackendID, g.Database, string(g.Role), string(g.Status),
		g.Reason, g.PortalPassword, g.T2ApprovedBy,
		g.RequestedAt.UTC(), nullableTime(g.T2ApprovedAt),
		nullableTime(g.ExpiresAt), nullableTime(g.RevokedAt),
		g.ConnectionTTLSec, g.EphemeralUsername, g.EphemeralPassword,
		g.T1Subject, g.T1ApprovedBy, nullableTime(g.T1ApprovedAt), g.T1ApprovedOnBehalf, g.T1OnBehalfReason,
		nullableTime(g.RequestExpiresAt), nullableTime(g.ClaimExpiresAt), g.PolicyMode,
		g.CreatedAt.UTC(), g.UpdatedAt.UTC(),
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
	row := s.db.QueryRowContext(ctx, grantSelectSQL+` WHERE id = $1`, id)
	g, err := scanGrant(row)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Grant{}, store.ErrNotFound
	}
	return g, err
}

func (s *Store) UpdateGrant(ctx context.Context, g domain.Grant) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE grants SET
			user_id = $1, backend_id = $2, database = $3, role = $4, status = $5, reason = $6,
			portal_password = $7, t2_approved_by = $8, requested_at = $9, t2_approved_at = $10,
			expires_at = $11, revoked_at = $12, connection_ttl_seconds = $13,
			ephemeral_username = $14, ephemeral_password = $15,
			t1_subject = $16, t1_approved_by = $17, t1_approved_at = $18,
			t1_approved_on_behalf = $19, t1_on_behalf_reason = $20,
			request_expires_at = $21, claim_expires_at = $22, policy_mode = $23,
			updated_at = $24
		WHERE id = $25`,
		g.UserID, g.BackendID, g.Database, string(g.Role), string(g.Status), g.Reason,
		g.PortalPassword, g.T2ApprovedBy, g.RequestedAt.UTC(), nullableTime(g.T2ApprovedAt),
		nullableTime(g.ExpiresAt), nullableTime(g.RevokedAt), g.ConnectionTTLSec,
		g.EphemeralUsername, g.EphemeralPassword,
		g.T1Subject, g.T1ApprovedBy, nullableTime(g.T1ApprovedAt),
		g.T1ApprovedOnBehalf, g.T1OnBehalfReason,
		nullableTime(g.RequestExpiresAt), nullableTime(g.ClaimExpiresAt), g.PolicyMode,
		g.UpdatedAt.UTC(), g.ID,
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
// ephemeral backend user. See store.Store for the contract.
func (s *Store) ListEphemeralOrphans(ctx context.Context) ([]domain.Grant, error) {
	rows, err := s.db.QueryContext(ctx, grantSelectSQL+`
		WHERE ephemeral_username <> '' AND status IN ($1, $2, $3)`,
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
		UPDATE grants SET status = $1, updated_at = $2
		WHERE status = $3 AND expires_at IS NOT NULL AND expires_at < $4
		  AND revoked_at IS NULL`,
		string(domain.GrantExpired), now.UTC(), string(domain.GrantActive), now.UTC(),
	)
	if err != nil {
		return 0, fmt.Errorf("expire grants: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// ExpireUnclaimedGrants combines the two pre-credential expiry passes.
// PENDING|VALIDATOR_APPROVED past request_expires_at lapse the validation
// window; APPROVED past claim_expires_at lapse the claim window. Both
// transition straight to EXPIRED — no creds were ever issued.
func (s *Store) ExpireUnclaimedGrants(ctx context.Context, now time.Time) (int, error) {
	res, err := s.db.ExecContext(ctx, `
		UPDATE grants SET status = $1, updated_at = $2
		WHERE revoked_at IS NULL AND (
			(status IN ($3, $4) AND request_expires_at IS NOT NULL AND request_expires_at < $5)
			OR (status = $6 AND claim_expires_at IS NOT NULL AND claim_expires_at < $7)
		)`,
		string(domain.GrantExpired), now.UTC(),
		string(domain.GrantPending), string(domain.GrantValidatorApproved), now.UTC(),
		string(domain.GrantApproved), now.UTC(),
	)
	if err != nil {
		return 0, fmt.Errorf("expire unclaimed grants: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// UpdateGrantIfStatus is the CAS variant: only writes when status still
// matches expect. Distinguishes ErrNotFound (row gone) from ErrConflict
// (row present but status drifted).
//
// The CAS and its disambiguation SELECT run on the same pooled connection
// inside a single serializable transaction, so a concurrent writer can't
// sneak between the UPDATE and SELECT and cause us to report a state that
// didn't cause the conflict. Serializable isolation can raise SQLSTATE
// 40001 (serialization_failure) / 40P01 (deadlock_detected) under
// contention; the operation is idempotent so we retry up to 3 times with
// short jittered backoff before surfacing the failure.
func (s *Store) UpdateGrantIfStatus(ctx context.Context, g domain.Grant, expect domain.GrantStatus) error {
	const maxAttempts = 3
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			// 10ms × 2^attempt + up to 10ms jitter. Tight enough that a
			// human clicker never notices, loose enough to break lock-
			// thrash patterns.
			backoff := time.Duration(10<<attempt) * time.Millisecond
			jitter := time.Duration(rand.Int64N(int64(10 * time.Millisecond)))
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff + jitter):
			}
		}
		err := s.updateGrantIfStatusOnce(ctx, g, expect)
		if err == nil || errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrConflict) {
			return err
		}
		if !isTransientTxErr(err) {
			return err
		}
		lastErr = err
	}
	return fmt.Errorf("update grant after %d serialization retries: %w", maxAttempts, lastErr)
}

func (s *Store) updateGrantIfStatusOnce(ctx context.Context, g domain.Grant, expect domain.GrantStatus) error {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // rollback after commit is a no-op

	res, err := tx.ExecContext(ctx, `
		UPDATE grants SET
			user_id = $1, backend_id = $2, database = $3, role = $4, status = $5, reason = $6,
			portal_password = $7, t2_approved_by = $8, requested_at = $9, t2_approved_at = $10,
			expires_at = $11, revoked_at = $12, connection_ttl_seconds = $13,
			ephemeral_username = $14, ephemeral_password = $15,
			t1_subject = $16, t1_approved_by = $17, t1_approved_at = $18,
			t1_approved_on_behalf = $19, t1_on_behalf_reason = $20,
			request_expires_at = $21, claim_expires_at = $22, policy_mode = $23,
			updated_at = $24
		WHERE id = $25 AND status = $26`,
		g.UserID, g.BackendID, g.Database, string(g.Role), string(g.Status), g.Reason,
		g.PortalPassword, g.T2ApprovedBy, g.RequestedAt.UTC(), nullableTime(g.T2ApprovedAt),
		nullableTime(g.ExpiresAt), nullableTime(g.RevokedAt), g.ConnectionTTLSec,
		g.EphemeralUsername, g.EphemeralPassword,
		g.T1Subject, g.T1ApprovedBy, nullableTime(g.T1ApprovedAt),
		g.T1ApprovedOnBehalf, g.T1OnBehalfReason,
		nullableTime(g.RequestExpiresAt), nullableTime(g.ClaimExpiresAt), g.PolicyMode,
		g.UpdatedAt.UTC(), g.ID, string(expect),
	)
	if err != nil {
		return fmt.Errorf("update grant: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 1 {
		return tx.Commit()
	}
	var cur string
	qerr := tx.QueryRowContext(ctx, `SELECT status FROM grants WHERE id = $1`, g.ID).Scan(&cur)
	if errors.Is(qerr, sql.ErrNoRows) {
		return store.ErrNotFound
	}
	if qerr != nil {
		return qerr
	}
	return store.ErrConflict
}

// isTransientTxErr matches retriable postgres transaction errors:
// SQLSTATE 40001 (serialization_failure) and 40P01 (deadlock_detected).
func isTransientTxErr(err error) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return false
	}
	return pgErr.Code == "40001" || pgErr.Code == "40P01"
}

// SetGrantEphemeral stamps (or clears, when both strings are empty) the
// ephemeral backend credential for an existing grant. See store.Store for
// the full contract.
func (s *Store) SetGrantEphemeral(ctx context.Context, id, username, password string) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE grants SET ephemeral_username = $1, ephemeral_password = $2, updated_at = $3
		WHERE id = $4`,
		username, password, time.Now().UTC(), id,
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
	next := func() string {
		return fmt.Sprintf("$%d", len(args)+1)
	}
	// Bridge for scope=validator (phase-7 §7.4): subquery against the
	// single-validator users.validator_user_id column. Mutually exclusive
	// with f.UserID — when both are set ValidatorUserID wins (see store.go
	// GrantFilter doc). Replaced by a JOIN on grant_validators when the
	// snapshot table lands.
	if f.ValidatorUserID != "" {
		clauses = append(clauses, "user_id IN (SELECT id FROM users WHERE validator_user_id = "+next()+")")
		args = append(args, f.ValidatorUserID)
	} else if f.UserID != "" {
		clauses = append(clauses, "user_id = "+next())
		args = append(args, f.UserID)
	}
	if f.BackendID != "" {
		clauses = append(clauses, "backend_id = "+next())
		args = append(args, f.BackendID)
	}
	if len(f.Statuses) > 0 {
		ph := make([]string, len(f.Statuses))
		for i, st := range f.Statuses {
			ph[i] = next()
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
		t2ApprovedAt                                   sql.NullTime
		expiresAt                                      sql.NullTime
		revokedAt                                      sql.NullTime
		t1ApprovedAt, requestExpiresAt, claimExpiresAt sql.NullTime
	)
	if err := r.Scan(&g.ID, &g.UserID, &g.BackendID, &g.Database, &role, &status, &g.Reason,
		&g.PortalPassword, &g.T2ApprovedBy, &g.RequestedAt, &t2ApprovedAt, &expiresAt, &revokedAt,
		&g.ConnectionTTLSec, &g.EphemeralUsername, &g.EphemeralPassword,
		&g.T1Subject, &g.T1ApprovedBy, &t1ApprovedAt, &g.T1ApprovedOnBehalf, &g.T1OnBehalfReason,
		&requestExpiresAt, &claimExpiresAt, &g.PolicyMode,
		&g.CreatedAt, &g.UpdatedAt); err != nil {
		return domain.Grant{}, err
	}
	g.Role = domain.Role(role)
	g.Status = domain.GrantStatus(status)
	if t2ApprovedAt.Valid {
		t := t2ApprovedAt.Time
		g.T2ApprovedAt = &t
	}
	if expiresAt.Valid {
		t := expiresAt.Time
		g.ExpiresAt = &t
	}
	if revokedAt.Valid {
		t := revokedAt.Time
		g.RevokedAt = &t
	}
	if t1ApprovedAt.Valid {
		t := t1ApprovedAt.Time
		g.T1ApprovedAt = &t
	}
	if requestExpiresAt.Valid {
		t := requestExpiresAt.Time
		g.RequestExpiresAt = &t
	}
	if claimExpiresAt.Valid {
		t := claimExpiresAt.Time
		g.ClaimExpiresAt = &t
	}
	return g, nil
}

func nullableTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.UTC()
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
		VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)
		ON CONFLICT(id) DO NOTHING`,
		in.ID, in.GrantID, string(in.Kind), in.BackendID, in.Database, string(in.Role),
		in.RequestedDurationSec, in.TargetUsername, string(in.Status), in.WorkerID, nullableTime(in.LeaseExpiresAt),
		in.ResultUsername, in.ResultPassword, in.ErrorClass, in.ErrorDetail, in.RetryCount,
		in.CreatedAt.UTC(), in.UpdatedAt.UTC(), nullableTime(in.CompletedAt),
	)
	if err != nil {
		return fmt.Errorf("insert intent: %w", err)
	}
	return nil
}

// ClaimPendingIntents leases eligible rows atomically. A single UPDATE with a
// FOR UPDATE SKIP LOCKED subquery does the claim: SKIP LOCKED lets concurrent
// workers each grab a disjoint batch without blocking on each other's locked
// rows, and RETURNING hands back the freshly-claimed rows in one round-trip.
func (s *Store) ClaimPendingIntents(ctx context.Context, workerID string, instanceWhitelist []string, lease time.Duration, limit int) ([]domain.Intent, error) {
	now := time.Now().UTC()
	leaseUntil := now.Add(lease)

	// $1 worker_id, $2 lease_expires_at, $3 updated_at, $4 now (for stale-lease
	// comparison), then optional whitelist args, then the LIMIT.
	args := []any{workerID, leaseUntil, now, now}
	whitelistClause := ""
	if len(instanceWhitelist) > 0 {
		ph := make([]string, len(instanceWhitelist))
		for i, b := range instanceWhitelist {
			ph[i] = fmt.Sprintf("$%d", len(args)+1)
			args = append(args, b)
		}
		whitelistClause = " AND backend_id IN (" + strings.Join(ph, ",") + ")"
	}
	limitPlaceholder := fmt.Sprintf("$%d", len(args)+1)
	args = append(args, limit)

	q := `
		UPDATE provision_intents SET
			status = 'in_flight', worker_id = $1, lease_expires_at = $2, updated_at = $3
		WHERE id IN (
			SELECT id FROM provision_intents
			WHERE (status = 'pending'
			    OR (status = 'in_flight' AND lease_expires_at IS NOT NULL AND lease_expires_at < $4))` +
		whitelistClause + `
			ORDER BY CASE kind WHEN 'revoke' THEN 0 ELSE 1 END ASC, created_at ASC, id ASC
			LIMIT ` + limitPlaceholder + `
			FOR UPDATE SKIP LOCKED
		)
		RETURNING id, grant_id, kind, backend_id, database, role,
			requested_duration_seconds, target_username, status, worker_id, lease_expires_at,
			result_username, result_password, error_class, error_detail, retry_count,
			created_at, updated_at, completed_at`

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("claim intents: %w", err)
	}
	defer rows.Close()
	out := make([]domain.Intent, 0)
	for rows.Next() {
		in, err := scanIntent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, in)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// RETURNING does not honour the subquery's ORDER BY, so re-establish the
	// revoke-before-provision / oldest-first contract on the result set.
	sortIntentsForClaim(out)
	return out, nil
}

// sortIntentsForClaim orders revoke ahead of provision, then oldest first,
// tie-broken on id for determinism.
func sortIntentsForClaim(in []domain.Intent) {
	rank := func(k domain.IntentKind) int {
		if k == domain.IntentRevoke {
			return 0
		}
		return 1
	}
	sort.Slice(in, func(i, j int) bool {
		if ri, rj := rank(in[i].Kind), rank(in[j].Kind); ri != rj {
			return ri < rj
		}
		if !in[i].CreatedAt.Equal(in[j].CreatedAt) {
			return in[i].CreatedAt.Before(in[j].CreatedAt)
		}
		return in[i].ID < in[j].ID
	})
}

// HeartbeatIntentLease extends the lease only while the row is still owned and
// in_flight. Zero rows affected ⇒ ErrNotFound (ownership lapsed).
func (s *Store) HeartbeatIntentLease(ctx context.Context, id, workerID string, lease time.Duration) error {
	now := time.Now().UTC()
	res, err := s.db.ExecContext(ctx, `
		UPDATE provision_intents SET lease_expires_at = $1, updated_at = $2
		WHERE id = $3 AND worker_id = $4 AND status = 'in_flight'`,
		now.Add(lease), now, id, workerID,
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
		SET status = 'done', result_username = $1, result_password = $2, completed_at = $3, updated_at = $4
		WHERE id = $5 AND worker_id = $6 AND status = 'in_flight'`,
		resultUsername, resultPassword, now, now, id, workerID,
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
		SET status = 'failed', error_class = $1, error_detail = $2, retry_count = $3, updated_at = $4
		WHERE id = $5 AND worker_id = $6 AND status = 'in_flight'`,
		errorClass, errorDetail, retryCount, time.Now().UTC(), id, workerID,
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
// worker/lease/error columns. The status = 'failed' guard makes it idempotent
// and race-safe: zero rows affected (already re-claimed or gone) ⇒ ErrNotFound.
func (s *Store) ResetIntentForRetry(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE provision_intents
		SET status = 'pending', worker_id = '', lease_expires_at = NULL,
			error_class = '', error_detail = '', retry_count = 0, updated_at = $1
		WHERE id = $2 AND status = 'failed'`,
		time.Now().UTC(), id,
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
	row := s.db.QueryRowContext(ctx, intentSelectSQL+` WHERE id = $1`, id)
	in, err := scanIntent(row)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Intent{}, store.ErrNotFound
	}
	return in, err
}

func (s *Store) GetLatestIntentForGrant(ctx context.Context, grantID string, kind domain.IntentKind) (domain.Intent, error) {
	row := s.db.QueryRowContext(ctx,
		intentSelectSQL+` WHERE grant_id = $1 AND kind = $2 ORDER BY created_at DESC, id DESC LIMIT 1`,
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
		leaseExpires sql.NullTime
		completedAt  sql.NullTime
	)
	if err := r.Scan(&in.ID, &in.GrantID, &kind, &in.BackendID, &in.Database, &role,
		&in.RequestedDurationSec, &in.TargetUsername, &status, &in.WorkerID, &leaseExpires,
		&in.ResultUsername, &in.ResultPassword, &in.ErrorClass, &in.ErrorDetail, &in.RetryCount,
		&in.CreatedAt, &in.UpdatedAt, &completedAt); err != nil {
		return domain.Intent{}, err
	}
	in.Kind = domain.IntentKind(kind)
	in.Role = domain.Role(role)
	in.Status = domain.IntentStatus(status)
	if leaseExpires.Valid {
		t := leaseExpires.Time
		in.LeaseExpiresAt = &t
	}
	if completedAt.Valid {
		t := completedAt.Time
		in.CompletedAt = &t
	}
	return in, nil
}

// --- worker liveness ---

// UpsertWorkerHeartbeat inserts on first beat, updates thereafter. The
// DO UPDATE list deliberately omits started_at so the original insert's value
// survives — a later beat must not reset process uptime. Instances / Health
// are stored as JSON text columns.
func (s *Store) UpsertWorkerHeartbeat(ctx context.Context, hb domain.WorkerHeartbeat) error {
	instances, health, err := sqlbase.MarshalHeartbeatSlices(hb)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO provisioning_workers(worker_id, instances, health, version, started_at, last_seen_at)
		VALUES($1, $2, $3, $4, $5, $6)
		ON CONFLICT(worker_id) DO UPDATE SET
			instances = excluded.instances,
			health = excluded.health,
			version = excluded.version,
			last_seen_at = excluded.last_seen_at`,
		hb.WorkerID, instances, health, hb.Version, hb.StartedAt.UTC(), hb.LastSeenAt.UTC(),
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
			hb                domain.WorkerHeartbeat
			instances, health string
		)
		if err := rows.Scan(&hb.WorkerID, &instances, &health, &hb.Version, &hb.StartedAt, &hb.LastSeenAt); err != nil {
			return nil, err
		}
		if err := sqlbase.UnmarshalHeartbeatSlices(&hb, instances, health); err != nil {
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
	res, err := s.db.ExecContext(ctx, `DELETE FROM provisioning_workers WHERE last_seen_at < $1`, cutoff.UTC())
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
		VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()
	for _, e := range entries {
		if _, err := stmt.ExecContext(ctx,
			e.Timestamp.UTC(), e.GrantID, e.Username, string(e.ProxyType),
			e.BackendServer, e.Database, e.Query, e.Truncated,
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
	next := func() string {
		return fmt.Sprintf("$%d", len(args)+1)
	}
	if f.GrantID != "" {
		clauses = append(clauses, "grant_id = "+next())
		args = append(args, f.GrantID)
	}
	if f.Username != "" {
		clauses = append(clauses, "username = "+next())
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
			e     domain.AuditEntry
			ptype string
		)
		if err := rows.Scan(&e.Timestamp, &e.GrantID, &e.Username, &ptype, &e.BackendServer,
			&e.Database, &e.Query, &e.Truncated, &e.SourceIP, &e.DurationMs, &e.TraceID); err != nil {
			return nil, err
		}
		e.ProxyType = domain.ProxyType(ptype)
		out = append(out, e)
	}
	return out, rows.Err()
}

// PruneAudit applies the retention policy. Strategy mirrors the sqlite impl:
//  1. Drop everything strictly older than cutoff.
//  2. If the remaining count exceeds the hard cap, drop the oldest rows by id.
func (s *Store) PruneAudit(ctx context.Context, cutoff time.Time, maxEntries int) (int, int, error) {
	var pruned int
	res, err := s.db.ExecContext(ctx, `DELETE FROM audit WHERE timestamp < $1`, cutoff.UTC())
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
			var cutID int64
			if err := s.db.QueryRowContext(ctx,
				`SELECT id FROM audit ORDER BY id DESC LIMIT 1 OFFSET $1`, maxEntries-1,
			).Scan(&cutID); err != nil {
				return pruned, total, fmt.Errorf("cap pivot: %w", err)
			}
			res, err := s.db.ExecContext(ctx, `DELETE FROM audit WHERE id < $1`, cutID)
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

// --- oidc sessions ---

// CreateSession inserts an OIDC session. Collisions on the 256-bit id map
// to ErrConflict; any other driver error is wrapped.
func (s *Store) CreateSession(ctx context.Context, r store.SessionRecord) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO oidc_sessions(id, subject, email, name, is_operator, portal_user_id, expires_at)
		VALUES($1, $2, $3, $4, $5, $6, $7)`,
		r.ID, r.Subject, r.Email, r.Name, r.IsOperator, r.PortalUserID, r.ExpiresAt.UTC(),
	)
	if isUniqueErr(err) {
		return store.ErrConflict
	}
	if err != nil {
		return fmt.Errorf("insert oidc session: %w", err)
	}
	return nil
}

// GetSession returns the row or ErrNotFound. Expiry is the caller's concern.
func (s *Store) GetSession(ctx context.Context, id string) (store.SessionRecord, error) {
	var r store.SessionRecord
	err := s.db.QueryRowContext(ctx, `
		SELECT id, subject, email, name, is_operator, portal_user_id, expires_at
		FROM oidc_sessions WHERE id = $1`, id,
	).Scan(&r.ID, &r.Subject, &r.Email, &r.Name, &r.IsOperator, &r.PortalUserID, &r.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return store.SessionRecord{}, store.ErrNotFound
	}
	if err != nil {
		return store.SessionRecord{}, err
	}
	return r, nil
}

// DeleteSession is a no-op for unknown IDs.
func (s *Store) DeleteSession(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM oidc_sessions WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete oidc session: %w", err)
	}
	return nil
}

// PruneExpiredSessions removes rows whose expires_at is before now.
func (s *Store) PruneExpiredSessions(ctx context.Context, now time.Time) (int, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM oidc_sessions WHERE expires_at < $1`, now.UTC())
	if err != nil {
		return 0, fmt.Errorf("prune oidc sessions: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}
