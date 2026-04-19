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

// Store is the PostgreSQL-backed implementation of store.Store.
type Store struct {
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

	s := &Store{db: db}
	if err := s.migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Close releases the underlying database handle.
func (s *Store) Close() error { return s.db.Close() }

// DB exposes the underlying sql.DB for advanced tests.
func (s *Store) DB() *sql.DB { return s.db }

// migrate applies every embedded migration that hasn't been recorded yet.
// Mirrors the sqlite impl — one tx per migration, deterministic ordering.
//
// Holds a postgres advisory lock for the duration so concurrent portal
// instances can't both try to apply the same migration (one would UNIQUE-
// conflict on schema_migrations and crash-loop). The lock id is a stable
// hash — arbitrary but deterministic across processes.
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

// --- users ---

func (s *Store) CreateUser(ctx context.Context, u domain.User) error {
	// Store NULL for empty ExternalID so the partial UNIQUE index doesn't
	// collide across multiple admin-created users without an IdP binding.
	var extID any
	if u.ExternalID != "" {
		extID = u.ExternalID
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO users(id, username, password_hash, display_name, email, external_id, is_admin, status, created_at, updated_at)
		VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		u.ID, u.Username, u.PasswordHash, u.DisplayName, u.Email, extID, u.IsAdmin, u.Status,
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
	var extID sql.NullString
	err := s.db.QueryRowContext(ctx, `
		SELECT id, username, password_hash, display_name, email, external_id, is_admin, status, created_at, updated_at
		FROM users `+where, arg,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.DisplayName, &u.Email, &extID, &u.IsAdmin, &u.Status, &u.CreatedAt, &u.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.User{}, store.ErrNotFound
	}
	if err != nil {
		return domain.User{}, err
	}
	if extID.Valid {
		u.ExternalID = extID.String
	}
	return u, nil
}

// --- backends ---

func (s *Store) CreateBackend(ctx context.Context, b domain.Backend) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO backends(id, name, type, host, port, databases, created_at, updated_at)
		VALUES($1, $2, $3, $4, $5, $6, $7, $8)`,
		b.ID, b.Name, string(b.Type), b.Host, b.Port,
		strings.Join(b.Databases, ","),
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
	host, port, err := splitAddr(addr)
	if err != nil {
		return domain.Backend{}, store.ErrNotFound
	}
	row := s.db.QueryRowContext(ctx, `
		SELECT id, name, type, host, port, databases, created_at, updated_at
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
		SELECT id, name, type, host, port, databases, created_at, updated_at
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
		SELECT id, name, type, host, port, databases, created_at, updated_at
		FROM backends WHERE id = $1`, id)
	b, err := scanBackend(row)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Backend{}, store.ErrNotFound
	}
	return b, err
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

func scanBackend(r rowScanner) (domain.Backend, error) {
	var b domain.Backend
	var bType, databases string
	if err := r.Scan(&b.ID, &b.Name, &bType, &b.Host, &b.Port, &databases, &b.CreatedAt, &b.UpdatedAt); err != nil {
		return domain.Backend{}, err
	}
	b.Type = domain.ProxyType(bType)
	if databases != "" {
		b.Databases = strings.Split(databases, ",")
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
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO backend_accounts(id, backend_id, role, username, password, created_at, updated_at)
		VALUES($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT(backend_id, role) DO UPDATE SET
			username   = EXCLUDED.username,
			password   = EXCLUDED.password,
			updated_at = EXCLUDED.updated_at`,
		a.ID, a.BackendID, string(a.Role), a.Username, a.Password, //nolint:staticcheck // legacy plaintext column.
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
	).Scan(&a.ID, &a.BackendID, &roleStr, &a.Username, &a.Password, &a.CreatedAt, &a.UpdatedAt) //nolint:staticcheck // legacy plaintext column.
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
			approved_by, requested_at, approved_at, expires_at, revoked_at,
			connection_ttl_seconds, ephemeral_username, ephemeral_password,
			manager_subject, manager_approved_by, manager_approved_at,
			request_expires_at, claim_expires_at, policy_mode,
			created_at, updated_at)
		VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24)`,
		g.ID, g.UserID, g.BackendID, g.Database, string(g.Role), string(g.Status),
		g.Reason, g.PortalPassword, g.ApprovedBy,
		g.RequestedAt.UTC(), nullableTime(g.ApprovedAt),
		nullableTime(g.ExpiresAt), nullableTime(g.RevokedAt),
		g.ConnectionTTLSec, g.EphemeralUsername, g.EphemeralPassword,
		g.ManagerSubject, g.ManagerApprovedBy, nullableTime(g.ManagerApprovedAt),
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
			portal_password = $7, approved_by = $8, requested_at = $9, approved_at = $10,
			expires_at = $11, revoked_at = $12, connection_ttl_seconds = $13,
			ephemeral_username = $14, ephemeral_password = $15,
			manager_subject = $16, manager_approved_by = $17, manager_approved_at = $18,
			request_expires_at = $19, claim_expires_at = $20, policy_mode = $21,
			updated_at = $22
		WHERE id = $23`,
		g.UserID, g.BackendID, g.Database, string(g.Role), string(g.Status), g.Reason,
		g.PortalPassword, g.ApprovedBy, g.RequestedAt.UTC(), nullableTime(g.ApprovedAt),
		nullableTime(g.ExpiresAt), nullableTime(g.RevokedAt), g.ConnectionTTLSec,
		g.EphemeralUsername, g.EphemeralPassword,
		g.ManagerSubject, g.ManagerApprovedBy, nullableTime(g.ManagerApprovedAt),
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
// PENDING|MANAGER_APPROVED past request_expires_at lapse the validation
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
		string(domain.GrantPending), string(domain.GrantManagerApproved), now.UTC(),
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
			portal_password = $7, approved_by = $8, requested_at = $9, approved_at = $10,
			expires_at = $11, revoked_at = $12, connection_ttl_seconds = $13,
			ephemeral_username = $14, ephemeral_password = $15,
			manager_subject = $16, manager_approved_by = $17, manager_approved_at = $18,
			request_expires_at = $19, claim_expires_at = $20, policy_mode = $21,
			updated_at = $22
		WHERE id = $23 AND status = $24`,
		g.UserID, g.BackendID, g.Database, string(g.Role), string(g.Status), g.Reason,
		g.PortalPassword, g.ApprovedBy, g.RequestedAt.UTC(), nullableTime(g.ApprovedAt),
		nullableTime(g.ExpiresAt), nullableTime(g.RevokedAt), g.ConnectionTTLSec,
		g.EphemeralUsername, g.EphemeralPassword,
		g.ManagerSubject, g.ManagerApprovedBy, nullableTime(g.ManagerApprovedAt),
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
	if f.UserID != "" {
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
	approved_by, requested_at, approved_at, expires_at, revoked_at, connection_ttl_seconds,
	ephemeral_username, ephemeral_password,
	manager_subject, manager_approved_by, manager_approved_at,
	request_expires_at, claim_expires_at, policy_mode,
	created_at, updated_at FROM grants`

func scanGrant(r rowScanner) (domain.Grant, error) {
	var (
		g                                                              domain.Grant
		role, status                                                   string
		approvedAt                                                     sql.NullTime
		expiresAt                                                      sql.NullTime
		revokedAt                                                      sql.NullTime
		managerApprovedAt, requestExpiresAt, claimExpiresAt            sql.NullTime
	)
	if err := r.Scan(&g.ID, &g.UserID, &g.BackendID, &g.Database, &role, &status, &g.Reason,
		&g.PortalPassword, &g.ApprovedBy, &g.RequestedAt, &approvedAt, &expiresAt, &revokedAt,
		&g.ConnectionTTLSec, &g.EphemeralUsername, &g.EphemeralPassword,
		&g.ManagerSubject, &g.ManagerApprovedBy, &managerApprovedAt,
		&requestExpiresAt, &claimExpiresAt, &g.PolicyMode,
		&g.CreatedAt, &g.UpdatedAt); err != nil {
		return domain.Grant{}, err
	}
	g.Role = domain.Role(role)
	g.Status = domain.GrantStatus(status)
	if approvedAt.Valid {
		t := approvedAt.Time
		g.ApprovedAt = &t
	}
	if expiresAt.Valid {
		t := expiresAt.Time
		g.ExpiresAt = &t
	}
	if revokedAt.Valid {
		t := revokedAt.Time
		g.RevokedAt = &t
	}
	if managerApprovedAt.Valid {
		t := managerApprovedAt.Time
		g.ManagerApprovedAt = &t
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
		INSERT INTO oidc_sessions(id, subject, email, name, is_admin, expires_at)
		VALUES($1, $2, $3, $4, $5, $6)`,
		r.ID, r.Subject, r.Email, r.Name, r.IsAdmin, r.ExpiresAt.UTC(),
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
		SELECT id, subject, email, name, is_admin, expires_at
		FROM oidc_sessions WHERE id = $1`, id,
	).Scan(&r.ID, &r.Subject, &r.Email, &r.Name, &r.IsAdmin, &r.ExpiresAt)
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
