package ephemeral

import "github.com/jackc/pgx/v5/pgconn"

// newPgUndefinedRole returns a *pgconn.PgError with SQLSTATE 42704 so the
// idempotent-revoke tests don't have to round-trip a real postgres server to
// reproduce the "role does not exist" error shape.
func newPgUndefinedRole() error {
	return &pgconn.PgError{Code: "42704", Message: "role does not exist"}
}
