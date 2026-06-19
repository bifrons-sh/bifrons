// Package sqlbase hosts the small slice of store logic that is genuinely
// dialect-independent and byte-identical between the sqlite and postgres
// Store implementations. It deliberately does NOT try to abstract over
// placeholder style (?-vs-$N), upsert/RETURNING syntax, or the timestamp /
// bool encoding differences (TEXT+int for sqlite, native time.Time+bool for
// postgres) — those stay duplicated in each backend where the SQL and scan
// logic legitimately diverge. Forcing them behind a shared seam would trade
// honest duplication for a leaky abstraction.
package sqlbase

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/babs/poc-proxies/portal/internal/domain"
)

// Common carries the database handle and the methods whose entire
// implementation — SQL string included — is identical across both backends.
// Each backend Store embeds it (and keeps its own field referencing the same
// *sql.DB for the dialect-specific methods), so Close/DB are promoted and the
// generic list helper is shared.
type Common struct {
	DBHandle *sql.DB
}

// Close releases the underlying database handle.
func (c *Common) Close() error { return c.DBHandle.Close() }

// DB exposes the underlying sql.DB for advanced tests. Avoid in handlers.
func (c *Common) DB() *sql.DB { return c.DBHandle }

// Scannable is a minimal interface wide enough for both *sql.Row and *sql.Rows.
type Scannable interface {
	Scan(dest ...any) error
}

// QueryList runs a parameter-free SELECT and maps each row with scan. Both
// backends pass the same SQL string (these queries carry no placeholders) and
// their own dialect-specific row scanner, so the boilerplate loop lives here
// without dragging any dialect knowledge into the shared layer.
func QueryList[T any](ctx context.Context, db *sql.DB, query string, scan func(Scannable) (T, error)) ([]T, error) {
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]T, 0)
	for rows.Next() {
		v, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// ApprovalModeOrDefault returns the column-safe value for an INSERT/UPDATE.
// Empty defaults to dual_strict (matches the schema CHECK + DEFAULT) so
// callers can omit the field on legacy code paths.
func ApprovalModeOrDefault(m domain.ApprovalMode) string {
	if m == "" {
		return string(domain.ApprovalDualStrict)
	}
	return string(m)
}

// MarshalHeartbeatSlices renders a WorkerHeartbeat's Instances and Health into
// the JSON text both backends store in the `instances` / `health` columns. A
// nil slice marshals to "[]" (never SQL NULL) so the NOT NULL DEFAULT '[]'
// columns stay satisfied and the round-trip is stable. Shared because the
// encoding is byte-identical across dialects.
func MarshalHeartbeatSlices(hb domain.WorkerHeartbeat) (instances, health string, err error) {
	inst := hb.Instances
	if inst == nil {
		inst = []string{}
	}
	ib, err := json.Marshal(inst)
	if err != nil {
		return "", "", fmt.Errorf("marshal worker instances: %w", err)
	}
	hl := hb.Health
	if hl == nil {
		hl = []domain.InstanceHealth{}
	}
	hb2, err := json.Marshal(hl)
	if err != nil {
		return "", "", fmt.Errorf("marshal worker health: %w", err)
	}
	return string(ib), string(hb2), nil
}

// UnmarshalHeartbeatSlices parses the JSON `instances` / `health` columns back
// onto hb. Empty strings (defensive — the columns default to '[]') leave the
// slices nil rather than erroring.
func UnmarshalHeartbeatSlices(hb *domain.WorkerHeartbeat, instances, health string) error {
	if instances != "" {
		if err := json.Unmarshal([]byte(instances), &hb.Instances); err != nil {
			return fmt.Errorf("unmarshal worker instances: %w", err)
		}
	}
	if health != "" {
		if err := json.Unmarshal([]byte(health), &hb.Health); err != nil {
			return fmt.Errorf("unmarshal worker health: %w", err)
		}
	}
	return nil
}

// SplitAddr parses a "host:port" backend address. Both backends resolve a
// backend by address with identical logic, so it lives here.
func SplitAddr(addr string) (string, int, error) {
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
