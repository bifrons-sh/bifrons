package api

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/babs/poc-proxies/portal/internal/domain"
	"github.com/babs/poc-proxies/portal/internal/store"
)

// workerStaleThreshold is how long a worker may go without a heartbeat before
// the portal flags it "presumed dead" in the liveness view. The worker beats
// every 10s by default, so 3 missed beats (30s) tolerates a transient blip /
// GC pause without flapping yet still surfaces a genuinely-wedged worker within
// one scrape interval. This is the OBSERVABILITY threshold; actual row deletion
// uses the far longer prune cutoff in the sweeper so a brief stall never drops
// the row out from under a watching operator.
const workerStaleThreshold = 30 * time.Second

// provisioningHandler serves the worker-liveness surface. Read-only; gated by
// the same operator guard the rest of the admin endpoints use (operatorOnly).
type provisioningHandler struct {
	store  store.Store
	logger *slog.Logger
}

// registerProvisioningRoutes wires the worker-liveness endpoint onto mux behind
// the operator guard, mirroring registerAdminRoutes' mutation wrapping.
func registerProvisioningRoutes(mux *http.ServeMux, h *provisioningHandler) {
	mux.Handle("GET /api/v1/provisioning/workers",
		operatorOnly(http.HandlerFunc(h.listWorkers)))
}

// workerHealthDTO mirrors domain.InstanceHealth with snake_case JSON for the
// SPA. Kept local to the handler so the domain type stays free of presentation
// concerns.
type workerHealthDTO struct {
	BackendID  string     `json:"backend_id"`
	OK         bool       `json:"ok"`
	LastOKAt   *time.Time `json:"last_ok_at,omitempty"`
	ErrorClass string     `json:"error_class,omitempty"`
}

// workerDTO is the per-worker liveness row the endpoint returns. stale and
// age_seconds are computed at request time against a single `now` so every row
// in a response is judged against the same clock.
type workerDTO struct {
	WorkerID   string            `json:"worker_id"`
	Instances  []string          `json:"instances"`
	Health     []workerHealthDTO `json:"health"`
	Version    string            `json:"version,omitempty"`
	StartedAt  time.Time         `json:"started_at"`
	LastSeenAt time.Time         `json:"last_seen_at"`
	Stale      bool              `json:"stale"`
	AgeSeconds float64           `json:"age_seconds"`
}

func toWorkerDTO(hb domain.WorkerHeartbeat, now time.Time) workerDTO {
	health := make([]workerHealthDTO, 0, len(hb.Health))
	for _, ih := range hb.Health {
		health = append(health, workerHealthDTO{
			BackendID:  ih.BackendID,
			OK:         ih.OK,
			LastOKAt:   ih.LastOKAt,
			ErrorClass: ih.ErrorClass,
		})
	}
	// Instances default to a non-nil empty slice so the JSON is [] not null —
	// the SPA renders "serves: all" off an empty list, never off a missing key.
	instances := hb.Instances
	if instances == nil {
		instances = []string{}
	}
	return workerDTO{
		WorkerID:   hb.WorkerID,
		Instances:  instances,
		Health:     health,
		Version:    hb.Version,
		StartedAt:  hb.StartedAt,
		LastSeenAt: hb.LastSeenAt,
		Stale:      hb.IsStale(now, workerStaleThreshold),
		AgeSeconds: now.Sub(hb.LastSeenAt).Seconds(),
	}
}

// listWorkers returns every registered worker's liveness row with a computed
// stale flag. Operator-only (the table reveals fleet topology + reachability).
func (h *provisioningHandler) listWorkers(w http.ResponseWriter, r *http.Request) {
	hbs, err := h.store.ListWorkerHeartbeats(r.Context())
	if err != nil {
		h.logger.Error("list_worker_heartbeats_failed", "err_class", errClass(err))
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	now := time.Now()
	out := make([]workerDTO, 0, len(hbs))
	for _, hb := range hbs {
		out = append(out, toWorkerDTO(hb, now))
	}
	writeJSON(w, http.StatusOK, out)
}
