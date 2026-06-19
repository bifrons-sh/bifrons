package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/babs/poc-proxies/portal/internal/domain"
	"github.com/babs/poc-proxies/portal/internal/store"
)

// orgHandler owns the org-hierarchy admin surface: validator links + group CRUD
// + group membership. These endpoints are populated by the entra-sync script
// for day-to-day ops; they're also usable by hand via curl when demoing or
// bootstrapping without a sync job.
type orgHandler struct {
	store  store.Store
	logger *slog.Logger
}

// registerOrgRoutes wires every org endpoint. Mutations are admin-only; reads
// are open to any authenticated caller (the SPA surfaces these for everyone).
func registerOrgRoutes(mux *http.ServeMux, h *orgHandler) {
	mux.HandleFunc("GET /api/v1/users/{id}/validator", h.getValidator)
	mux.Handle("PUT /api/v1/users/{id}/validator",
		operatorOnly(http.HandlerFunc(h.setValidator)))
	mux.Handle("DELETE /api/v1/users/{id}/validator",
		operatorOnly(http.HandlerFunc(h.clearValidator)))

	mux.HandleFunc("GET /api/v1/groups", h.listGroups)
	mux.Handle("POST /api/v1/groups", operatorOnly(http.HandlerFunc(h.upsertGroup)))
	mux.HandleFunc("GET /api/v1/groups/{id}", h.getGroup)
	mux.Handle("DELETE /api/v1/groups/{id}", operatorOnly(http.HandlerFunc(h.deleteGroup)))

	mux.HandleFunc("GET /api/v1/groups/{id}/members", h.listGroupMembers)
	mux.Handle("POST /api/v1/groups/{id}/members/{userId}",
		operatorOnly(http.HandlerFunc(h.addGroupMember)))
	mux.Handle("DELETE /api/v1/groups/{id}/members/{userId}",
		operatorOnly(http.HandlerFunc(h.removeGroupMember)))

	mux.HandleFunc("GET /api/v1/users/{id}/groups", h.listUserGroups)
}

// --- validator ---

// getValidator returns the validator user record (not the id) so SPA UIs can
// render the display-name + email without a second round-trip. Non-admins
// see the trimmed publicUser shape.
func (h *orgHandler) getValidator(w http.ResponseWriter, r *http.Request) {
	u, err := h.store.GetUser(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "user not found")
		return
	}
	if u.ValidatorUserID == "" {
		writeJSON(w, http.StatusOK, map[string]any{"validator": nil})
		return
	}
	mgr, err := h.store.GetUser(r.Context(), u.ValidatorUserID)
	if err != nil {
		// Validator FK set but row gone — should be impossible under ON DELETE
		// SET NULL, but surface it rather than lying to the SPA.
		h.logger.Warn("validator_row_missing", "user_id", u.ID, "validator_user_id", u.ValidatorUserID)
		writeJSON(w, http.StatusOK, map[string]any{"validator": nil})
		return
	}
	if callerIsOperator(r) {
		writeJSON(w, http.StatusOK, map[string]any{"validator": mgr})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"validator": toPublicUser(mgr)})
}

type setValidatorReq struct {
	ValidatorUserID string `json:"validator_user_id"`
}

func (h *orgHandler) setValidator(w http.ResponseWriter, r *http.Request) {
	var req setValidatorReq
	if err := decodeJSONBodyStrict(w, r, defaultBodyLimit, &req); err != nil {
		return
	}
	if req.ValidatorUserID == "" {
		writeErr(w, http.StatusBadRequest, "validator_user_id is required (DELETE to clear)")
		return
	}
	userID := r.PathValue("id")
	if userID == req.ValidatorUserID {
		writeErr(w, http.StatusBadRequest, "a user cannot be their own validator")
		return
	}
	// Validate that the validator user actually exists — otherwise we'd rely on
	// the FK constraint to reject, which surfaces as a 500.
	if _, err := h.store.GetUser(r.Context(), req.ValidatorUserID); err != nil {
		writeErr(w, http.StatusBadRequest, "validator user not found")
		return
	}
	// Cycle detection: walking the proposed validator's chain upward, userID
	// must not appear — otherwise A→B→…→A becomes a cycle the moment the write
	// lands. Bounded by the number of users to survive pre-existing corrupt
	// chains without looping forever.
	if cycle, err := h.validatorChainContains(r.Context(), req.ValidatorUserID, userID); err != nil {
		h.logger.Error("validator_cycle_check_failed", "user_id", userID, "err_class", errClass(err))
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	} else if cycle {
		writeErr(w, http.StatusBadRequest, "validator chain would contain a cycle")
		return
	}
	if err := h.store.SetUserValidator(r.Context(), userID, req.ValidatorUserID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "user not found")
			return
		}
		h.logger.Error("set_user_validator_failed", "user_id", userID, "err_class", errClass(err))
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	h.logger.Info("user_validator_set", "user_id", userID, "validator_user_id", req.ValidatorUserID, "by", principalFrom(r))
	w.WriteHeader(http.StatusNoContent)
}

// validatorChainContains walks the validator chain starting at startID and
// reports whether needle appears in it. Hard-capped at 64 hops — anything
// deeper than that is a pre-existing corrupt chain, not a real org. Returns
// the store error unchanged so callers can distinguish 404 (row missing)
// from "chain ended cleanly".
func (h *orgHandler) validatorChainContains(ctx context.Context, startID, needle string) (bool, error) {
	const maxDepth = 64
	cur := startID
	for i := 0; i < maxDepth && cur != ""; i++ {
		if cur == needle {
			return true, nil
		}
		u, err := h.store.GetUser(ctx, cur)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return false, nil
			}
			return false, err
		}
		if u.ValidatorUserID == "" {
			return false, nil
		}
		cur = u.ValidatorUserID
	}
	// Chain exceeded maxDepth — treat as a cycle defensively rather than
	// letting the new link extend it further.
	return true, nil
}

func (h *orgHandler) clearValidator(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("id")
	if err := h.store.SetUserValidator(r.Context(), userID, ""); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "user not found")
			return
		}
		h.logger.Error("clear_user_validator_failed", "user_id", userID, "err_class", errClass(err))
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- groups ---

type upsertGroupReq struct {
	ID          string `json:"id,omitempty"` // optional; generated when absent
	Slug        string `json:"slug"`
	DisplayName string `json:"display_name,omitempty"`
	ExternalID  string `json:"external_id,omitempty"`
}

func (h *orgHandler) upsertGroup(w http.ResponseWriter, r *http.Request) {
	var req upsertGroupReq
	if err := decodeJSONBodyStrict(w, r, defaultBodyLimit, &req); err != nil {
		return
	}
	if req.Slug == "" {
		writeErr(w, http.StatusBadRequest, "slug is required")
		return
	}
	// Client-supplied IDs must follow the portal's prefix convention so a
	// stray string (say, a raw Entra GUID) can't land in the id column and
	// mismatch the NewID("grp") shape the rest of the codebase expects.
	if req.ID != "" && !strings.HasPrefix(req.ID, "grp-") {
		writeErr(w, http.StatusBadRequest, `id must start with "grp-" or be omitted to auto-generate`)
		return
	}
	now := time.Now().UTC()
	g := domain.Group{
		ID:          req.ID,
		Slug:        req.Slug,
		DisplayName: req.DisplayName,
		ExternalID:  req.ExternalID,
		UpdatedAt:   now,
	}
	if g.ID == "" {
		g.ID = domain.NewID("grp")
		g.CreatedAt = now
	} else if existing, err := h.store.GetGroup(r.Context(), g.ID); err == nil {
		g.CreatedAt = existing.CreatedAt
	} else {
		g.CreatedAt = now
	}
	if err := h.store.UpsertGroup(r.Context(), g); err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeErr(w, http.StatusConflict, "slug already in use by a different group")
			return
		}
		h.logger.Error("upsert_group_failed", "id", g.ID, "slug", g.Slug, "err_class", errClass(err))
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	h.logger.Info("group_upserted", "id", g.ID, "slug", g.Slug, "by", principalFrom(r))
	writeJSON(w, http.StatusOK, g)
}

func (h *orgHandler) getGroup(w http.ResponseWriter, r *http.Request) {
	g, err := h.store.GetGroup(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "group not found")
		return
	}
	if callerIsOperator(r) {
		writeJSON(w, http.StatusOK, g)
		return
	}
	writeJSON(w, http.StatusOK, toPublicGroup(g))
}

func (h *orgHandler) listGroups(w http.ResponseWriter, r *http.Request) {
	gs, err := h.store.ListGroups(r.Context())
	if err != nil {
		h.logger.Error("list_groups_failed", "err_class", errClass(err))
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	if callerIsOperator(r) {
		writeJSON(w, http.StatusOK, gs)
		return
	}
	writeJSON(w, http.StatusOK, toPublicGroups(gs))
}

func (h *orgHandler) deleteGroup(w http.ResponseWriter, r *http.Request) {
	gid := r.PathValue("id")
	if err := h.store.DeleteGroup(r.Context(), gid); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "group not found")
			return
		}
		h.logger.Error("delete_group_failed", "group_id", gid, "err_class", errClass(err))
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- membership ---

func (h *orgHandler) listGroupMembers(w http.ResponseWriter, r *http.Request) {
	gid := r.PathValue("id")
	members, err := h.store.ListGroupMembers(r.Context(), gid)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "group not found")
			return
		}
		h.logger.Error("list_group_members_failed", "group_id", gid, "err_class", errClass(err))
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	if callerIsOperator(r) {
		writeJSON(w, http.StatusOK, members)
		return
	}
	writeJSON(w, http.StatusOK, toPublicUsers(members))
}

func (h *orgHandler) addGroupMember(w http.ResponseWriter, r *http.Request) {
	gid, uid := r.PathValue("id"), r.PathValue("userId")
	if err := h.store.AddGroupMember(r.Context(), gid, uid); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "group or user not found")
			return
		}
		h.logger.Error("add_group_member_failed", "group_id", gid, "user_id", uid, "err_class", errClass(err))
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	h.logger.Info("group_member_added", "group_id", gid, "user_id", uid, "by", principalFrom(r))
	w.WriteHeader(http.StatusNoContent)
}

func (h *orgHandler) removeGroupMember(w http.ResponseWriter, r *http.Request) {
	gid, uid := r.PathValue("id"), r.PathValue("userId")
	if err := h.store.RemoveGroupMember(r.Context(), gid, uid); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "group or user not found")
			return
		}
		h.logger.Error("remove_group_member_failed", "group_id", gid, "user_id", uid, "err_class", errClass(err))
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	h.logger.Info("group_member_removed", "group_id", gid, "user_id", uid, "by", principalFrom(r))
	w.WriteHeader(http.StatusNoContent)
}

func (h *orgHandler) listUserGroups(w http.ResponseWriter, r *http.Request) {
	uid := r.PathValue("id")
	gs, err := h.store.ListUserGroups(r.Context(), uid)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "user not found")
			return
		}
		h.logger.Error("list_user_groups_failed", "user_id", uid, "err_class", errClass(err))
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	if callerIsOperator(r) {
		writeJSON(w, http.StatusOK, gs)
		return
	}
	writeJSON(w, http.StatusOK, toPublicGroups(gs))
}
