// Command entra-sync pulls org-hierarchy data (users + validators + groups +
// membership) from a source and pushes it to the portal via its admin API.
//
// The whole point of this binary is to keep live IdP calls OFF the portal's
// hot path — grant creation reads validator + groups from the portal store,
// which this script refreshes out-of-band on a cron / timer.
//
// Two sources ship:
//   - `-source file` reads a JSON fixture (example / bootstrap / test).
//   - `-source entra` pulls from Microsoft Graph via the portal/internal/entra
//     client (app-only client credentials).
//
// Run with `-dry-run` to see the plan without mutating the portal. The script
// is idempotent: re-running converges state — new members are added, no-op
// members are left alone. It does NOT remove users/groups that disappeared
// from the source (that's a deliberate safety choice; add a `-prune` flag
// when you're confident the source is authoritative).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/babs/poc-proxies/internal/logging"
	"github.com/babs/poc-proxies/portal/internal/domain"
)

// Fixture is the wire shape of the JSON file the example mode reads. Matching
// the mirrored shape makes it easy to hand-write one for tests.
type Fixture struct {
	Users  []FixtureUser  `json:"users"`
	Groups []FixtureGroup `json:"groups"`
}

type FixtureUser struct {
	Username    string `json:"username"`
	DisplayName string `json:"display_name,omitempty"`
	Email       string `json:"email,omitempty"`
	ExternalID  string `json:"external_id,omitempty"`
	// ValidatorUsername is the USERNAME of this user's validator — not a portal
	// id. Hand-written fixtures are much easier to read that way; the syncer
	// resolves it to the portal id before calling PUT /users/{id}/validator.
	ValidatorUsername string   `json:"validator_username,omitempty"`
	IsAdmin         bool     `json:"is_admin,omitempty"`
	Groups          []string `json:"groups,omitempty"` // group slugs
}

type FixtureGroup struct {
	Slug        string `json:"slug"`
	DisplayName string `json:"display_name,omitempty"`
	ExternalID  string `json:"external_id,omitempty"`
}

func main() {
	portalURL := flag.String("portal-url", getEnv("PORTAL_URL", "http://127.0.0.1:8080"), "Portal base URL (env: PORTAL_URL)")
	token := flag.String("token", os.Getenv("PORTAL_USER_TOKEN"), "Static bearer for the portal admin API (env: PORTAL_USER_TOKEN)")
	source := flag.String("source", getEnv("ENTRA_SYNC_SOURCE", "file"), "Source: file | entra (env: ENTRA_SYNC_SOURCE)")
	fixturePath := flag.String("fixture", getEnv("ENTRA_SYNC_FIXTURE", ""), "Path to JSON fixture when -source=file")
	dryRun := flag.Bool("dry-run", false, "Print the plan without mutating the portal")
	flag.Parse()

	logger := logging.New()
	defer logging.Sync()

	if *token == "" {
		logger.Warn("no portal token configured — the admin endpoints will reject mutations unless the portal is in local-dev (open) mode")
	}

	var fx Fixture
	switch *source {
	case "file":
		if err := loadFixture(*fixturePath, &fx); err != nil {
			logger.Error("load fixture failed", "path", *fixturePath, "err", err)
			os.Exit(2)
		}
	case "entra":
		if err := loadFromEntra(context.Background(), &fx, logger); err != nil {
			logger.Error("entra pull failed", "err", err)
			os.Exit(2)
		}
	default:
		logger.Error("unknown source", "source", *source)
		os.Exit(2)
	}

	client := &portalClient{
		url:    *portalURL,
		token:  *token,
		http:   &http.Client{Timeout: 10 * time.Second},
		dryRun: *dryRun,
		logger: logger,
	}
	if err := client.apply(context.Background(), fx); err != nil {
		logger.Error("sync failed", "err", err)
		os.Exit(1)
	}
	logger.Info("sync complete", "users", len(fx.Users), "groups", len(fx.Groups), "dry_run", *dryRun)
}

func getEnv(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func loadFixture(path string, out *Fixture) error {
	if path == "" {
		return errors.New("fixture path is empty; set -fixture or -source=entra")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	return nil
}

// loadFromEntra is intentionally a thin wrapper. Example mode documents the
// shape by reading a fixture; production callers wire the actual Graph walk
// (list users, pull validators, enumerate group members) against
// portal/internal/entra. Leaving the hook in place keeps the CLI surface
// stable so operators can point -source=entra at a patched build.
func loadFromEntra(_ context.Context, _ *Fixture, logger *slog.Logger) error {
	logger.Warn("entra source is stub in the example script — flesh out loadFromEntra or use -source=file for bootstrap")
	return errors.New("entra source not implemented in example build; use -source=file")
}

// portalClient is a small convenience wrapper over the portal admin API —
// just enough to upsert users / set validators / upsert groups / reconcile
// membership. Not meant to be production-perfect (no retry, no concurrency);
// a real runbook handles those.
type portalClient struct {
	url    string
	token  string
	http   *http.Client
	dryRun bool
	logger *slog.Logger
}

// apply walks the fixture in dependency order:
//   1. ensure every group exists (so membership inserts don't 404)
//   2. ensure every user exists (creating when missing)
//   3. stamp validators (requires both users to exist)
//   4. reconcile membership for each group
func (c *portalClient) apply(ctx context.Context, fx Fixture) error {
	// Build lookups so we can do fewer round-trips than naive.
	existingUsers, err := c.listUsers(ctx)
	if err != nil {
		return err
	}
	existingGroups, err := c.listGroups(ctx)
	if err != nil {
		return err
	}

	// 1. Groups — create when missing, reconcile on drift (display_name,
	// external_id). Slug is the identity so a mismatch there would be a
	// different group entirely and falls into the "create" branch.
	groupBySlug := map[string]domain.Group{}
	for _, g := range existingGroups {
		groupBySlug[g.Slug] = g
	}
	for _, fg := range fx.Groups {
		existing, ok := groupBySlug[fg.Slug]
		if !ok {
			g, err := c.upsertGroup(ctx, fg, "")
			if err != nil {
				return fmt.Errorf("upsert group %s: %w", fg.Slug, err)
			}
			groupBySlug[fg.Slug] = g
			continue
		}
		if existing.DisplayName != fg.DisplayName || existing.ExternalID != fg.ExternalID {
			g, err := c.upsertGroup(ctx, fg, existing.ID)
			if err != nil {
				return fmt.Errorf("reconcile group %s: %w", fg.Slug, err)
			}
			groupBySlug[fg.Slug] = g
		}
	}

	// 2. Users — create when missing, reconcile scalar attrs on drift. We
	// deliberately only reconcile the attributes the fixture is authoritative
	// for (display_name, email, external_id, is_admin) and leave status /
	// validator alone; the validator link has its own pass below.
	userByUsername := map[string]domain.User{}
	for _, u := range existingUsers {
		userByUsername[u.Username] = u
	}
	for _, fu := range fx.Users {
		existing, ok := userByUsername[fu.Username]
		if !ok {
			u, err := c.createUser(ctx, fu)
			if err != nil {
				return fmt.Errorf("create user %s: %w", fu.Username, err)
			}
			userByUsername[fu.Username] = u
			continue
		}
		if userAttrsDrifted(existing, fu) {
			updated, err := c.patchUser(ctx, existing.ID, fu)
			if err != nil {
				return fmt.Errorf("patch user %s: %w", fu.Username, err)
			}
			userByUsername[fu.Username] = updated
		}
	}

	// 3. Validators. The fixture's `validator_username` field holds a
	// username (nicer for hand-written fixtures); resolve it to the portal id
	// before calling setValidator. Skip the call when the stored link already
	// matches — keeps syncs quiet and audit logs small.
	for _, fu := range fx.Users {
		me, ok := userByUsername[fu.Username]
		if !ok {
			continue
		}
		if fu.ValidatorUsername == "" {
			continue
		}
		mgr, ok := userByUsername[fu.ValidatorUsername]
		if !ok {
			c.logger.Warn("validator_not_in_fixture", "user", fu.Username, "validator", fu.ValidatorUsername)
			continue
		}
		if me.ValidatorUserID == mgr.ID {
			continue
		}
		if err := c.setValidator(ctx, me.ID, mgr.ID); err != nil {
			return fmt.Errorf("set validator %s -> %s: %w", fu.Username, fu.ValidatorUsername, err)
		}
	}

	// 4. Membership — pre-fetch current member sets per group so we only
	// POST when a user is actually missing. Pre-loading per-group is one
	// HTTP call per group (constant); the naive per-user loop did N calls
	// per user. Still O(users * groups) work in the fixture loop but no
	// redundant outbound writes.
	currentMembers := map[string]map[string]struct{}{}
	for slug, g := range groupBySlug {
		members, err := c.listGroupMembers(ctx, g.ID)
		if err != nil {
			return fmt.Errorf("list members %s: %w", slug, err)
		}
		set := make(map[string]struct{}, len(members))
		for _, m := range members {
			set[m.ID] = struct{}{}
		}
		currentMembers[g.ID] = set
	}
	for _, fu := range fx.Users {
		me, ok := userByUsername[fu.Username]
		if !ok {
			continue
		}
		for _, slug := range fu.Groups {
			g, ok := groupBySlug[slug]
			if !ok {
				c.logger.Warn("membership_group_missing", "user", fu.Username, "group", slug)
				continue
			}
			if _, already := currentMembers[g.ID][me.ID]; already {
				continue
			}
			if err := c.addMember(ctx, g.ID, me.ID); err != nil {
				return fmt.Errorf("add %s to %s: %w", fu.Username, slug, err)
			}
			// Keep the cache coherent so a re-run inside the same apply()
			// (not current usage but defence against future refactors)
			// doesn't re-post.
			if currentMembers[g.ID] == nil {
				currentMembers[g.ID] = map[string]struct{}{}
			}
			currentMembers[g.ID][me.ID] = struct{}{}
		}
	}
	return nil
}

// userAttrsDrifted reports whether the portal row disagrees with the fixture
// on any attribute the syncer is authoritative for. is_admin is intentionally
// excluded: the sync only promotes on CREATE and never touches the flag on
// PATCH, so drift on is_admin must not trigger a PATCH.
func userAttrsDrifted(existing domain.User, fu FixtureUser) bool {
	return existing.DisplayName != fu.DisplayName ||
		existing.Email != fu.Email ||
		existing.ExternalID != fu.ExternalID
}

// --- portal API glue (minimal) ---

func (c *portalClient) listUsers(ctx context.Context) ([]domain.User, error) {
	var out []domain.User
	if err := c.do(ctx, http.MethodGet, "/api/v1/users", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *portalClient) listGroups(ctx context.Context) ([]domain.Group, error) {
	var out []domain.Group
	if err := c.do(ctx, http.MethodGet, "/api/v1/groups", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *portalClient) createUser(ctx context.Context, fu FixtureUser) (domain.User, error) {
	body := map[string]any{
		"username":     fu.Username,
		"display_name": fu.DisplayName,
		"email":        fu.Email,
		"external_id":  fu.ExternalID,
		"is_admin":     fu.IsAdmin,
	}
	if c.dryRun {
		c.logger.Info("dry-run: create user", "username", fu.Username)
		return domain.User{ID: "dry-" + fu.Username, Username: fu.Username}, nil
	}
	var u domain.User
	if err := c.do(ctx, http.MethodPost, "/api/v1/users", body, &u); err != nil {
		return domain.User{}, err
	}
	return u, nil
}

// patchUser reconciles an existing user via PATCH /api/v1/users/{id}. Only
// fields the fixture is authoritative for are sent. is_admin is deliberately
// NOT patched: demotions through a cron job surprise operators who elevated
// someone through the UI, and promotions through the sync tend to be footguns
// too. Admin membership stays an explicit operator action via the portal.
func (c *portalClient) patchUser(ctx context.Context, userID string, fu FixtureUser) (domain.User, error) {
	body := map[string]any{
		"display_name": fu.DisplayName,
		"email":        fu.Email,
		"external_id":  fu.ExternalID,
	}
	if c.dryRun {
		c.logger.Info("dry-run: patch user", "user", userID, "username", fu.Username)
		return domain.User{ID: userID, Username: fu.Username}, nil
	}
	var u domain.User
	if err := c.do(ctx, http.MethodPatch, "/api/v1/users/"+userID, body, &u); err != nil {
		return domain.User{}, err
	}
	return u, nil
}

func (c *portalClient) listGroupMembers(ctx context.Context, groupID string) ([]domain.User, error) {
	var out []domain.User
	if err := c.do(ctx, http.MethodGet, "/api/v1/groups/"+groupID+"/members", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *portalClient) setValidator(ctx context.Context, userID, validatorID string) error {
	if c.dryRun {
		c.logger.Info("dry-run: set validator", "user", userID, "validator", validatorID)
		return nil
	}
	return c.do(ctx, http.MethodPut, "/api/v1/users/"+userID+"/validator",
		map[string]string{"validator_user_id": validatorID}, nil)
}

// upsertGroup creates a new group or (when id != "") reconciles an existing
// one. The portal's POST /api/v1/groups is a create-or-update that keys on
// body.id for the update path; we pass the existing id back so drift on
// display_name / external_id overwrites the row in place rather than trying
// to create a duplicate slug (which would 409).
func (c *portalClient) upsertGroup(ctx context.Context, fg FixtureGroup, id string) (domain.Group, error) {
	body := map[string]any{
		"slug":         fg.Slug,
		"display_name": fg.DisplayName,
		"external_id":  fg.ExternalID,
	}
	if id != "" {
		body["id"] = id
	}
	if c.dryRun {
		c.logger.Info("dry-run: upsert group", "slug", fg.Slug, "id", id)
		if id == "" {
			id = "dry-" + fg.Slug
		}
		return domain.Group{ID: id, Slug: fg.Slug}, nil
	}
	var g domain.Group
	if err := c.do(ctx, http.MethodPost, "/api/v1/groups", body, &g); err != nil {
		return domain.Group{}, err
	}
	return g, nil
}

func (c *portalClient) addMember(ctx context.Context, groupID, userID string) error {
	if c.dryRun {
		c.logger.Info("dry-run: add member", "group", groupID, "user", userID)
		return nil
	}
	return c.do(ctx, http.MethodPost, "/api/v1/groups/"+groupID+"/members/"+userID, nil, nil)
}

// do sends an HTTP request and decodes the response when dest != nil.
// Status < 300 is success; anything else becomes an error carrying the body.
func (c *portalClient) do(ctx context.Context, method, path string, body, dest any) error {
	var reader *jsonReader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = &jsonReader{data: raw}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.url+path, reader.reader())
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		buf, _ := readAll(resp.Body, 4096)
		return fmt.Errorf("%s %s: status %d: %s", method, path, resp.StatusCode, string(buf))
	}
	if dest != nil {
		if err := json.NewDecoder(resp.Body).Decode(dest); err != nil {
			return fmt.Errorf("decode %s %s: %w", method, path, err)
		}
	}
	return nil
}
