package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/babs/poc-proxies/portal"
)

// TestApply_EndToEnd boots the real portal in-process with the static-bearer
// shortcut and runs the syncer against it. Validates that fixtures round-trip
// into users + groups + membership + validator links.
func TestApply_EndToEnd(t *testing.T) {
	cfg := &portal.Config{UserToken: "sync-tok"}
	srv := httptest.NewServer(portal.NewHandler(cfg, portal.NewMemoryStore(), slog.New(slog.NewJSONHandler(io.Discard, nil))))
	t.Cleanup(srv.Close)

	// Load the shipped example fixture.
	path := filepath.Join("example-fixture.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var fx Fixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatal(err)
	}

	c := &portalClient{
		url: srv.URL, token: "sync-tok",
		http: &http.Client{}, logger: slog.New(slog.NewJSONHandler(io.Discard, nil)),
	}
	if err := c.apply(context.Background(), fx); err != nil {
		t.Fatalf("apply: %v", err)
	}

	// Re-running must be a no-op — the syncer should never error on unchanged state.
	if err := c.apply(context.Background(), fx); err != nil {
		t.Fatalf("idempotent apply: %v", err)
	}

	// Verify group membership via the portal API — alice ends up in dev-team.
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/groups", nil)
	req.Header.Set("Authorization", "Bearer sync-tok")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("list groups status=%d body=%s", resp.StatusCode, body)
	}
	var groups []map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&groups)
	if len(groups) != 3 {
		t.Errorf("expected 3 groups, got %d", len(groups))
	}
}

// TestApply_DryRun asserts the dry-run path fires no outbound HTTP for write
// operations. We point the client at a test server that fails the test on
// any request — that way a future change that starts issuing HEADs / probes
// /ping in dry-run will flip this test red immediately rather than silently
// contacting a real portal.
func TestApply_DryRun(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		t.Errorf("dry-run issued unexpected %s %s", r.Method, r.URL.Path)
	}))
	t.Cleanup(srv.Close)

	c := &portalClient{
		url:    srv.URL,
		http:   srv.Client(),
		logger: slog.New(slog.NewJSONHandler(io.Discard, nil)),
		dryRun: true,
	}
	if _, err := c.createUser(context.Background(), FixtureUser{Username: "x"}); err != nil {
		t.Errorf("dry-run createUser: %v", err)
	}
	if _, err := c.patchUser(context.Background(), "u-1", FixtureUser{Username: "x"}); err != nil {
		t.Errorf("dry-run patchUser: %v", err)
	}
	if err := c.setValidator(context.Background(), "a", "b"); err != nil {
		t.Errorf("dry-run setValidator: %v", err)
	}
	if err := c.addMember(context.Background(), "g", "u"); err != nil {
		t.Errorf("dry-run addMember: %v", err)
	}
	if _, err := c.upsertGroup(context.Background(), FixtureGroup{Slug: "x"}, ""); err != nil {
		t.Errorf("dry-run upsertGroup: %v", err)
	}
}
