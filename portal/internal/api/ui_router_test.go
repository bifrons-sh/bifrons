package api

import (
	"net/http"
	"testing"

	"github.com/babs/poc-proxies/portal/internal/config"
)

// TestUIMount_Unauthenticated_Rejects exercises the UI mount with a static
// bearer guard configured but no matching credential on the request. Browsers
// can't attach an Authorization header on plain navigations, so with OIDC
// absent the only correct response is a JSON 401. The OIDC-backed redirect
// branch is exercised end-to-end by portal/internal/oidc/oidc_test.go.
func TestUIMount_Unauthenticated_Rejects(t *testing.T) {
	cfg := &config.Config{UserToken: "api-tok"}
	srv, _ := newTestPortal(t, cfg)

	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get(srv.URL + "/ui/")
	if err != nil {
		t.Fatalf("get /ui/: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("want 401 without credentials, got %d", resp.StatusCode)
	}
}

// TestRootRedirectsToUI confirms the "/" → "/ui/" convenience hop.
func TestRootRedirectsToUI(t *testing.T) {
	cfg := &config.Config{}
	srv, _ := newTestPortal(t, cfg)

	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("get /: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("want 302, got %d", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/ui/" {
		t.Errorf("Location = %q, want /ui/", loc)
	}
}

// TestUIServesIndex_WhenOpen: with neither OIDC provider nor static bearer
// configured (local-dev shortcut), the UI mount serves the placeholder HTML
// under the strict security headers spec'd for the operator surface.
func TestUIServesIndex_WhenOpen(t *testing.T) {
	cfg := &config.Config{}
	srv, _ := newTestPortal(t, cfg)

	resp, err := http.Get(srv.URL + "/ui/")
	if err != nil {
		t.Fatalf("get /ui/: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Security-Policy"); got == "" {
		t.Errorf("CSP header missing")
	}
	if got := resp.Header.Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("X-Frame-Options = %q, want DENY", got)
	}
}

// TestSessionEndpoint_ReturnsBearerIdentity covers the new /api/v1/session
// route via the static-bearer guard. OIDC-session coverage lives next to the
// OIDC end-to-end test so we don't have to stand up a real IdP here.
func TestSessionEndpoint_ReturnsBearerIdentity(t *testing.T) {
	cfg := &config.Config{UserToken: "api-tok"}
	srv, _ := newTestPortal(t, cfg)

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/session", nil)
	req.Header.Set("Authorization", "Bearer api-tok")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

// TestBackendsList_AnyAuthenticatedCaller verifies that a non-admin path can
// still list the fleet — the UI backend view doesn't need admin privileges.
func TestBackendsList_AnyAuthenticatedCaller(t *testing.T) {
	cfg := &config.Config{UserToken: "api-tok"}
	srv, _ := newTestPortal(t, cfg)

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/backends", nil)
	req.Header.Set("Authorization", "Bearer api-tok")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("list backends: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
}
