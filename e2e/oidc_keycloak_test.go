//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/babs/poc-proxies/portal"
)

// TestOIDC_KeycloakE2E walks a real login→callback→grants-list flow against a
// Keycloak container. Covers the Phase 2.3 AC:
//   - admin user logs in, Session.IsAdmin=true, can list all grants,
//   - plain user logs in, Session.IsAdmin=false, list is scoped to their own,
//     /approve returns 403.
//
// Skipped cleanly when the docker socket isn't reachable.
func TestOIDC_KeycloakE2E(t *testing.T) {
	skipIfNoDocker(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	const (
		kcAdminUser = "admin"
		kcAdminPass = "admin"
		realmName   = "portal-test"
		clientID    = "portal"
		clientPW    = "portal-secret"
		adminUser   = "kc-admin"
		adminPW     = "admin-pw"
		plainUser   = "kc-plain"
		plainPW     = "plain-pw"
	)

	// Reserve a local TCP port for the portal so the redirect URL registered
	// with Keycloak matches what the portal later listens on. Keycloak
	// validates redirect_uri strictly, so we can't afford to find out the URL
	// after the client is created.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	portalURL := "http://" + ln.Addr().String()
	redirectURI := portalURL + "/oidc/callback"

	// Boot Keycloak in dev mode.
	kc, err := testcontainers.Run(ctx, "quay.io/keycloak/keycloak:26.0",
		testcontainers.WithExposedPorts("8080/tcp"),
		testcontainers.WithEnv(map[string]string{
			"KC_BOOTSTRAP_ADMIN_USERNAME": kcAdminUser,
			"KC_BOOTSTRAP_ADMIN_PASSWORD": kcAdminPass,
		}),
		testcontainers.WithCmd("start-dev"),
		testcontainers.WithWaitStrategy(
			wait.ForHTTP("/realms/master").
				WithPort("8080/tcp").
				WithStatusCodeMatcher(func(status int) bool { return status == http.StatusOK }).
				WithStartupTimeout(4*time.Minute),
		),
	)
	if err != nil {
		_ = ln.Close()
		t.Skipf("keycloak testcontainer unavailable: %v", err)
	}
	t.Cleanup(func() {
		cctx, cc := context.WithTimeout(context.Background(), 30*time.Second)
		defer cc()
		_ = testcontainers.TerminateContainer(kc, testcontainers.StopContext(cctx))
	})

	host, err := kc.Host(ctx)
	if err != nil {
		t.Fatalf("kc host: %v", err)
	}
	port, err := kc.MappedPort(ctx, "8080/tcp")
	if err != nil {
		t.Fatalf("kc port: %v", err)
	}
	issuerBase := fmt.Sprintf("http://%s:%s", host, port.Port())
	issuer := issuerBase + "/realms/" + realmName

	// Seed realm + client + users + group mapper via the admin REST API.
	admTok := kcAdminToken(t, issuerBase, kcAdminUser, kcAdminPass)
	kcCreateRealm(t, ctx, issuerBase, admTok, realmName)
	kcCreateClient(t, ctx, issuerBase, admTok, realmName, clientID, clientPW, redirectURI)
	kcCreateGroup(t, ctx, issuerBase, admTok, realmName, "dba")
	kcCreateUser(t, ctx, issuerBase, admTok, realmName, adminUser, adminPW, "admin@example.com", []string{"dba"})
	kcCreateUser(t, ctx, issuerBase, admTok, realmName, plainUser, plainPW, "plain@example.com", nil)
	kcAddGroupMapper(t, ctx, issuerBase, admTok, realmName, clientID)

	// Build the portal with OIDC wired to the Keycloak realm.
	cfg := &portal.Config{}
	s := portal.NewMemoryStore()
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))

	discCtx, discCancel := context.WithTimeout(ctx, 30*time.Second)
	oidcCfg := &portal.OIDCConfig{
		IssuerURL:    issuer,
		ClientID:     clientID,
		ClientSecret: clientPW,
		RedirectURL:  redirectURI,
		AdminClaim:   "groups",
		AdminValue:   "dba",
	}
	provider, err := portal.NewOIDCProvider(discCtx, oidcCfg, s, logger)
	discCancel()
	if err != nil {
		_ = ln.Close()
		t.Fatalf("portal oidc provider: %v", err)
	}
	handler := portal.NewHandlerWithOIDC(cfg, s, provider, logger)

	// Serve the portal on the reserved listener.
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		shutCtx, sc := context.WithTimeout(context.Background(), 5*time.Second)
		defer sc()
		_ = srv.Shutdown(shutCtx)
	})

	// --- admin login + list ---

	adminJar, _ := cookiejar.New(nil)
	adminClient := &http.Client{Jar: adminJar, Timeout: 30 * time.Second}
	oidcLogin(t, adminClient, portalURL, adminUser, adminPW)
	adminGrants := httpGetJSONArray(t, adminClient, portalURL+"/api/v1/grants")
	if adminGrants == nil {
		t.Fatal("admin grants list returned nil (should be [] or populated)")
	}

	// --- plain user login + list (scoped to self) ---

	plainJar, _ := cookiejar.New(nil)
	plainClient := &http.Client{Jar: plainJar, Timeout: 30 * time.Second}
	oidcLogin(t, plainClient, portalURL, plainUser, plainPW)
	plainGrants := httpGetJSONArray(t, plainClient, portalURL+"/api/v1/grants")
	if plainGrants == nil {
		t.Fatal("plain grants list returned nil")
	}

	// --- provisioning assertions ---

	adminU, err := s.GetUserByUsername(ctx, adminUser)
	if err != nil {
		t.Fatalf("admin user not provisioned: %v", err)
	}
	if adminU.ExternalID == "" {
		t.Error("admin user missing ExternalID (OIDC sub)")
	}
	if !adminU.IsAdmin {
		t.Errorf("admin user IsAdmin=false (expected true via groups:dba mapping)")
	}
	plainU, err := s.GetUserByUsername(ctx, plainUser)
	if err != nil {
		t.Fatalf("plain user not provisioned: %v", err)
	}
	if plainU.IsAdmin {
		t.Errorf("plain user wrongly flagged IsAdmin=true")
	}

	// --- admin-only endpoint rejects non-admin session ---

	// Seed a PENDING grant so approve is reachable.
	now := time.Now().UTC()
	b := portal.Backend{ID: "b-oidc", Name: "m", Type: "mongo", Host: "127.0.0.1", Port: 27099, CreatedAt: now, UpdatedAt: now}
	_ = s.CreateBackend(ctx, b)
	g := portal.Grant{
		ID: "g-oidc-pending", UserID: plainU.ID, BackendID: b.ID,
		Role: "app", Status: "PENDING", RequestedAt: now, CreatedAt: now, UpdatedAt: now,
	}
	_ = s.CreateGrant(ctx, g)

	req, _ := http.NewRequest(http.MethodPost, portalURL+"/api/v1/grants/"+g.ID+"/approve", nil)
	resp, err := plainClient.Do(req)
	if err != nil {
		t.Fatalf("plain approve: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("plain user approve expected 403, got %d", resp.StatusCode)
	}

	// Admin can approve.
	req2, _ := http.NewRequest(http.MethodPost, portalURL+"/api/v1/grants/"+g.ID+"/approve", nil)
	resp2, err := adminClient.Do(req2)
	if err != nil {
		t.Fatalf("admin approve: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp2.Body)
		t.Fatalf("admin approve status=%d body=%s", resp2.StatusCode, body)
	}
}

// --- helpers ---

// oidcLogin walks the /oidc/login → Keycloak form → /oidc/callback chain using
// the provided cookie-aware client. Keycloak's login page is a plain HTML form
// we POST with username+password; success yields a redirect back to the
// portal's callback which the client follows automatically.
func oidcLogin(t *testing.T, client *http.Client, portalURL, user, pw string) {
	t.Helper()
	resp, err := client.Get(portalURL + "/oidc/login")
	if err != nil {
		t.Fatalf("oidc login: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	actionURL := extractFormAction(string(body))
	if actionURL == "" {
		t.Fatalf("no form action in keycloak login page: %s", string(body))
	}
	form := url.Values{"username": {user}, "password": {pw}, "credentialId": {""}}
	resp2, err := client.PostForm(actionURL, form)
	if err != nil {
		t.Fatalf("kc credentials post: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode >= 400 {
		b, _ := io.ReadAll(resp2.Body)
		t.Fatalf("kc login status=%d body=%s", resp2.StatusCode, string(b))
	}
	// Final body should be the portal's callback JSON — if it's the KC login
	// page again the credentials bounced, surface a readable failure.
	final, _ := io.ReadAll(resp2.Body)
	if !strings.Contains(string(final), "subject") {
		t.Fatalf("callback did not reach portal (final url=%s body=%s)", resp2.Request.URL, string(final))
	}
}

// extractFormAction finds the first <form action="..."> URL in the Keycloak
// login page HTML. Avoids pulling in a parser for this one-shot scrape.
func extractFormAction(html string) string {
	i := strings.Index(html, "<form")
	if i < 0 {
		return ""
	}
	j := strings.Index(html[i:], "action=\"")
	if j < 0 {
		return ""
	}
	start := i + j + len("action=\"")
	end := strings.Index(html[start:], "\"")
	if end < 0 {
		return ""
	}
	raw := html[start : start+end]
	return strings.NewReplacer("&amp;", "&").Replace(raw)
}

func httpGetJSONArray(t *testing.T, client *http.Client, u string) []map[string]any {
	t.Helper()
	resp, err := client.Get(u)
	if err != nil {
		t.Fatalf("GET %s: %v", u, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET %s status=%d body=%s", u, resp.StatusCode, body)
	}
	var out []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode %s: %v", u, err)
	}
	if out == nil {
		out = []map[string]any{}
	}
	return out
}

// --- keycloak admin REST helpers ---

func kcAdminToken(t *testing.T, base, user, pw string) string {
	t.Helper()
	form := url.Values{
		"client_id":  {"admin-cli"},
		"grant_type": {"password"},
		"username":   {user},
		"password":   {pw},
	}
	resp, err := http.PostForm(base+"/realms/master/protocol/openid-connect/token", form)
	if err != nil {
		t.Fatalf("kc admin token: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("kc admin token status=%d body=%s", resp.StatusCode, string(b))
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&tok)
	if tok.AccessToken == "" {
		t.Fatal("empty kc admin token")
	}
	return tok.AccessToken
}

func kcCreateRealm(t *testing.T, ctx context.Context, base, tok, realm string) {
	kcPOST(t, ctx, base+"/admin/realms", tok, map[string]any{
		"realm":   realm,
		"enabled": true,
	}, http.StatusCreated, http.StatusConflict)
}

func kcCreateClient(t *testing.T, ctx context.Context, base, tok, realm, clientID, secret, redirect string) {
	kcPOST(t, ctx, fmt.Sprintf("%s/admin/realms/%s/clients", base, realm), tok, map[string]any{
		"clientId":                  clientID,
		"secret":                    secret,
		"enabled":                   true,
		"protocol":                  "openid-connect",
		"publicClient":              false,
		"standardFlowEnabled":       true,
		"directAccessGrantsEnabled": true,
		"redirectUris":              []string{redirect},
		"webOrigins":                []string{"*"},
	}, http.StatusCreated, http.StatusConflict)
}

func kcCreateGroup(t *testing.T, ctx context.Context, base, tok, realm, name string) {
	kcPOST(t, ctx, fmt.Sprintf("%s/admin/realms/%s/groups", base, realm), tok, map[string]any{
		"name": name,
	}, http.StatusCreated, http.StatusConflict)
}

func kcCreateUser(t *testing.T, ctx context.Context, base, tok, realm, uname, pw, email string, groups []string) {
	t.Helper()
	payload := map[string]any{
		"username":      uname,
		"email":         email,
		"emailVerified": true,
		"enabled":       true,
		// firstName/lastName satisfy Keycloak 26's default user profile
		// requirements — without them Keycloak redirects login to an
		// "update profile" form that our headless client can't complete.
		"firstName": uname,
		"lastName":  "Tester",
		"credentials": []map[string]any{
			{"type": "password", "value": pw, "temporary": false},
		},
		"groups":          groups,
		"requiredActions": []string{},
	}
	kcPOST(t, ctx, fmt.Sprintf("%s/admin/realms/%s/users", base, realm), tok, payload, http.StatusCreated, http.StatusConflict)
}

// kcAddGroupMapper wires a `groups` claim into the client's ID token so the
// portal's AdminClaim="groups" admin-check actually sees realm group membership.
func kcAddGroupMapper(t *testing.T, ctx context.Context, base, tok, realm, clientID string) {
	t.Helper()
	id := kcClientInternalID(t, ctx, base, tok, realm, clientID)
	kcPOST(t, ctx, fmt.Sprintf("%s/admin/realms/%s/clients/%s/protocol-mappers/models", base, realm, id), tok, map[string]any{
		"name":           "groups",
		"protocol":       "openid-connect",
		"protocolMapper": "oidc-group-membership-mapper",
		"config": map[string]string{
			"claim.name":           "groups",
			"full.path":            "false",
			"id.token.claim":       "true",
			"access.token.claim":   "true",
			"userinfo.token.claim": "true",
		},
	}, http.StatusCreated, http.StatusConflict)
}

func kcClientInternalID(t *testing.T, ctx context.Context, base, tok, realm, clientID string) string {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("%s/admin/realms/%s/clients?clientId=%s", base, realm, url.QueryEscape(clientID)), nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("kc list clients: %v", err)
	}
	defer resp.Body.Close()
	var arr []struct {
		ID       string `json:"id"`
		ClientID string `json:"clientId"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&arr)
	for _, c := range arr {
		if c.ClientID == clientID {
			return c.ID
		}
	}
	t.Fatalf("client %s not found", clientID)
	return ""
}

func kcPOST(t *testing.T, ctx context.Context, url, tok string, payload any, okStatuses ...int) {
	t.Helper()
	raw, _ := json.Marshal(payload)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(string(raw)))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer resp.Body.Close()
	for _, ok := range okStatuses {
		if resp.StatusCode == ok {
			return
		}
	}
	body, _ := io.ReadAll(resp.Body)
	t.Fatalf("POST %s status=%d body=%s", url, resp.StatusCode, string(body))
}
