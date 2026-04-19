package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// --- mock OIDC provider ---

type mockIDP struct {
	srv    *httptest.Server
	priv   *rsa.PrivateKey
	kid    string
	issuer string
	// scripted state
	code       string
	claimsFn   func() map[string]any
	tokenCalls int
}

func newMockIDP(t *testing.T, claimsFn func() map[string]any) *mockIDP {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	idp := &mockIDP{
		priv:     priv,
		kid:      "test-kid",
		code:     "mock-auth-code",
		claimsFn: claimsFn,
	}
	srv := httptest.NewServer(mux)
	idp.srv = srv
	idp.issuer = srv.URL

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                idp.issuer,
			"authorization_endpoint":                idp.issuer + "/authorize",
			"token_endpoint":                        idp.issuer + "/token",
			"jwks_uri":                              idp.issuer + "/jwks",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		jwk := jose.JSONWebKey{Key: &priv.PublicKey, KeyID: idp.kid, Algorithm: "RS256", Use: "sig"}
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		// Redirect back to the client's redirect_uri with code + state.
		q := r.URL.Query()
		redir := q.Get("redirect_uri")
		state := q.Get("state")
		loc := redir + "?code=" + url.QueryEscape(idp.code) + "&state=" + url.QueryEscape(state)
		http.Redirect(w, r, loc, http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		idp.tokenCalls++
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if r.Form.Get("code") != idp.code {
			http.Error(w, "bad code", http.StatusBadRequest)
			return
		}
		claims := idp.claimsFn()
		claims["iss"] = idp.issuer
		claims["exp"] = time.Now().Add(10 * time.Minute).Unix()
		claims["iat"] = time.Now().Unix()
		idToken, err := idp.signToken(claims)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "mock-access",
			"token_type":   "Bearer",
			"expires_in":   600,
			"id_token":     idToken,
		})
	})
	t.Cleanup(srv.Close)
	return idp
}

func (m *mockIDP) signToken(claims map[string]any) (string, error) {
	sig, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: m.priv},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", m.kid),
	)
	if err != nil {
		return "", err
	}
	return jwt.Signed(sig).Claims(claims).Serialize()
}

// --- tests ---

func silentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestOIDC_LoginCallbackFlow_Success(t *testing.T) {
	idp := newMockIDP(t, func() map[string]any {
		return map[string]any{
			"sub":    "user-123",
			"email":  "alice@example.com",
			"name":   "Alice",
			"aud":    "client-under-test",
			"groups": []string{"engineers", "dba"},
		}
	})

	cfg := &Config{
		IssuerURL:    idp.issuer,
		ClientID:     "client-under-test",
		ClientSecret: "shh",
		RedirectURL:  "http://127.0.0.1:0/cb", // overwritten below
		AdminClaim:   "groups",
		AdminValue:   "dba",
	}
	store := NewMemoryStore()
	p, err := New(context.Background(), cfg, store, silentLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if p == nil {
		t.Fatal("provider is nil")
	}

	// Boot the portal-side OIDC endpoints on an ephemeral host.
	portalMux := http.NewServeMux()
	p.RegisterRoutes(portalMux)
	portalSrv := httptest.NewServer(portalMux)
	defer portalSrv.Close()

	// Patch the redirect URL to the actual portal test URL and re-init provider.
	p.oauth2.RedirectURL = portalSrv.URL + "/oidc/callback"
	p.cfg.RedirectURL = portalSrv.URL + "/oidc/callback"

	// Walk the flow with a cookie-aware client that doesn't auto-follow the
	// final callback redirect (we want to inspect the session cookie set on
	// the callback response, not whatever Location header it points at).
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}

	// Step 1: /oidc/login — should redirect us to the IdP's /authorize.
	resp, err := client.Get(portalSrv.URL + "/oidc/login")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login ended with status %d", resp.StatusCode)
	}

	// After the full redirect chain, the client should have the session cookie.
	u, _ := url.Parse(portalSrv.URL)
	var sessionCookie *http.Cookie
	for _, c := range jar.Cookies(u) {
		if c.Name == "portal_session" {
			sessionCookie = c
		}
	}
	if sessionCookie == nil || sessionCookie.Value == "" {
		t.Fatalf("no portal_session cookie set; jar: %+v", jar.Cookies(u))
	}

	// Look up the session in the store to confirm admin resolution + subject.
	sess, ok := store.Get(sessionCookie.Value)
	if !ok {
		t.Fatal("session not in store")
	}
	if sess.Subject != "user-123" {
		t.Errorf("subject=%q", sess.Subject)
	}
	if sess.Email != "alice@example.com" {
		t.Errorf("email=%q", sess.Email)
	}
	if !sess.IsAdmin {
		t.Error("expected IsAdmin=true for groups:[engineers,dba] with admin-value=dba")
	}
}

func TestOIDC_Callback_StateMismatchRejected(t *testing.T) {
	idp := newMockIDP(t, func() map[string]any {
		return map[string]any{"sub": "x", "aud": "c"}
	})
	cfg := &Config{IssuerURL: idp.issuer, ClientID: "c", ClientSecret: "s", RedirectURL: "http://x/cb"}
	p, err := New(context.Background(), cfg, NewMemoryStore(), silentLogger())
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	p.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// Request with no state cookie set.
	resp, err := http.Get(srv.URL + "/oidc/callback?code=x&state=y")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("no-state-cookie status=%d want 400", resp.StatusCode)
	}
}

func TestOIDC_Logout_RequiresPOST(t *testing.T) {
	idp := newMockIDP(t, func() map[string]any { return map[string]any{"sub": "x", "aud": "c"} })
	cfg := &Config{IssuerURL: idp.issuer, ClientID: "c", ClientSecret: "s", RedirectURL: "http://x/cb"}
	p, err := New(context.Background(), cfg, NewMemoryStore(), silentLogger())
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	p.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// GET /oidc/logout must 405 — defence against cross-site top-level GETs
	// that would otherwise log an authenticated user out.
	resp, err := http.Get(srv.URL + "/oidc/logout")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET /oidc/logout status=%d want 405", resp.StatusCode)
	}
	if resp.Header.Get("Allow") != "POST" {
		t.Errorf("Allow header=%q want POST", resp.Header.Get("Allow"))
	}

	// POST variant clears the cookie and returns 204.
	resp2, err := http.Post(srv.URL+"/oidc/logout", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusNoContent {
		t.Errorf("POST /oidc/logout status=%d want 204", resp2.StatusCode)
	}
}

func TestOIDC_Disabled_NewReturnsNil(t *testing.T) {
	p, err := New(context.Background(), &Config{}, NewMemoryStore(), silentLogger())
	if err != nil {
		t.Fatal(err)
	}
	if p != nil {
		t.Fatal("expected nil provider when IssuerURL empty")
	}
}

func TestOIDC_ConfigValidation(t *testing.T) {
	// Non-enabled: Validate is a no-op.
	if err := (&Config{}).Validate(); err != nil {
		t.Errorf("non-enabled: %v", err)
	}
	// Enabled but missing secret.
	cfg := &Config{IssuerURL: "https://a", ClientID: "x", RedirectURL: "https://b"}
	if err := cfg.Validate(); err == nil {
		t.Error("missing secret should fail")
	}
	// Admin claim set without value.
	cfg = &Config{IssuerURL: "https://a", ClientID: "x", ClientSecret: "s", RedirectURL: "https://b", AdminClaim: "groups"}
	if err := cfg.Validate(); err == nil {
		t.Error("admin claim without value should fail")
	}
}

func TestSessionStore_Expiry(t *testing.T) {
	store := NewMemoryStore()
	now := time.Now()

	alive := Session{ID: "a", Subject: "a", ExpiresAt: now.Add(1 * time.Hour)}
	dead := Session{ID: "d", Subject: "d", ExpiresAt: now.Add(-1 * time.Hour)}
	_ = store.Create(alive)
	_ = store.Create(dead)

	if _, ok := store.Get("a"); !ok {
		t.Error("alive session missing")
	}
	if got := store.SweepExpired(now); got != 1 {
		t.Errorf("swept=%d want 1", got)
	}
	if _, ok := store.Get("d"); ok {
		t.Error("dead session still present after sweep")
	}
}

func TestClaimContains(t *testing.T) {
	cases := []struct {
		name   string
		claims map[string]any
		key    string
		value  string
		want   bool
	}{
		{"string match", map[string]any{"role": "admin"}, "role", "admin", true},
		{"string miss", map[string]any{"role": "user"}, "role", "admin", false},
		{"[]string match", map[string]any{"g": []string{"a", "b"}}, "g", "b", true},
		{"[]any match", map[string]any{"g": []any{"a", "b"}}, "g", "a", true},
		{"missing key", map[string]any{}, "g", "x", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := claimContains(tc.claims, tc.key, tc.value)
			if got != tc.want {
				t.Errorf("got=%v want=%v", got, tc.want)
			}
		})
	}
}

// Sanity: make sure the mock issuer produces a parseable discovery doc.
func TestMockIdP_DiscoveryParses(t *testing.T) {
	idp := newMockIDP(t, func() map[string]any { return map[string]any{"sub": "s", "aud": "c"} })
	resp, err := http.Get(idp.issuer + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `"issuer"`) {
		t.Errorf("bad discovery: %s", body)
	}
}

// Tiny helper to avoid go-jose churn when the signature import changes.
var _ = fmt.Sprintf
