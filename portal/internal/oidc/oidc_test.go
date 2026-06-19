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
	// nonce captured from the most recent /authorize request, echoed back into
	// the minted ID token so the callback's nonce binding succeeds by default.
	lastNonce string
	// failure knobs (zero value = healthy IdP):
	signWithWrongKey bool      // sign the ID token with a key the JWKS doesn't publish
	tokenStatus      int       // if non-zero, /token responds with this status instead of a token
	authError        string    // if set, /authorize redirects back with ?error=<authError> and no code
	expOverride      time.Time // if non-zero, force the token `exp` to this instant
	dropNonce        bool      // if true, omit the nonce claim from the minted token
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
		// Capture the OIDC nonce so /token can echo it into the ID token.
		q := r.URL.Query()
		idp.lastNonce = q.Get("nonce")
		redir := q.Get("redirect_uri")
		state := q.Get("state")
		// Simulate an IdP-side error (e.g. user declined consent): bounce back
		// with ?error=... and no code, mirroring an RFC 6749 §4.1.2.1 response.
		if idp.authError != "" {
			loc := redir + "?error=" + url.QueryEscape(idp.authError) + "&state=" + url.QueryEscape(state)
			http.Redirect(w, r, loc, http.StatusFound)
			return
		}
		// Redirect back to the client's redirect_uri with code + state.
		loc := redir + "?code=" + url.QueryEscape(idp.code) + "&state=" + url.QueryEscape(state)
		http.Redirect(w, r, loc, http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		idp.tokenCalls++
		if idp.tokenStatus != 0 {
			http.Error(w, "scripted token failure", idp.tokenStatus)
			return
		}
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
		if idp.expOverride.IsZero() {
			claims["exp"] = time.Now().Add(10 * time.Minute).Unix()
		} else {
			claims["exp"] = idp.expOverride.Unix()
		}
		claims["iat"] = time.Now().Unix()
		// Echo the captured nonce by default so the callback's nonce binding
		// passes; dropNonce exercises the missing-nonce rejection path.
		if !idp.dropNonce && idp.lastNonce != "" {
			claims["nonce"] = idp.lastNonce
		}
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
	signKey := m.priv
	if m.signWithWrongKey {
		// Sign with a freshly-generated key whose public half is NOT in the
		// JWKS, so the verifier's signature check fails — exercises the bad
		// signature → 401 path. kid stays the published one so the verifier
		// selects the (wrong) key rather than rejecting on key lookup alone.
		wrong, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return "", err
		}
		signKey = wrong
	}
	sig, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: signKey},
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

// newTestProvider boots a Provider wired to idp plus a portal httptest server
// hosting /oidc/* with the redirect URL patched to that server. Returns the
// provider, the portal server, and a redirect-following cookie-aware client
// that stops at /ui/ (the SPA entry point, not mounted here).
func newTestProvider(t *testing.T, idp *mockIDP, mutate func(*Config)) (*Provider, *httptest.Server, *http.Client) {
	t.Helper()
	cfg := &Config{
		IssuerURL:    idp.issuer,
		ClientID:     "client-under-test",
		ClientSecret: "shh",
		RedirectURL:  "http://127.0.0.1:0/cb", // patched below
		AdminClaim:   "groups",
		AdminValue:   "dba",
	}
	if mutate != nil {
		mutate(cfg)
	}
	p, err := New(context.Background(), cfg, NewMemoryStore(), silentLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if p == nil {
		t.Fatal("provider is nil")
	}
	mux := http.NewServeMux()
	p.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	p.oauth2.RedirectURL = srv.URL + "/oidc/callback"
	p.cfg.RedirectURL = srv.URL + "/oidc/callback"

	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			if req.URL.Path == "/ui/" {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	return p, srv, client
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

	// Walk the flow with a cookie-aware client. The callback now ends with a
	// 302 to /ui/ (SPA entry point), which isn't mounted on this test server —
	// so we tell the client to stop following redirects there and inspect the
	// final hop directly.
	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Path == "/ui/" {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	// Step 1: /oidc/login — should redirect us to the IdP's /authorize.
	resp, err := client.Get(portalSrv.URL + "/oidc/login")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer resp.Body.Close()
	// Final hop is the callback's redirect to /ui/. The client stops following
	// once it sees that target, so we should see a 302 here.
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("login ended with status %d, want 302", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/ui/" {
		t.Errorf("callback Location=%q, want /ui/", loc)
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
	if !sess.IsOperator {
		t.Error("expected IsOperator=true for groups:[engineers,dba] with admin-value=dba")
	}
}

// fakeProvisioner lets tests assert what the callback persists for IsOperator
// and observe the claimIsAdmin value it forwards to the provisioner.
type fakeProvisioner struct {
	returnOperator bool
	gotClaimAdmin  bool
}

func (f *fakeProvisioner) ProvisionOIDCUser(_ context.Context, sub, _, _ string, claimIsAdmin bool) (string, bool, error) {
	f.gotClaimAdmin = claimIsAdmin
	return "puid-" + sub, f.returnOperator, nil
}

// Regression for the admin-flag-survives-relogin invariant documented at the
// UserProvisioner interface and handleCallback step 5: the *provisioner's*
// IsOperator is authoritative, not the IdP claim. Here the IdP claim says
// non-admin (groups lacks "dba") yet the provisioner returns operator=true —
// modelling an admin who was toggled on via the admin API. The session MUST be
// operator. The store-side persistence of that flag is owned by package api
// (oidc_provisioner.go) and is tested there; this guards the oidc-side contract
// that the callback trusts the provisioner over the claim.
func TestOIDC_Callback_ProvisionerOperatorOverridesClaim(t *testing.T) {
	idp := newMockIDP(t, func() map[string]any {
		return map[string]any{"sub": "u-9", "aud": "client-under-test", "groups": []string{"engineers"}}
	})
	p, srv, client := newTestProvider(t, idp, nil)
	fp := &fakeProvisioner{returnOperator: true}
	p.WithProvisioner(fp)

	resp, err := client.Get(srv.URL + "/oidc/login")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("login status=%d want 302", resp.StatusCode)
	}
	if fp.gotClaimAdmin {
		t.Error("claimIsAdmin should be false for groups:[engineers] with admin-value=dba")
	}

	u, _ := url.Parse(srv.URL)
	var sid string
	for _, c := range client.Jar.Cookies(u) {
		if c.Name == "portal_session" {
			sid = c.Value
		}
	}
	if sid == "" {
		t.Fatal("no session cookie set")
	}
	sess, ok := p.store.Get(sid)
	if !ok {
		t.Fatal("session not in store")
	}
	if !sess.IsOperator {
		t.Error("provisioner returned operator=true but session IsOperator=false")
	}
}

// Without a state cookie AND without a session cookie, the callback handler
// can't move the user forward. It used to return 400 "missing state cookie",
// which is technically correct but surfaces every time a user pastes a stale
// callback URL or uses the browser's back button after success. The friendly
// behaviour is a 302 to /oidc/login: the next round-trip mints a fresh state
// nonce and the user resumes login without seeing an error.
func TestOIDC_Callback_NoStateCookie_RedirectsToLogin(t *testing.T) {
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

	// Don't follow redirects so we can inspect the bounce target directly.
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get(srv.URL + "/oidc/callback?code=x&state=y")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Errorf("no-state-cookie status=%d want 302", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/oidc/login" {
		t.Errorf("no-state-cookie Location=%q want /oidc/login", loc)
	}
}

// loginCookies drives /oidc/login (without following the IdP redirect) and
// returns the state + nonce cookies the handler set, so callback tests can
// craft a request that passes the CSRF gate but fails further down.
func loginCookies(t *testing.T, srv *httptest.Server) (state, nonce string) {
	t.Helper()
	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := noFollow.Get(srv.URL + "/oidc/login")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	for _, c := range resp.Cookies() {
		switch c.Name {
		case "portal_session_state":
			state = c.Value
		case "portal_session_nonce":
			nonce = c.Value
		}
	}
	if state == "" || nonce == "" {
		t.Fatalf("login did not set state(%q)+nonce(%q) cookies", state, nonce)
	}
	return state, nonce
}

// H13: the CSRF state-mismatch branch (subtle.ConstantTimeCompare) must 400.
func TestOIDC_Callback_StateMismatch_400(t *testing.T) {
	idp := newMockIDP(t, func() map[string]any { return map[string]any{"sub": "x", "aud": "client-under-test"} })
	_, srv, _ := newTestProvider(t, idp, nil)

	state, _ := loginCookies(t, srv)

	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/oidc/callback?code=mock-auth-code&state=not-"+state, nil)
	// Supply the real state cookie but a mismatched ?state= query value.
	req.AddCookie(&http.Cookie{Name: "portal_session_state", Value: state})
	resp, err := noFollow.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "state mismatch") {
		t.Errorf("body=%q want to contain %q", body, "state mismatch")
	}
}

// H14: id_token verification failures must surface as 401. Drives the mock IdP
// to mint a bad-signature / wrong-aud / expired token. The wrong-aud and
// expired tokens are correctly signed but fail the verifier's claim checks.
func TestOIDC_Callback_TokenVerifyFailures_401(t *testing.T) {
	cases := []struct {
		name   string
		claims map[string]any
		setup  func(*mockIDP)
	}{
		{
			name:   "bad signature",
			claims: map[string]any{"sub": "u", "aud": "client-under-test"},
			setup:  func(m *mockIDP) { m.signWithWrongKey = true },
		},
		{
			name:   "wrong audience",
			claims: map[string]any{"sub": "u", "aud": "some-other-client"},
		},
		{
			name:   "expired token",
			claims: map[string]any{"sub": "u", "aud": "client-under-test"},
			setup:  func(m *mockIDP) { m.expOverride = time.Now().Add(-1 * time.Hour) },
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			idp := newMockIDP(t, func() map[string]any {
				out := map[string]any{}
				for k, v := range tc.claims {
					out[k] = v
				}
				return out
			})
			if tc.setup != nil {
				tc.setup(idp)
			}
			_, srv, client := newTestProvider(t, idp, nil)
			resp, err := client.Get(srv.URL + "/oidc/login")
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized {
				body, _ := io.ReadAll(resp.Body)
				t.Fatalf("status=%d want 401 (body=%q)", resp.StatusCode, body)
			}
		})
	}
}

// M3: a token whose nonce claim doesn't match the issued nonce cookie must 401,
// proving the nonce binding actually rejects replayed/injected tokens.
func TestOIDC_Callback_NonceMismatch_401(t *testing.T) {
	idp := newMockIDP(t, func() map[string]any {
		return map[string]any{"sub": "u", "aud": "client-under-test"}
	})
	idp.dropNonce = true // token carries no nonce → mismatch against the cookie
	_, srv, client := newTestProvider(t, idp, nil)
	resp, err := client.Get(srv.URL + "/oidc/login")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 401 (body=%q)", resp.StatusCode, body)
	}
}

// M14: an IdP that redirects back with ?error=... (no code) must surface 400.
func TestOIDC_Callback_IdPError_400(t *testing.T) {
	idp := newMockIDP(t, func() map[string]any { return map[string]any{"sub": "u", "aud": "client-under-test"} })
	idp.authError = "access_denied"
	_, srv, client := newTestProvider(t, idp, nil)
	resp, err := client.Get(srv.URL + "/oidc/login")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 400 (body=%q)", resp.StatusCode, body)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "access_denied") {
		t.Errorf("body=%q want to contain %q", body, "access_denied")
	}
}

// M14: a token endpoint returning 5xx makes Exchange fail → 502 BadGateway.
func TestOIDC_Callback_TokenEndpoint5xx_502(t *testing.T) {
	idp := newMockIDP(t, func() map[string]any { return map[string]any{"sub": "u", "aud": "client-under-test"} })
	idp.tokenStatus = http.StatusInternalServerError
	_, srv, client := newTestProvider(t, idp, nil)
	resp, err := client.Get(srv.URL + "/oidc/login")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 502 (body=%q)", resp.StatusCode, body)
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
	// Over-broad cookie domains must be rejected; explicit domains accepted.
	for _, bad := range []string{"*", ".", ".."} {
		cfg = &Config{IssuerURL: "https://a", ClientID: "x", ClientSecret: "s", RedirectURL: "https://b", CookieDomain: bad}
		if err := cfg.Validate(); err == nil {
			t.Errorf("cookie domain %q should be rejected", bad)
		}
	}
	cfg = &Config{IssuerURL: "https://a", ClientID: "x", ClientSecret: "s", RedirectURL: "https://b", CookieDomain: ".example.com"}
	if err := cfg.Validate(); err != nil {
		t.Errorf("explicit parent-domain cookie should be accepted: %v", err)
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
