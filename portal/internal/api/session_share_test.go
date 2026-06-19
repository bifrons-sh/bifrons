package api

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/babs/poc-proxies/portal/internal/config"
	"github.com/babs/poc-proxies/portal/internal/oidc"
	"github.com/babs/poc-proxies/portal/internal/policy"
	"github.com/babs/poc-proxies/portal/internal/store"
	_ "github.com/babs/poc-proxies/portal/internal/store/sqlite"

	"github.com/go-jose/go-jose/v4"
	gojosejwt "github.com/go-jose/go-jose/v4/jwt"
)

// mockIDP is a minimal OIDC issuer for the shared-store integration test.
// It differs from the one in portal/internal/oidc/oidc_test.go only in that
// it can't be shared across packages; duplication is cheaper than exporting.
type mockIDP struct {
	priv   *rsa.PrivateKey
	kid    string
	issuer string
	code   string
	claims func() map[string]any
	nonce  string // captured from /authorize, echoed into the id_token (OIDC nonce binding)
}

func newMockIDP(t *testing.T, claims func() map[string]any) *mockIDP {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	idp := &mockIDP{priv: priv, kid: "share-kid", code: "share-code", claims: claims}
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	idp.issuer = srv.URL

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
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
		q := r.URL.Query()
		idp.nonce = q.Get("nonce") // echo back into the token so callback nonce-binding passes
		loc := q.Get("redirect_uri") + "?code=" + url.QueryEscape(idp.code) + "&state=" + url.QueryEscape(q.Get("state"))
		http.Redirect(w, r, loc, http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if r.Form.Get("code") != idp.code {
			http.Error(w, "bad code", http.StatusBadRequest)
			return
		}
		c := idp.claims()
		c["iss"] = idp.issuer
		c["exp"] = time.Now().Add(10 * time.Minute).Unix()
		c["iat"] = time.Now().Unix()
		if idp.nonce != "" {
			c["nonce"] = idp.nonce
		}
		sig, err := jose.NewSigner(
			jose.SigningKey{Algorithm: jose.RS256, Key: priv},
			(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", idp.kid),
		)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		tok, err := gojosejwt.Signed(sig).Claims(c).Serialize()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "x", "token_type": "Bearer", "expires_in": 600, "id_token": tok,
		})
	})
	return idp
}

// TestOIDC_SharedSQLiteSessions_LoginOnALookupOnB is the acceptance test for
// phase-2.4: with a persistent session store, a session minted on one portal
// replica must be resolvable by another — HTTP LB round-robin friendly.
func TestOIDC_SharedSQLiteSessions_LoginOnALookupOnB(t *testing.T) {
	// One shared sqlite::memory: store backs both replicas.
	shared, err := store.NewFromURL("sqlite::memory:")
	if err != nil {
		t.Fatalf("open shared store: %v", err)
	}
	t.Cleanup(func() { _ = shared.Close() })

	idp := newMockIDP(t, func() map[string]any {
		return map[string]any{
			"sub":    "shared-user",
			"email":  "share@example.com",
			"name":   "Sharer",
			"aud":    "client-share",
			"groups": []string{"dba"},
		}
	})
	baseCfg := &oidc.Config{
		IssuerURL:    idp.issuer,
		ClientID:     "client-share",
		ClientSecret: "shh",
		// Admin flag must be set so requireOperator on replica B accepts the
		// request — the spec's acceptance criterion is "call a guarded
		// endpoint", and /api/v1/grants is admin-guarded.
		AdminClaim: "groups",
		AdminValue: "dba",
	}

	// Build two independent providers that wrap the SAME backend. Each one
	// gets its own LRU cache — the correctness test is that replica B sees
	// the session even though its cache is cold.
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	buildReplica := func(label string) (*httptest.Server, *oidc.Provider) {
		// Separate session store instances both backed by `shared`.
		sessionStore := oidc.NewSQLStore(shared)
		cfg := *baseCfg
		cfg.RedirectURL = "http://example.invalid/cb" // patched post-construction
		p, err := oidc.New(context.Background(), &cfg, sessionStore, logger)
		if err != nil {
			t.Fatalf("oidc.New(%s): %v", label, err)
		}
		// portal-like router: /oidc/* from provider + /api/v1/grants guarded
		// by requireUserAuth so we can exercise the guarded path from B.
		eng := policy.New(shared)
		router := NewRouter(&config.Config{ProxyToken: "", UserToken: ""}, shared, eng, logger, WithOIDC(p))
		srv := httptest.NewServer(router)
		// Only replica A needs the redirect back to itself — the cookie
		// issued here is what we replay against B.
		p.RedirectURL(srv.URL + "/oidc/callback")
		return srv, p
	}

	srvA, _ := buildReplica("A")
	defer srvA.Close()
	srvB, _ := buildReplica("B")
	defer srvB.Close()

	// Step 1: login on A with a cookie jar that follows the full redirect chain.
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	resp, err := client.Get(srvA.URL + "/oidc/login")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login chain ended status=%d body=%s", resp.StatusCode, string(body))
	}

	uA, _ := url.Parse(srvA.URL)
	var sessCookie *http.Cookie
	for _, c := range jar.Cookies(uA) {
		if c.Name == "portal_session" {
			sessCookie = c
		}
	}
	if sessCookie == nil {
		t.Fatalf("no session cookie after login on A; jar=%+v", jar.Cookies(uA))
	}

	// Step 2: replay the cookie against B's guarded endpoint. ListGrants is
	// a convenient GET — it returns 200+[] for an authenticated caller, 401
	// otherwise. Replica B uses a fresh LRU cache so the hit must come
	// through the shared sqlite store.
	req, _ := http.NewRequest(http.MethodGet, srvB.URL+"/api/v1/grants", nil)
	req.AddCookie(&http.Cookie{Name: "portal_session", Value: sessCookie.Value})
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("replica B: %v", err)
	}
	defer resp2.Body.Close()
	body2, _ := io.ReadAll(resp2.Body)
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("replica B returned %d body=%s; shared session should have authed the request", resp2.StatusCode, strings.TrimSpace(string(body2)))
	}
}
