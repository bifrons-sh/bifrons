package oidc

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// UserProvisioner resolves-or-creates a portal user for an authenticated OIDC
// identity. Implemented by the store layer (or any adapter around it); kept
// narrow so the oidc package doesn't pull in the full store.Store surface or
// the domain types for anything except what the callback actually needs.
//
// Returned tuple: (portalUserID, isOperator, error). The callback trusts the
// provisioner's isOperator when the user already exists — this lets the store
// hold the source of truth (e.g. admin flipped on/off via the admin API)
// rather than forever inheriting the first-login claim value.
type UserProvisioner interface {
	ProvisionOIDCUser(ctx context.Context, sub, email, preferredUsername string, claimIsAdmin bool) (portalUserID string, isOperator bool, err error)
}

// Provider holds the validated OIDC provider + oauth2 client. Exposed as an
// interface on the HTTP layer so tests can supply mock providers without
// reaching the discovery endpoint.
type Provider struct {
	cfg         *Config
	logger      *slog.Logger
	store       SessionStore
	oauth2      *oauth2.Config
	verifier    *gooidc.IDTokenVerifier
	provisioner UserProvisioner
}

// WithProvisioner attaches a UserProvisioner so handleCallback can materialise
// a portal user on first OIDC login. Returns p for fluent wiring; tolerates a
// nil receiver so callers with OIDC disabled don't need to branch.
func (p *Provider) WithProvisioner(up UserProvisioner) *Provider {
	if p == nil {
		return nil
	}
	p.provisioner = up
	return p
}

// New builds a Provider. Performs OIDC discovery against cfg.IssuerURL; the
// returned Provider is nil if cfg is not Enabled(). Caller should treat a nil
// Provider as "OIDC disabled".
func New(ctx context.Context, cfg *Config, store SessionStore, logger *slog.Logger) (*Provider, error) {
	if cfg == nil || !cfg.Enabled() {
		return nil, nil
	}
	cfg = cfg.normalize()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	p, err := gooidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery: %w", err)
	}
	oauth2Cfg := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Endpoint:     p.Endpoint(),
		Scopes:       cfg.Scopes,
	}
	verifier := p.Verifier(&gooidc.Config{ClientID: cfg.ClientID})

	return &Provider{
		cfg:      cfg,
		logger:   logger.With("component", "oidc"),
		store:    store,
		oauth2:   oauth2Cfg,
		verifier: verifier,
	}, nil
}

// RegisterRoutes wires /oidc/login, /oidc/callback, /oidc/logout on mux. If p
// is nil the function is a no-op, so callers can unconditionally invoke it.
func (p *Provider) RegisterRoutes(mux *http.ServeMux) {
	if p == nil {
		return
	}
	mux.HandleFunc("/oidc/login", p.handleLogin)
	mux.HandleFunc("/oidc/callback", p.handleCallback)
	mux.HandleFunc("/oidc/logout", p.handleLogout)
}

// Store returns the underlying session store. Exposed so the middleware layer
// can resolve session cookies into Session structs.
func (p *Provider) Store() SessionStore {
	if p == nil {
		return nil
	}
	return p.store
}

// CookieName returns the session cookie name or the empty string when OIDC is disabled.
func (p *Provider) CookieName() string {
	if p == nil {
		return ""
	}
	return p.cfg.CookieName
}

// RedirectURL overrides the OAuth2 redirect URL after construction. Useful
// for tests (where the server port is allocated post-New) and for operators
// exposing the portal behind a DNS name unknown at boot. No-op on nil.
func (p *Provider) RedirectURL(u string) {
	if p == nil {
		return
	}
	p.cfg.RedirectURL = u
	p.oauth2.RedirectURL = u
}

// --- handlers ---

// handleLogin generates a CSRF-safe state nonce (delivered back via the state
// query param and via an HttpOnly cookie) plus an OIDC nonce (delivered to the
// IdP on the auth URL and stored in its own HttpOnly cookie), then redirects to
// the IdP.
//
// Why two distinct values: `state` defends the *redirect* against CSRF (it ties
// the callback to the browser that started the flow). The OIDC `nonce` defends
// the *ID token* against replay/injection: the IdP echoes it into the signed
// token's `nonce` claim, and the callback rejects any token whose nonce doesn't
// match what we issued. Without it, a SameSite=Lax cookie + a single CSRF state
// nonce is the only binding, which a stolen-or-replayed authorization response
// could still satisfy. Per OpenID Connect Core §3.1.2.1 the nonce is the
// canonical mitigation for token replay.
func (p *Provider) handleLogin(w http.ResponseWriter, r *http.Request) {
	state, err := randomToken(24)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		p.logger.Error("oidc state gen", "err", err)
		return
	}
	nonce, err := randomToken(24)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		p.logger.Error("oidc nonce gen", "err", err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     p.cfg.CookieName + "_state",
		Value:    state,
		Path:     "/",
		Domain:   p.cfg.CookieDomain,
		Secure:   p.cfg.CookieSecure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(10 * time.Minute),
	})
	http.SetCookie(w, &http.Cookie{
		Name:     p.cfg.CookieName + "_nonce",
		Value:    nonce,
		Path:     "/",
		Domain:   p.cfg.CookieDomain,
		Secure:   p.cfg.CookieSecure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(10 * time.Minute),
	})
	// gooidc.Nonce sets the `nonce` auth-request param; the IdP MUST copy it
	// into the issued ID token so the callback can bind the token to this flow.
	url := p.oauth2.AuthCodeURL(state, oauth2.AccessTypeOnline, gooidc.Nonce(nonce))
	http.Redirect(w, r, url, http.StatusFound)
}

// handleCallback completes the authorization-code exchange, validates the ID
// token, creates a session, and issues the session cookie.
func (p *Provider) handleCallback(w http.ResponseWriter, r *http.Request) {
	// 0. Stale-replay short-circuit. The state cookie is single-use: a
	// successful callback clears it at the end of this handler. If the user
	// then refreshes / pastes the URL / uses the back button to revisit
	// /oidc/callback, the second hit finds no state cookie and historically
	// surfaced a confusing "missing state cookie" 400. When the request
	// already carries a valid session cookie there's no auth work left to
	// do; bounce to /ui/ and let the SPA take over.
	if sess := p.LookupSession(r); sess != nil {
		http.Redirect(w, r, "/ui/", http.StatusFound)
		return
	}
	// 1. Verify CSRF state matches the cookie set at /oidc/login.
	stateCookie, err := r.Cookie(p.cfg.CookieName + "_state")
	if err != nil {
		// No state cookie AND no session — the most likely cause is a stale
		// callback URL where the cookie already lapsed (10 min TTL) or the
		// user came in from a bookmark. Kick them back to /oidc/login so the
		// next attempt starts a fresh state nonce instead of dead-ending.
		http.Redirect(w, r, "/oidc/login", http.StatusFound)
		return
	}
	// Constant-time compare — the state nonce is short-lived random, so a
	// timing side-channel is theoretical, but this matches the convention
	// used for every other bearer/token/password compare in this codebase
	// and costs nothing.
	got := []byte(r.URL.Query().Get("state"))
	want := []byte(stateCookie.Value)
	if subtle.ConstantTimeCompare(got, want) != 1 {
		http.Error(w, "state mismatch", http.StatusBadRequest)
		return
	}
	// 2. Exchange code for tokens.
	code := r.URL.Query().Get("code")
	if code == "" {
		if errMsg := r.URL.Query().Get("error"); errMsg != "" {
			http.Error(w, "idp error: "+errMsg, http.StatusBadRequest)
			return
		}
		http.Error(w, "missing code", http.StatusBadRequest)
		return
	}
	tok, err := p.oauth2.Exchange(r.Context(), code)
	if err != nil {
		http.Error(w, "token exchange failed", http.StatusBadGateway)
		p.logger.Error("oidc exchange", "err", err)
		return
	}
	rawID, ok := tok.Extra("id_token").(string)
	if !ok {
		http.Error(w, "missing id_token", http.StatusBadGateway)
		return
	}
	idTok, err := p.verifier.Verify(r.Context(), rawID)
	if err != nil {
		http.Error(w, "id_token verification failed", http.StatusUnauthorized)
		p.logger.Error("oidc verify", "err", err)
		return
	}

	// 2b. Bind the ID token to this login flow via the OIDC nonce. The signed
	// token carries back the nonce we issued at /oidc/login; if it's missing or
	// doesn't match the nonce cookie, the token is replayed or injected — reject
	// with 401. Constant-time compare to match the codebase convention for
	// secret comparisons (the nonce is short-lived random, so a timing leak is
	// only theoretical, but consistency costs nothing).
	nonceCookie, err := r.Cookie(p.cfg.CookieName + "_nonce")
	if err != nil || subtle.ConstantTimeCompare([]byte(idTok.Nonce), []byte(nonceCookie.Value)) != 1 {
		http.Error(w, "id_token nonce mismatch", http.StatusUnauthorized)
		p.logger.Error("oidc nonce mismatch", "sub", idTok.Subject)
		return
	}

	// 3. Pull the claims we care about for session identity.
	var claims struct {
		Sub               string   `json:"sub"`
		Email             string   `json:"email"`
		Name              string   `json:"name"`
		PreferredUsername string   `json:"preferred_username"`
		Groups            []string `json:"groups"`
	}
	if err := idTok.Claims(&claims); err != nil {
		http.Error(w, "claim parse error", http.StatusBadGateway)
		return
	}

	// 4. Compute admin flag from configurable claim.
	claimIsAdmin := false
	if p.cfg.AdminClaim != "" {
		raw := map[string]any{}
		_ = idTok.Claims(&raw)
		claimIsAdmin = claimContains(raw, p.cfg.AdminClaim, p.cfg.AdminValue)
	}

	// 5. Resolve-or-create the portal user tied to this IdP subject.
	// Skipped when no provisioner is wired (e.g. unit tests exercising the
	// auth flow without a store). When wired, the provisioner's IsOperator
	// becomes authoritative so admin flips via the admin API survive
	// subsequent logins.
	isOperator := claimIsAdmin
	portalUserID := ""
	if p.provisioner != nil {
		uid, effAdmin, perr := p.provisioner.ProvisionOIDCUser(
			r.Context(), claims.Sub, claims.Email, claims.PreferredUsername, claimIsAdmin,
		)
		if perr != nil {
			http.Error(w, "user provisioning failed", http.StatusInternalServerError)
			p.logger.Error("oidc provision", "err", perr, "sub", claims.Sub)
			return
		}
		portalUserID = uid
		isOperator = effAdmin
	}

	// 6. Session expiry: lesser of ID-token exp and configured SessionTTL.
	expires := time.Now().Add(p.cfg.SessionTTL)
	if !idTok.Expiry.IsZero() && idTok.Expiry.Before(expires) {
		expires = idTok.Expiry
	}

	// 7. Persist the session and set the cookie.
	sid, err := newSessionID()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		p.logger.Error("oidc sid gen", "err", err)
		return
	}
	sess := Session{
		ID:           sid,
		Subject:      claims.Sub,
		Email:        claims.Email,
		Name:         claims.Name,
		IsOperator:   isOperator,
		PortalUserID: portalUserID,
		ExpiresAt:    expires,
	}
	if err := p.store.Create(sess); err != nil {
		http.Error(w, "session create failed", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     p.cfg.CookieName,
		Value:    sid,
		Path:     "/",
		Domain:   p.cfg.CookieDomain,
		Secure:   p.cfg.CookieSecure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  expires,
	})
	// Clear the single-use state and nonce cookies now that the flow completed.
	http.SetCookie(w, &http.Cookie{
		Name:    p.cfg.CookieName + "_state",
		Value:   "",
		Path:    "/",
		Domain:  p.cfg.CookieDomain,
		Expires: time.Unix(0, 0),
		MaxAge:  -1,
	})
	http.SetCookie(w, &http.Cookie{
		Name:    p.cfg.CookieName + "_nonce",
		Value:   "",
		Path:    "/",
		Domain:  p.cfg.CookieDomain,
		Expires: time.Unix(0, 0),
		MaxAge:  -1,
	})
	p.logger.Info("oidc_login", "sub", claims.Sub, "email", claims.Email, "is_operator", isOperator)

	// Redirect to the SPA. A future iteration can carry a pre-login `return_to`
	// in the state cookie (paired with the CSRF nonce) so deep-links survive
	// the round trip; for now /ui/ is the only meaningful destination.
	http.Redirect(w, r, "/ui/", http.StatusFound)
}

// handleLogout clears the session cookie and removes the server-side record.
// POST-only so a cross-site top-level GET navigation (<a href>, bookmark) can't
// log an authenticated user out by accident or by malice. SameSite=Lax blocks
// cross-site POST cookies, so the attacker cannot substitute POST either —
// together the two gates make logout-CSRF a non-issue.
func (p *Provider) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if c, err := r.Cookie(p.cfg.CookieName); err == nil {
		p.store.Delete(c.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:    p.cfg.CookieName,
		Value:   "",
		Path:    "/",
		Domain:  p.cfg.CookieDomain,
		Expires: time.Unix(0, 0),
		MaxAge:  -1,
	})
	w.WriteHeader(http.StatusNoContent)
}

// --- helpers ---

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// claimContains returns true when claim `key` in raw contains `value`. The
// claim may be a string, a []string, or a []any from the JSON decoder — we
// accept all three so the operator can point AdminClaim at common layouts
// like Keycloak's `groups` array or Okta's `roles` array.
func claimContains(raw map[string]any, key, value string) bool {
	v, ok := raw[key]
	if !ok {
		return false
	}
	switch t := v.(type) {
	case string:
		return t == value
	case []string:
		for _, s := range t {
			if s == value {
				return true
			}
		}
	case []any:
		for _, s := range t {
			if str, ok := s.(string); ok && str == value {
				return true
			}
		}
	}
	return false
}

// --- session cookie extraction for middleware ---

// LookupSession resolves an incoming request's session cookie to a Session.
// Returns nil when OIDC is disabled, no cookie is present, or the session is
// expired/unknown — callers should fall through to the static-bearer path.
func (p *Provider) LookupSession(r *http.Request) *Session {
	if p == nil {
		return nil
	}
	c, err := r.Cookie(p.cfg.CookieName)
	if err != nil || c.Value == "" {
		return nil
	}
	s, ok := p.store.Get(c.Value)
	if !ok {
		return nil
	}
	if s.Expired(time.Now()) {
		p.store.Delete(c.Value)
		return nil
	}
	return &s
}
