package oidc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Provider holds the validated OIDC provider + oauth2 client. Exposed as an
// interface on the HTTP layer so tests can supply mock providers without
// reaching the discovery endpoint.
type Provider struct {
	cfg      *Config
	logger   *slog.Logger
	store    SessionStore
	oauth2   *oauth2.Config
	verifier *gooidc.IDTokenVerifier
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

// --- handlers ---

// handleLogin generates a CSRF-safe state nonce (delivered back via the state
// query param and via an HttpOnly cookie) and redirects to the IdP.
func (p *Provider) handleLogin(w http.ResponseWriter, r *http.Request) {
	state, err := randomToken(24)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		p.logger.Error("oidc state gen", "err", err)
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
	url := p.oauth2.AuthCodeURL(state, oauth2.AccessTypeOnline)
	http.Redirect(w, r, url, http.StatusFound)
}

// handleCallback completes the authorization-code exchange, validates the ID
// token, creates a session, and issues the session cookie.
func (p *Provider) handleCallback(w http.ResponseWriter, r *http.Request) {
	// 1. Verify CSRF state matches the cookie set at /oidc/login.
	stateCookie, err := r.Cookie(p.cfg.CookieName + "_state")
	if err != nil {
		http.Error(w, "missing state cookie", http.StatusBadRequest)
		return
	}
	if r.URL.Query().Get("state") != stateCookie.Value {
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

	// 3. Pull the claims we care about for session identity.
	var claims struct {
		Sub    string   `json:"sub"`
		Email  string   `json:"email"`
		Name   string   `json:"name"`
		Groups []string `json:"groups"`
	}
	if err := idTok.Claims(&claims); err != nil {
		http.Error(w, "claim parse error", http.StatusBadGateway)
		return
	}

	// 4. Compute admin flag from configurable claim.
	isAdmin := false
	if p.cfg.AdminClaim != "" {
		raw := map[string]any{}
		_ = idTok.Claims(&raw)
		isAdmin = claimContains(raw, p.cfg.AdminClaim, p.cfg.AdminValue)
	}

	// 5. Session expiry: lesser of ID-token exp and configured SessionTTL.
	expires := time.Now().Add(p.cfg.SessionTTL)
	if !idTok.Expiry.IsZero() && idTok.Expiry.Before(expires) {
		expires = idTok.Expiry
	}

	// 6. Persist the session and set the cookie.
	sid, err := newSessionID()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		p.logger.Error("oidc sid gen", "err", err)
		return
	}
	sess := Session{
		ID:        sid,
		Subject:   claims.Sub,
		Email:     claims.Email,
		Name:      claims.Name,
		IsAdmin:   isAdmin,
		ExpiresAt: expires,
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
	// Clear the state cookie.
	http.SetCookie(w, &http.Cookie{
		Name:    p.cfg.CookieName + "_state",
		Value:   "",
		Path:    "/",
		Domain:  p.cfg.CookieDomain,
		Expires: time.Unix(0, 0),
		MaxAge:  -1,
	})
	p.logger.Info("oidc_login", "sub", claims.Sub, "email", claims.Email, "is_admin", isAdmin)

	// Lightweight JSON response rather than a redirect: callers are usually
	// API consumers (curl / Postman) during POC phase. A real UI can flip
	// this to redirect to the user's pre-login URL.
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"subject":    claims.Sub,
		"email":      claims.Email,
		"expires_at": expires,
	})
}

// handleLogout clears the session cookie and removes the server-side record.
func (p *Provider) handleLogout(w http.ResponseWriter, r *http.Request) {
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

