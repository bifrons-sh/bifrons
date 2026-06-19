// Package oidc provides OIDC (OpenID Connect) authentication scaffolding for
// the portal's user-facing endpoints. When configured, operators who have
// completed the `/oidc/login` → `/oidc/callback` flow hold a session token
// that authenticates them to the Grant/Admin APIs without a static bearer.
//
// Design goals:
//   - Additive: the existing static bearer guard (`-user-token`) continues to
//     work. Middleware accepts *either* token, so rollout is incremental.
//   - Non-intrusive for proxies: the proxy↔portal path (X-Portal-Token) is
//     unaffected by OIDC.
//   - Provider-agnostic: discovery-based, tested against go-oidc's TestOIDC
//     mock provider rather than a specific IdP.
package oidc

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

// Config is the runtime configuration for the OIDC integration. When IssuerURL
// is empty the whole subsystem is disabled and Middleware becomes a pass-through.
type Config struct {
	IssuerURL    string        // e.g. https://accounts.example.com
	ClientID     string        // OAuth2 client identifier issued by the IdP
	ClientSecret string        // OAuth2 client secret (kept server-side)
	RedirectURL  string        // proxy-visible callback URL, e.g. https://portal.example.com/oidc/callback
	Scopes       []string      // additional scopes beyond `openid profile email`
	SessionTTL   time.Duration // how long a validated session remains usable; defaults to ID-token expiry
	AdminClaim   string        // optional: a custom claim that marks admin users (e.g. "groups")
	AdminValue   string        // optional: the value admin users must have in AdminClaim (e.g. "dba")
	CookieName   string        // session cookie name; default "portal_session"
	CookieDomain string        // optional cookie domain; usually left blank
	CookieSecure bool          // true in prod (HTTPS); false in local dev
}

// Enabled reports whether the config has the minimum fields set to wire OIDC.
func (c *Config) Enabled() bool {
	return c != nil && c.IssuerURL != "" && c.ClientID != "" && c.RedirectURL != ""
}

// normalize fills in documented defaults so handlers don't need to branch on
// zero-valued fields. Returns a copy; the caller's config is not mutated.
func (c *Config) normalize() *Config {
	if c == nil {
		return nil
	}
	out := *c
	if out.SessionTTL <= 0 {
		out.SessionTTL = 8 * time.Hour
	}
	if out.CookieName == "" {
		out.CookieName = "portal_session"
	}
	if len(out.Scopes) == 0 {
		out.Scopes = []string{"openid", "profile", "email"}
	} else if !slices.Contains(out.Scopes, "openid") {
		out.Scopes = append([]string{"openid"}, out.Scopes...)
	}
	return &out
}

// Validate rejects obviously-invalid configs at startup. The portal binary
// should only construct an OIDC provider if Enabled()+Validate() succeed.
func (c *Config) Validate() error {
	if !c.Enabled() {
		return nil
	}
	if c.ClientSecret == "" {
		return fmt.Errorf("oidc client secret is required")
	}
	if c.SessionTTL < 0 {
		return fmt.Errorf("oidc session TTL must be >= 0")
	}
	if c.AdminClaim != "" && c.AdminValue == "" {
		return fmt.Errorf("oidc admin claim set without admin value")
	}
	// Reject a cookie domain that would over-widen the session/state/nonce
	// cookie scope. A bare wildcard ("*", ".") or a leading-dot-only value has
	// no registrable label, so a browser either rejects it or — worse on legacy
	// stacks — scopes the auth cookies far too broadly, leaking them to
	// unrelated hosts. An operator wanting a parent-domain cookie must spell out
	// at least one label (e.g. ".example.com"), not just a dot.
	if d := strings.TrimSpace(c.CookieDomain); d != "" {
		if d == "*" || d == "." || strings.TrimLeft(d, ".") == "" {
			return fmt.Errorf("oidc cookie domain %q is too broad: specify an explicit domain", c.CookieDomain)
		}
	}
	return nil
}
