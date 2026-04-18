package config

import (
	"flag"
	"fmt"
	"os"
	"time"
)

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// Config holds portal runtime configuration.
type Config struct {
	ListenAddr        string
	MetricsAddr       string
	ProxyToken        string        // shared secret required on /api/v1/auth and /api/v1/audit/query
	UserToken         string        // bearer token for user-facing endpoints (scaffold: single static token)
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	ShutdownGrace     time.Duration

	// OIDC auth (optional). When OIDCIssuerURL is empty, OIDC is disabled and
	// user-facing endpoints fall back to the static bearer above.
	OIDCIssuerURL    string
	OIDCClientID     string
	OIDCClientSecret string
	OIDCRedirectURL  string
	OIDCAdminClaim   string // optional claim name carrying group memberships (e.g. "groups")
	OIDCAdminValue   string // optional claim value marking admin users (e.g. "dba")
	OIDCCookieSecure bool

	// Approval workflow.
	// AutoApprove flips newly created grants to APPROVED synchronously. Escape
	// hatch for bootstrap/demo — disable in production so the four-eyes gate
	// actually applies.
	AutoApprove bool
	// ApprovalWebhookURL, if set, receives a non-blocking POST when a grant
	// lands in PENDING. Operators wire this to Slack/email/etc.
	ApprovalWebhookURL string
}

// RegisterFlags wires portal flags into fs and returns the Config populated at fs.Parse().
//
// Env-var fallbacks: `PORTAL_LISTEN`, `PORTAL_METRICS_ADDR`, `PORTAL_PROXY_TOKEN`,
// `PORTAL_USER_TOKEN` seed the corresponding flag defaults. Secrets (`PROXY_TOKEN`,
// `USER_TOKEN`) are sensitive and should be set via env or a secrets file in
// real deployments, not via CLI flags visible in `ps`.
func RegisterFlags(fs *flag.FlagSet) *Config {
	cfg := &Config{}
	fs.StringVar(&cfg.ListenAddr, "listen", getEnv("PORTAL_LISTEN", "127.0.0.1:8080"), "Portal API listen address (env: PORTAL_LISTEN)")
	fs.StringVar(&cfg.MetricsAddr, "metrics-addr", getEnv("PORTAL_METRICS_ADDR", "127.0.0.1:9095"), "Address for /healthz + /metrics (env: PORTAL_METRICS_ADDR)")
	fs.StringVar(&cfg.ProxyToken, "proxy-token", getEnv("PORTAL_PROXY_TOKEN", ""), "Shared secret required from proxies (env: PORTAL_PROXY_TOKEN, empty disables the guard)")
	fs.StringVar(&cfg.UserToken, "user-token", getEnv("PORTAL_USER_TOKEN", ""), "Static bearer token for user-facing endpoints (env: PORTAL_USER_TOKEN, scaffold)")
	fs.DurationVar(&cfg.ReadHeaderTimeout, "read-header-timeout", 5*time.Second, "HTTP ReadHeaderTimeout")
	fs.DurationVar(&cfg.ReadTimeout, "read-timeout", 10*time.Second, "HTTP ReadTimeout")
	fs.DurationVar(&cfg.WriteTimeout, "write-timeout", 10*time.Second, "HTTP WriteTimeout")
	fs.DurationVar(&cfg.ShutdownGrace, "shutdown-grace", 10*time.Second, "Graceful shutdown window")

	// OIDC — leave issuer empty to disable. Operators setting OIDC should
	// supply issuer + client ID + client secret + redirect URL, all via env in
	// real deployments so secrets don't land in `ps`.
	fs.StringVar(&cfg.OIDCIssuerURL, "oidc-issuer", getEnv("PORTAL_OIDC_ISSUER", ""), "OIDC issuer URL (env: PORTAL_OIDC_ISSUER, empty disables)")
	fs.StringVar(&cfg.OIDCClientID, "oidc-client-id", getEnv("PORTAL_OIDC_CLIENT_ID", ""), "OIDC client identifier (env: PORTAL_OIDC_CLIENT_ID)")
	fs.StringVar(&cfg.OIDCClientSecret, "oidc-client-secret", getEnv("PORTAL_OIDC_CLIENT_SECRET", ""), "OIDC client secret (env: PORTAL_OIDC_CLIENT_SECRET)")
	fs.StringVar(&cfg.OIDCRedirectURL, "oidc-redirect-url", getEnv("PORTAL_OIDC_REDIRECT_URL", ""), "Callback URL registered with the IdP (env: PORTAL_OIDC_REDIRECT_URL)")
	fs.StringVar(&cfg.OIDCAdminClaim, "oidc-admin-claim", getEnv("PORTAL_OIDC_ADMIN_CLAIM", ""), "Optional claim name carrying admin group (env: PORTAL_OIDC_ADMIN_CLAIM)")
	fs.StringVar(&cfg.OIDCAdminValue, "oidc-admin-value", getEnv("PORTAL_OIDC_ADMIN_VALUE", ""), "Optional value inside OIDC admin claim that grants admin (env: PORTAL_OIDC_ADMIN_VALUE)")
	fs.BoolVar(&cfg.OIDCCookieSecure, "oidc-cookie-secure", getEnvBool("PORTAL_OIDC_COOKIE_SECURE", false), "Mark session cookies Secure (HTTPS only, env: PORTAL_OIDC_COOKIE_SECURE)")

	// Approval workflow.
	fs.BoolVar(&cfg.AutoApprove, "auto-approve", getEnvBool("PORTAL_AUTO_APPROVE", false), "Auto-approve grants on create — bootstrap/demo only (env: PORTAL_AUTO_APPROVE)")
	fs.StringVar(&cfg.ApprovalWebhookURL, "approval-webhook-url", getEnv("PORTAL_APPROVAL_WEBHOOK_URL", ""), "Webhook URL POSTed on grant_requested (env: PORTAL_APPROVAL_WEBHOOK_URL, empty disables)")

	return cfg
}

func getEnvBool(key string, fallback bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	return v == "1" || v == "true" || v == "TRUE" || v == "yes"
}

// Validate checks the portal config for internal consistency. Call after
// fs.Parse() to fail fast at boot.
func (c *Config) Validate() error {
	if c.ListenAddr == "" {
		return fmt.Errorf("listen address must not be empty")
	}
	if c.ReadHeaderTimeout < 0 || c.ReadTimeout < 0 || c.WriteTimeout < 0 || c.ShutdownGrace < 0 {
		return fmt.Errorf("timeouts must be >= 0")
	}
	return nil
}
