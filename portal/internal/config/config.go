package config

import (
	"flag"
	"fmt"
	"os"
	"strings"
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

	// Persistence + audit retention (phase 1.1/1.3).
	StoreURL           string        // `memory`, `sqlite::memory:`, `sqlite:///path/to.db`, `postgres://...`
	AuditRetentionDays int           // drop audit rows older than this; 0 disables the age cutoff
	AuditMaxEntries    int           // hard cap on audit row count; 0 disables the cap
	AuditSweepInterval time.Duration // how often the sweeper runs; <=0 disables it

	// Approval workflow (phase 1.2).
	// AutoApprove flips newly created grants to APPROVED synchronously. Escape
	// hatch for bootstrap/demo — disable in production so the four-eyes gate
	// actually applies.
	AutoApprove bool
	// ApprovalWebhookURL, if set, receives a non-blocking POST when a grant
	// lands in PENDING. Operators wire this to Slack/email/etc.
	ApprovalWebhookURL string
	// ApprovalWebhookSecret, if set, is used to HMAC-SHA256 sign the webhook
	// body. Receivers verify the hex digest in the X-Portal-Signature header
	// (format "sha256=<hex>"). Empty = unsigned (local dev only).
	ApprovalWebhookSecret string

	// Rate limiting (phase 2.1). Token-bucket budgets on sensitive endpoints
	// (/api/v1/auth, /api/v1/grants). 0 on either dimension disables that
	// dimension; both 0 = guard off.
	AuthRatePerIP   int // events per minute per source IP
	AuthRatePerUser int // events per minute per username
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

	fs.StringVar(&cfg.StoreURL, "store", getEnv("PORTAL_STORE", "memory"), "Store URL: memory | sqlite::memory: | sqlite:///path | postgres://... (env: PORTAL_STORE)")
	fs.IntVar(&cfg.AuditRetentionDays, "audit-retention-days", getEnvInt("PORTAL_AUDIT_RETENTION_DAYS", 30), "Drop audit rows older than N days; 0 disables (env: PORTAL_AUDIT_RETENTION_DAYS)")
	fs.IntVar(&cfg.AuditMaxEntries, "audit-max-entries", getEnvInt("PORTAL_AUDIT_MAX_ENTRIES", 10_000_000), "Hard cap on audit rows; 0 disables (env: PORTAL_AUDIT_MAX_ENTRIES)")
	fs.DurationVar(&cfg.AuditSweepInterval, "audit-sweep-interval", getEnvDuration("PORTAL_AUDIT_SWEEP_INTERVAL", time.Hour), "Interval between audit retention sweeps; <=0 disables (env: PORTAL_AUDIT_SWEEP_INTERVAL)")

	// Approval workflow.
	fs.BoolVar(&cfg.AutoApprove, "auto-approve", getEnvBool("PORTAL_AUTO_APPROVE", false), "Auto-approve grants on create — bootstrap/demo only (env: PORTAL_AUTO_APPROVE)")
	fs.StringVar(&cfg.ApprovalWebhookURL, "approval-webhook-url", getEnv("PORTAL_APPROVAL_WEBHOOK_URL", ""), "Webhook URL POSTed on grant_requested (env: PORTAL_APPROVAL_WEBHOOK_URL, empty disables)")
	fs.StringVar(&cfg.ApprovalWebhookSecret, "approval-webhook-secret", getEnv("PORTAL_APPROVAL_WEBHOOK_SECRET", ""), "HMAC-SHA256 secret for X-Portal-Signature on approval webhooks (env: PORTAL_APPROVAL_WEBHOOK_SECRET)")

	// Rate limits on sensitive endpoints — defaults match HLD phase 2.1.
	// Set to 0 to disable either dimension; both 0 turns the guard off entirely.
	fs.IntVar(&cfg.AuthRatePerIP, "auth-rate-per-ip", getEnvInt("PORTAL_AUTH_RATE_PER_IP", 60), "Auth/grant requests allowed per minute per source IP; 0 disables (env: PORTAL_AUTH_RATE_PER_IP)")
	fs.IntVar(&cfg.AuthRatePerUser, "auth-rate-per-user", getEnvInt("PORTAL_AUTH_RATE_PER_USER", 30), "Auth/grant requests allowed per minute per username; 0 disables (env: PORTAL_AUTH_RATE_PER_USER)")

	return cfg
}

func getEnvInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	var n int
	if _, err := fmt.Sscanf(v, "%d", &n); err != nil {
		return fallback
	}
	return n
}

func getEnvDuration(key string, fallback time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return d
}

func getEnvBool(key string, fallback bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	return v == "1" ||
		strings.EqualFold(v, "true") ||
		strings.EqualFold(v, "yes") ||
		strings.EqualFold(v, "on")
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
