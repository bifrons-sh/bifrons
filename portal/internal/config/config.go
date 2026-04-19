package config

import (
	"flag"
	"fmt"
	"log/slog"
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

	// SecretboxKeyEnv names the env var holding the base64-encoded 32-byte key
	// used to encrypt at-rest secrets (backend-account passwords, portal &
	// ephemeral passwords on grants). Default SECRETBOX_KEY. Leaving this
	// empty explicitly opts the portal into plaintext storage (local-dev only).
	SecretboxKeyEnv string

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

	// Rate limiting (phase 2.1).
	AuthRatePerIP   int
	AuthRatePerUser int

	// EphemeralAccounts opts into per-grant backend account provisioning.
	EphemeralAccounts bool

	// Entra (Azure AD) integration — phase 2 approval workflow.
	EntraTenantID     string
	EntraClientID     string
	EntraClientSecret string
	EntraSenderUPN    string
	EntraPolicyFile   string
	// EntraAdminMailbox, when set, is the single mailbox notified on the
	// MANAGER_APPROVED → APPROVED gate. Mutually compatible with the group
	// flavour; if both are set, the mailbox is appended to the resolved list.
	EntraAdminMailbox string
	// EntraAdminGroupID, when set, is an Entra group whose members the portal
	// resolves via Graph /groups/{id}/members and emails on the admin gate.
	EntraAdminGroupID string

	// PublicURL is the portal's externally reachable base URL used in
	// approval email deep-links. No trailing slash.
	PublicURL string

	// Tri-phase grant lifecycle windows.
	ValidationWindow time.Duration // PENDING|MANAGER_APPROVED → EXPIRED if not fully approved within this window
	ClaimWindow      time.Duration // APPROVED → EXPIRED if not claimed within this window
	CredentialTTL    time.Duration // ACTIVE → EXPIRED once this elapses post-claim
}

// EntraEnabled reports whether the full Entra integration is wired.
func (c *Config) EntraEnabled() bool {
	return c.EntraTenantID != "" && c.EntraClientID != "" && c.EntraClientSecret != ""
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
	fs.StringVar(&cfg.SecretboxKeyEnv, "secretbox-key-env", getEnv("PORTAL_SECRETBOX_KEY_ENV", "SECRETBOX_KEY"), "Env var holding the base64 32-byte key used to encrypt at-rest secrets; empty = disabled (plaintext at rest)")
	fs.IntVar(&cfg.AuditRetentionDays, "audit-retention-days", getEnvInt("PORTAL_AUDIT_RETENTION_DAYS", 30), "Drop audit rows older than N days; 0 disables (env: PORTAL_AUDIT_RETENTION_DAYS)")
	fs.IntVar(&cfg.AuditMaxEntries, "audit-max-entries", getEnvInt("PORTAL_AUDIT_MAX_ENTRIES", 10_000_000), "Hard cap on audit rows; 0 disables (env: PORTAL_AUDIT_MAX_ENTRIES)")
	fs.DurationVar(&cfg.AuditSweepInterval, "audit-sweep-interval", getEnvDuration("PORTAL_AUDIT_SWEEP_INTERVAL", time.Hour), "Interval between audit retention sweeps; <=0 disables (env: PORTAL_AUDIT_SWEEP_INTERVAL)")

	// Approval workflow.
	fs.BoolVar(&cfg.AutoApprove, "auto-approve", getEnvBool("PORTAL_AUTO_APPROVE", false), "Auto-approve grants on create — bootstrap/demo only (env: PORTAL_AUTO_APPROVE)")
	fs.StringVar(&cfg.ApprovalWebhookURL, "approval-webhook-url", getEnv("PORTAL_APPROVAL_WEBHOOK_URL", ""), "Webhook URL POSTed on grant_requested (env: PORTAL_APPROVAL_WEBHOOK_URL, empty disables)")
	fs.StringVar(&cfg.ApprovalWebhookSecret, "approval-webhook-secret", getEnv("PORTAL_APPROVAL_WEBHOOK_SECRET", ""), "HMAC-SHA256 secret for X-Portal-Signature on approval webhooks (env: PORTAL_APPROVAL_WEBHOOK_SECRET)")
	fs.BoolVar(&cfg.EphemeralAccounts, "ephemeral-accounts", getEnvBool("PORTAL_EPHEMERAL_ACCOUNTS", false), "Provision per-grant backend users on approve, drop on revoke/expire (requires role=dba BackendAccount per backend; env: PORTAL_EPHEMERAL_ACCOUNTS)")

	// Rate limits on sensitive endpoints — defaults match HLD phase 2.1.
	// Set to 0 to disable either dimension; both 0 turns the guard off entirely.
	fs.IntVar(&cfg.AuthRatePerIP, "auth-rate-per-ip", getEnvInt("PORTAL_AUTH_RATE_PER_IP", 60), "Auth/grant requests allowed per minute per source IP; 0 disables (env: PORTAL_AUTH_RATE_PER_IP)")
	fs.IntVar(&cfg.AuthRatePerUser, "auth-rate-per-user", getEnvInt("PORTAL_AUTH_RATE_PER_USER", 30), "Auth/grant requests allowed per minute per username; 0 disables (env: PORTAL_AUTH_RATE_PER_USER)")

	// Entra (Azure AD). Secrets must come from env in production; flags are
	// visible in `ps` and leak via process listings.
	fs.StringVar(&cfg.EntraTenantID, "entra-tenant-id", getEnv("PORTAL_ENTRA_TENANT_ID", ""), "Entra tenant id / directory id (env: PORTAL_ENTRA_TENANT_ID)")
	fs.StringVar(&cfg.EntraClientID, "entra-client-id", getEnv("PORTAL_ENTRA_CLIENT_ID", ""), "Entra app registration client id (env: PORTAL_ENTRA_CLIENT_ID)")
	fs.StringVar(&cfg.EntraClientSecret, "entra-client-secret", getEnv("PORTAL_ENTRA_CLIENT_SECRET", ""), "Entra app registration client secret (env: PORTAL_ENTRA_CLIENT_SECRET)")
	fs.StringVar(&cfg.EntraSenderUPN, "entra-sender", getEnv("PORTAL_ENTRA_SENDER", ""), "Mailbox UPN Graph /sendMail runs as (env: PORTAL_ENTRA_SENDER)")
	fs.StringVar(&cfg.EntraPolicyFile, "entra-policy-file", getEnv("PORTAL_ENTRA_POLICY_FILE", ""), "Path to YAML group->backend/role policy (env: PORTAL_ENTRA_POLICY_FILE)")
	fs.StringVar(&cfg.EntraAdminMailbox, "entra-admin-mailbox", getEnv("PORTAL_ENTRA_ADMIN_MAILBOX", ""), "Single mailbox notified on the admin (second-gate) approval (env: PORTAL_ENTRA_ADMIN_MAILBOX)")
	fs.StringVar(&cfg.EntraAdminGroupID, "entra-admin-group-id", getEnv("PORTAL_ENTRA_ADMIN_GROUP_ID", ""), "Entra group id whose members are notified on the admin gate (env: PORTAL_ENTRA_ADMIN_GROUP_ID)")
	fs.StringVar(&cfg.PublicURL, "public-url", getEnv("PORTAL_PUBLIC_URL", ""), "Portal externally-reachable base URL for email deep-links (env: PORTAL_PUBLIC_URL)")

	// Tri-phase lifecycle defaults — overridable per request via the create body.
	fs.DurationVar(&cfg.ValidationWindow, "validation-window", getEnvDuration("PORTAL_VALIDATION_WINDOW", 24*time.Hour), "PENDING/MANAGER_APPROVED grants expire after this window (env: PORTAL_VALIDATION_WINDOW)")
	fs.DurationVar(&cfg.ClaimWindow, "claim-window", getEnvDuration("PORTAL_CLAIM_WINDOW", time.Hour), "APPROVED grants expire if not claimed within this window (env: PORTAL_CLAIM_WINDOW)")
	fs.DurationVar(&cfg.CredentialTTL, "credential-ttl", getEnvDuration("PORTAL_CREDENTIAL_TTL", time.Hour), "ACTIVE grants expire this long after /claim (env: PORTAL_CREDENTIAL_TTL)")

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

// LogValue implements slog.LogValuer so accidental structured-logging of a
// Config redacts the Entra/OIDC client secrets and approval webhook secret.
// Anything not explicitly listed here is omitted — add fields as needed; the
// default is deny.
func (c *Config) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("listen", c.ListenAddr),
		slog.String("store", c.StoreURL),
		slog.Bool("oidc_enabled", c.OIDCIssuerURL != ""),
		slog.String("oidc_issuer", c.OIDCIssuerURL),
		slog.String("oidc_client_secret", redactIfSet(c.OIDCClientSecret)),
		slog.Bool("entra_enabled", c.EntraEnabled()),
		slog.String("entra_tenant", c.EntraTenantID),
		slog.String("entra_client_secret", redactIfSet(c.EntraClientSecret)),
		slog.String("entra_sender", c.EntraSenderUPN),
		slog.String("entra_policy_file", c.EntraPolicyFile),
		slog.String("approval_webhook_secret", redactIfSet(c.ApprovalWebhookSecret)),
		slog.String("user_token", redactIfSet(c.UserToken)),
		slog.String("proxy_token", redactIfSet(c.ProxyToken)),
		slog.String("public_url", c.PublicURL),
	)
}

func redactIfSet(s string) string {
	if s == "" {
		return ""
	}
	return "<redacted>"
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
	// When Entra is enabled the admin half of the dual-gate must reach
	// somebody — a mailbox or a resolved group. Bail early so an operator
	// doesn't ship a portal that silently strands every grant at the
	// MANAGER_APPROVED stage.
	if c.EntraEnabled() && c.EntraAdminMailbox == "" && c.EntraAdminGroupID == "" {
		return fmt.Errorf("entra enabled but no admin reachability: set -entra-admin-mailbox or -entra-admin-group-id")
	}
	if c.ValidationWindow < 0 || c.ClaimWindow < 0 || c.CredentialTTL < 0 {
		return fmt.Errorf("validation/claim/credential windows must be >= 0")
	}
	return nil
}
