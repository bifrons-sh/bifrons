package config

import (
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"

	// Aliased because this package is also named "config"; the shared env
	// helpers (GetEnv/GetEnvInt) live in the proxy-side config package and are
	// reused here instead of being re-implemented.
	baseconfig "github.com/babs/poc-proxies/internal/config"
)

// Config bundles portal runtime configuration. Fields are grouped into
// sub-structs by concern so call sites read as `cfg.OIDC.IssuerURL` rather
// than drowning in a flat 30-field bag.
type Config struct {
	HTTP      HTTP
	OIDC      OIDC
	Store     Store
	Audit     Audit
	RateLimit RateLimit
	Approval  Approval
	Entra     Entra
	Windows   Windows

	// ProxyToken guards /api/v1/auth and /api/v1/audit/query (proxy ↔ portal).
	ProxyToken string
	// UserToken is the static bearer for operator endpoints (scaffold; OIDC
	// is the production path).
	UserToken string
	// EphemeralAccounts opts into per-grant backend account provisioning.
	EphemeralAccounts bool
}

// HTTP groups the HTTP server settings (listen, timeouts, public URL).
type HTTP struct {
	ListenAddr        string
	MetricsAddr       string
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	ShutdownGrace     time.Duration
	// PublicURL is the portal's externally reachable base URL, used in
	// approval email deep-links. No trailing slash.
	PublicURL string
}

// OIDC groups the session-cookie auth settings. Leave IssuerURL empty to
// disable and fall back to the static UserToken path.
type OIDC struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	AdminClaim   string // optional claim name carrying group memberships
	AdminValue   string // optional claim value marking admin users
	CookieSecure bool
	// AccountURL is the IdP-side user account / profile page. The SPA navigates
	// here after a successful logout so the operator can manage their identity
	// (password, MFA, other apps) at the IdP rather than being dumped on the
	// portal login page. When empty the SPA falls back to the portal root. The
	// canonical Keycloak path is `<issuer>/account/`; Okta uses `/profile`;
	// Auth0 differs again — explicit config keeps the portal IdP-agnostic.
	AccountURL string
}

// Enabled reports whether an OIDC issuer is configured.
func (o OIDC) Enabled() bool { return o.IssuerURL != "" }

// Store groups the persistence URL + the at-rest encryption key location.
type Store struct {
	URL string // memory | sqlite::memory: | sqlite:///path | postgres://...
	// SecretboxKeyEnv names the env var holding the base64-encoded 32-byte
	// key that encrypts row-stored secrets. Default SECRETBOX_KEY. Setting
	// this to "" explicitly opts into plaintext storage (local-dev only).
	SecretboxKeyEnv string
}

// Audit groups the audit-table retention knobs consumed by lifecycle.Run.
type Audit struct {
	RetentionDays int           // drop audit rows older than this; 0 disables the age cutoff
	MaxEntries    int           // hard cap on audit row count; 0 disables the cap
	SweepInterval time.Duration // how often the sweeper runs; <=0 disables it
}

// RateLimit bounds the /auth + /grants POST buckets. Either dimension at 0
// disables that bucket; both at 0 turns the guard off entirely.
type RateLimit struct {
	PerIP   int // requests allowed per minute per source IP
	PerUser int // requests allowed per minute per username / user_id
}

// Approval groups the approval-workflow knobs.
type Approval struct {
	// AutoApprove flips newly created grants to APPROVED synchronously.
	// Escape hatch for bootstrap/demo; off in production so the four-eyes
	// gate actually applies.
	AutoApprove bool
	// WebhookURL, if set, receives a non-blocking POST on grant_requested.
	WebhookURL string
	// WebhookSecret is the HMAC-SHA256 secret used for X-Portal-Signature.
	// Empty = unsigned (local dev only).
	WebhookSecret string
}

// Entra groups the Azure AD integration: Graph auth, mail sender, policy
// file, admin reachability.
type Entra struct {
	TenantID     string
	ClientID     string
	ClientSecret string
	SenderUPN    string
	PolicyFile   string
	// T2Mailbox, when set, is the single-mailbox reachability fallback for
	// gate2 (admin-tier) notifications. Appended to every gate2 send
	// regardless of the backend's T2 group — a safety net for
	// misconfigured backends.
	//
	// Primary T2 recipient resolution is per-backend via
	// backends.t2_group_slug (specs/phase-7-validation-ui.md §7.8.1) —
	// different backends have different admin tiers. This mailbox exists
	// only to guarantee somebody is notified even if a backend's group
	// resolves to zero members.
	T2Mailbox string
}

// Enabled reports whether the Graph-auth trio is populated.
func (e Entra) Enabled() bool {
	return e.TenantID != "" && e.ClientID != "" && e.ClientSecret != ""
}

// Windows groups the three grant-lifecycle deadlines.
type Windows struct {
	// Validation: PENDING|VALIDATOR_APPROVED → EXPIRED if not fully approved
	// within this window.
	Validation time.Duration
	// Claim: APPROVED → EXPIRED if not claimed within this window.
	Claim time.Duration
	// CredentialTTL: ACTIVE → EXPIRED once this elapses post-claim.
	CredentialTTL time.Duration
}

// RegisterFlags wires portal flags into fs and returns the Config populated at fs.Parse().
func RegisterFlags(fs *flag.FlagSet) *Config {
	cfg := &Config{}
	// HTTP
	fs.StringVar(&cfg.HTTP.ListenAddr, "listen", baseconfig.GetEnv("PORTAL_LISTEN", "127.0.0.1:8080"), "Portal API listen address (env: PORTAL_LISTEN)")
	fs.StringVar(&cfg.HTTP.MetricsAddr, "metrics-addr", baseconfig.GetEnv("PORTAL_METRICS_ADDR", "127.0.0.1:9095"), "Address for /healthz + /metrics (env: PORTAL_METRICS_ADDR)")
	fs.DurationVar(&cfg.HTTP.ReadHeaderTimeout, "read-header-timeout", 5*time.Second, "HTTP ReadHeaderTimeout")
	fs.DurationVar(&cfg.HTTP.ReadTimeout, "read-timeout", 10*time.Second, "HTTP ReadTimeout")
	fs.DurationVar(&cfg.HTTP.WriteTimeout, "write-timeout", 10*time.Second, "HTTP WriteTimeout")
	fs.DurationVar(&cfg.HTTP.ShutdownGrace, "shutdown-grace", 10*time.Second, "Graceful shutdown window")
	fs.StringVar(&cfg.HTTP.PublicURL, "public-url", baseconfig.GetEnv("PORTAL_PUBLIC_URL", ""), "Portal externally-reachable base URL for email deep-links (env: PORTAL_PUBLIC_URL)")

	// Tokens
	fs.StringVar(&cfg.ProxyToken, "proxy-token", baseconfig.GetEnv("PORTAL_PROXY_TOKEN", ""), "Shared secret required from proxies (env: PORTAL_PROXY_TOKEN, empty disables the guard)")
	fs.StringVar(&cfg.UserToken, "user-token", baseconfig.GetEnv("PORTAL_USER_TOKEN", ""), "Static bearer token for user-facing endpoints (env: PORTAL_USER_TOKEN, scaffold)")

	// OIDC
	fs.StringVar(&cfg.OIDC.IssuerURL, "oidc-issuer", baseconfig.GetEnv("PORTAL_OIDC_ISSUER", ""), "OIDC issuer URL (env: PORTAL_OIDC_ISSUER, empty disables)")
	fs.StringVar(&cfg.OIDC.ClientID, "oidc-client-id", baseconfig.GetEnv("PORTAL_OIDC_CLIENT_ID", ""), "OIDC client identifier (env: PORTAL_OIDC_CLIENT_ID)")
	fs.StringVar(&cfg.OIDC.ClientSecret, "oidc-client-secret", baseconfig.GetEnv("PORTAL_OIDC_CLIENT_SECRET", ""), "OIDC client secret (env: PORTAL_OIDC_CLIENT_SECRET)")
	fs.StringVar(&cfg.OIDC.RedirectURL, "oidc-redirect-url", baseconfig.GetEnv("PORTAL_OIDC_REDIRECT_URL", ""), "Callback URL registered with the IdP (env: PORTAL_OIDC_REDIRECT_URL)")
	fs.StringVar(&cfg.OIDC.AdminClaim, "oidc-admin-claim", baseconfig.GetEnv("PORTAL_OIDC_ADMIN_CLAIM", ""), "Optional claim name carrying admin group (env: PORTAL_OIDC_ADMIN_CLAIM)")
	fs.StringVar(&cfg.OIDC.AdminValue, "oidc-admin-value", baseconfig.GetEnv("PORTAL_OIDC_ADMIN_VALUE", ""), "Optional value inside OIDC admin claim that grants admin (env: PORTAL_OIDC_ADMIN_VALUE)")
	fs.BoolVar(&cfg.OIDC.CookieSecure, "oidc-cookie-secure", getEnvBool("PORTAL_OIDC_COOKIE_SECURE", true), "Mark session cookies Secure (HTTPS only). Defaults to true; pass -oidc-cookie-secure=false for HTTP-only local development. env: PORTAL_OIDC_COOKIE_SECURE")
	fs.StringVar(&cfg.OIDC.AccountURL, "oidc-account-url", baseconfig.GetEnv("PORTAL_OIDC_ACCOUNT_URL", ""), "IdP account/profile page the SPA navigates to after logout. Keycloak: <issuer>/account/. Okta: /profile. Empty = fall back to portal root. env: PORTAL_OIDC_ACCOUNT_URL")

	// Store
	fs.StringVar(&cfg.Store.URL, "store", baseconfig.GetEnv("PORTAL_STORE", "memory"), "Store URL: memory | sqlite::memory: | sqlite:///path | postgres://... (env: PORTAL_STORE)")
	fs.StringVar(&cfg.Store.SecretboxKeyEnv, "secretbox-key-env", baseconfig.GetEnv("PORTAL_SECRETBOX_KEY_ENV", "SECRETBOX_KEY"), "Env var holding the base64 32-byte key used to encrypt at-rest secrets; empty = disabled (plaintext at rest)")

	// Audit
	fs.IntVar(&cfg.Audit.RetentionDays, "audit-retention-days", baseconfig.GetEnvInt("PORTAL_AUDIT_RETENTION_DAYS", 30), "Drop audit rows older than N days; 0 disables (env: PORTAL_AUDIT_RETENTION_DAYS)")
	fs.IntVar(&cfg.Audit.MaxEntries, "audit-max-entries", baseconfig.GetEnvInt("PORTAL_AUDIT_MAX_ENTRIES", 10_000_000), "Hard cap on audit rows; 0 disables (env: PORTAL_AUDIT_MAX_ENTRIES)")
	fs.DurationVar(&cfg.Audit.SweepInterval, "audit-sweep-interval", getEnvDuration("PORTAL_AUDIT_SWEEP_INTERVAL", time.Hour), "Interval between audit retention sweeps; <=0 disables (env: PORTAL_AUDIT_SWEEP_INTERVAL)")

	// Approval
	fs.BoolVar(&cfg.Approval.AutoApprove, "auto-approve", getEnvBool("PORTAL_AUTO_APPROVE", false), "Auto-approve grants on create — bootstrap/demo only (env: PORTAL_AUTO_APPROVE)")
	fs.StringVar(&cfg.Approval.WebhookURL, "approval-webhook-url", baseconfig.GetEnv("PORTAL_APPROVAL_WEBHOOK_URL", ""), "Webhook URL POSTed on grant_requested (env: PORTAL_APPROVAL_WEBHOOK_URL, empty disables)")
	fs.StringVar(&cfg.Approval.WebhookSecret, "approval-webhook-secret", baseconfig.GetEnv("PORTAL_APPROVAL_WEBHOOK_SECRET", ""), "HMAC-SHA256 secret for X-Portal-Signature on approval webhooks (env: PORTAL_APPROVAL_WEBHOOK_SECRET)")

	// Ephemeral
	fs.BoolVar(&cfg.EphemeralAccounts, "ephemeral-accounts", getEnvBool("PORTAL_EPHEMERAL_ACCOUNTS", false), "Provision per-grant backend users on approve, drop on revoke/expire (env: PORTAL_EPHEMERAL_ACCOUNTS)")

	// Rate limit
	fs.IntVar(&cfg.RateLimit.PerIP, "auth-rate-per-ip", baseconfig.GetEnvInt("PORTAL_AUTH_RATE_PER_IP", 60), "Auth/grant requests allowed per minute per source IP; 0 disables (env: PORTAL_AUTH_RATE_PER_IP)")
	fs.IntVar(&cfg.RateLimit.PerUser, "auth-rate-per-user", baseconfig.GetEnvInt("PORTAL_AUTH_RATE_PER_USER", 30), "Auth/grant requests allowed per minute per username; 0 disables (env: PORTAL_AUTH_RATE_PER_USER)")

	// Entra
	fs.StringVar(&cfg.Entra.TenantID, "entra-tenant-id", baseconfig.GetEnv("PORTAL_ENTRA_TENANT_ID", ""), "Entra tenant id / directory id (env: PORTAL_ENTRA_TENANT_ID)")
	fs.StringVar(&cfg.Entra.ClientID, "entra-client-id", baseconfig.GetEnv("PORTAL_ENTRA_CLIENT_ID", ""), "Entra app registration client id (env: PORTAL_ENTRA_CLIENT_ID)")
	fs.StringVar(&cfg.Entra.ClientSecret, "entra-client-secret", baseconfig.GetEnv("PORTAL_ENTRA_CLIENT_SECRET", ""), "Entra app registration client secret (env: PORTAL_ENTRA_CLIENT_SECRET)")
	fs.StringVar(&cfg.Entra.SenderUPN, "entra-sender", baseconfig.GetEnv("PORTAL_ENTRA_SENDER", ""), "Mailbox UPN Graph /sendMail runs as (env: PORTAL_ENTRA_SENDER)")
	fs.StringVar(&cfg.Entra.PolicyFile, "entra-policy-file", baseconfig.GetEnv("PORTAL_ENTRA_POLICY_FILE", ""), "Path to YAML group->backend/role policy (env: PORTAL_ENTRA_POLICY_FILE)")
	fs.StringVar(&cfg.Entra.T2Mailbox, "t2-mailbox", baseconfig.GetEnv("PORTAL_T2_MAILBOX", ""), "Reachability fallback mailbox appended to every gate2 (admin-tier) notification regardless of the backend's T2 group (env: PORTAL_T2_MAILBOX). Primary T2 recipients are resolved per-backend via backends.t2_group_slug.")

	// Windows
	fs.DurationVar(&cfg.Windows.Validation, "validation-window", getEnvDuration("PORTAL_VALIDATION_WINDOW", 24*time.Hour), "PENDING/VALIDATOR_APPROVED grants expire after this window (env: PORTAL_VALIDATION_WINDOW)")
	fs.DurationVar(&cfg.Windows.Claim, "claim-window", getEnvDuration("PORTAL_CLAIM_WINDOW", time.Hour), "APPROVED grants expire if not claimed within this window (env: PORTAL_CLAIM_WINDOW)")
	fs.DurationVar(&cfg.Windows.CredentialTTL, "credential-ttl", getEnvDuration("PORTAL_CREDENTIAL_TTL", time.Hour), "ACTIVE grants expire this long after /claim (env: PORTAL_CREDENTIAL_TTL)")

	return cfg
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
// Anything not explicitly listed here is omitted — add fields as needed;
// the default is deny.
func (c *Config) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("listen", c.HTTP.ListenAddr),
		slog.String("store", c.Store.URL),
		slog.Bool("oidc_enabled", c.OIDC.Enabled()),
		slog.String("oidc_issuer", c.OIDC.IssuerURL),
		slog.String("oidc_client_secret", redactIfSet(c.OIDC.ClientSecret)),
		slog.Bool("entra_enabled", c.Entra.Enabled()),
		slog.String("entra_tenant", c.Entra.TenantID),
		slog.String("entra_client_secret", redactIfSet(c.Entra.ClientSecret)),
		slog.String("entra_sender", c.Entra.SenderUPN),
		slog.String("entra_policy_file", c.Entra.PolicyFile),
		slog.String("approval_webhook_secret", redactIfSet(c.Approval.WebhookSecret)),
		slog.String("user_token", redactIfSet(c.UserToken)),
		slog.String("proxy_token", redactIfSet(c.ProxyToken)),
		slog.String("public_url", c.HTTP.PublicURL),
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
	if c.HTTP.ListenAddr == "" {
		return fmt.Errorf("listen address must not be empty")
	}
	if c.HTTP.ReadHeaderTimeout < 0 || c.HTTP.ReadTimeout < 0 || c.HTTP.WriteTimeout < 0 || c.HTTP.ShutdownGrace < 0 {
		return fmt.Errorf("timeouts must be >= 0")
	}
	// When Entra is enabled the admin half of the dual-gate must reach
	// somebody — a mailbox or a resolved group. Bail early so an operator
	// doesn't ship a portal that silently strands every grant at
	// VALIDATOR_APPROVED.
	if c.Entra.Enabled() && c.Entra.T2Mailbox == "" {
		return fmt.Errorf("entra enabled but no gate2 reachability fallback: set -t2-mailbox (primary recipients come from each backend's t2_group_slug)")
	}
	if c.Windows.Validation < 0 || c.Windows.Claim < 0 {
		return fmt.Errorf("validation/claim windows must be >= 0")
	}
	// CredentialTTL of exactly 0 is rejected (not just < 0): the claim handler
	// computes the ephemeral account's expiry as now+TTL, so a zero TTL mints a
	// credential that is born expired (or, depending on the downstream
	// comparison, never expires) — both are unsafe. Unset still defaults to 1h
	// via RegisterFlags; this gate only catches an explicit -credential-ttl=0.
	if c.Windows.CredentialTTL <= 0 {
		return fmt.Errorf("credential-ttl must be > 0 (got %s); a zero TTL produces a non-expiring or already-expired ephemeral credential", c.Windows.CredentialTTL)
	}
	// Security fail-safe: refuse to boot with NO authentication path on a
	// non-loopback listener. With empty ProxyToken AND empty UserToken AND OIDC
	// disabled, both bearer guards are off and /api/v1/auth (full credential
	// vending) is reachable unauthenticated. That is only tolerable bound to
	// localhost for local dev; on any externally reachable address it would
	// silently expose credential vending, so we hard-fail instead.
	if c.ProxyToken == "" && c.UserToken == "" && !c.OIDC.Enabled() && !isLoopbackListen(c.HTTP.ListenAddr) {
		return fmt.Errorf("no authentication configured (empty -proxy-token, empty -user-token, OIDC disabled) on non-loopback listen %q: set at least one auth path or bind to loopback for local dev", c.HTTP.ListenAddr)
	}
	return nil
}

// isLoopbackListen reports whether addr binds only to the loopback interface.
// A bare ":port" / "0.0.0.0:port" / "[::]:port" listens on every interface and
// is treated as non-loopback. An empty host is also non-loopback (it binds all
// interfaces), but that case is caught earlier by the empty-listen check.
func isLoopbackListen(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// No port present (or malformed) — treat the whole string as the host.
		host = addr
	}
	if host == "" {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
