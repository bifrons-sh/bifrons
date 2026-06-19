package config

import (
	"flag"
	"fmt"
	"os"
	"time"
)

// GetEnv returns the value of env var key, or fallback when unset/empty.
// Exposed so main binaries and sibling packages read env vars consistently
// instead of each re-implementing the same fallback helper.
func GetEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// GetEnvInt returns the integer value of env var key, or fallback when
// unset/empty or unparseable. Exported alongside GetEnv so the integer-env
// helper lives in one place rather than being copied per package.
func GetEnvInt(key string, fallback int) int {
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

// Config holds shared proxy configuration.
type Config struct {
	ListenAddr  string
	BackendAddr string

	// Client-facing TLS (client → proxy)
	ClientTLSEnabled  bool
	ClientCertFile    string
	ClientKeyFile     string
	ClientCACertFile  string // enables mTLS when set
	ClientTLSRequired bool   // require + verify client cert when ClientCACertFile is set

	// ClientTLSCBRequired, when true, forces SCRAM-SHA-256-PLUS (channel binding)
	// on TLS-wrapped client connections and rejects plain SCRAM-SHA-256. Only
	// meaningful to Postgres, which is the one proxy that terminates SCRAM on
	// the client side; ignored elsewhere.
	ClientTLSCBRequired bool

	// Backend TLS (proxy → backend)
	BackendTLSEnabled  bool
	BackendCACertFile  string
	BackendCertFile    string // mTLS to backend (optional)
	BackendKeyFile     string
	BackendTLSInsecure bool

	// Resilience
	MaxConns            int           // 0 = unlimited
	HandshakeTimeout    time.Duration // deadline for auth/handshake phase
	IdleTimeout         time.Duration // rolling deadline during relay (0 = none)
	BackendDialTimeout  time.Duration
	ShutdownGracePeriod time.Duration

	// Observability sidecar
	MetricsAddr string // empty disables

	// Rate limiting (phase 2.1). Per-IP token bucket applied to new client
	// connections BEFORE the auth/handshake step, so compute-heavy ops
	// (PBKDF2 inside SCRAM) cannot be exhausted by a single attacker.
	// 0 disables the per-IP bucket — MaxConns remains as the global cap.
	AuthRatePerIP int // accepts allowed per minute per client IP

	// Reserved for future per-user accept limits; wired on the flag surface
	// to keep parity with the portal. Currently unused at accept time
	// (username isn't known until after handshake).
	AuthRatePerUser int

	// RateLimitCloseDelay bounds the sleep-then-close window on the proxy
	// accept side: rejected TCP connections are held open briefly so a
	// misbehaving client doesn't see an instant RST-loop and retry harder.
	RateLimitCloseDelay time.Duration
}

// RegisterFlags registers common CLI flags on fs and returns a Config populated after fs.Parse().
// Callers should set defaultListen/defaultBackend per protocol before calling fs.Parse().
//
// Environment-variable fallbacks (for 12-factor deployments): each flag below
// checks the matching `PROXY_*` env var as its default, so e.g. `PROXY_LISTEN`
// seeds `-listen`, `PROXY_BACKEND` seeds `-backend`, `PROXY_METRICS_ADDR`
// seeds `-metrics-addr`. Explicit flags always win over the env fallback.
func RegisterFlags(fs *flag.FlagSet, defaultListen, defaultBackend string) *Config {
	cfg := &Config{}
	fs.StringVar(&cfg.ListenAddr, "listen", GetEnv("PROXY_LISTEN", defaultListen), "Listen address (env: PROXY_LISTEN)")
	fs.StringVar(&cfg.BackendAddr, "backend", GetEnv("PROXY_BACKEND", defaultBackend), "Backend address (env: PROXY_BACKEND)")

	fs.BoolVar(&cfg.ClientTLSEnabled, "client-tls", false, "Enable TLS for client connections (listener-level; see protocol docs)")
	fs.StringVar(&cfg.ClientCertFile, "client-tls-cert", "", "TLS certificate for client-facing listener")
	fs.StringVar(&cfg.ClientKeyFile, "client-tls-key", "", "TLS key for client-facing listener")
	fs.StringVar(&cfg.ClientCACertFile, "client-tls-ca", "", "CA bundle to verify client certificates (enables mTLS)")
	fs.BoolVar(&cfg.ClientTLSRequired, "client-tls-required", false, "Require a valid client certificate (mTLS)")
	fs.BoolVar(&cfg.ClientTLSCBRequired, "client-tls-cb-required", GetEnv("PROXY_CLIENT_TLS_CB_REQUIRED", "") == "1" || GetEnv("PROXY_CLIENT_TLS_CB_REQUIRED", "") == "true",
		"Require SCRAM-SHA-256-PLUS (channel binding) from TLS-wrapped clients; rejects plain SCRAM on TLS conns (env: PROXY_CLIENT_TLS_CB_REQUIRED)")

	fs.BoolVar(&cfg.BackendTLSEnabled, "backend-tls", false, "Enable TLS for backend connections")
	fs.StringVar(&cfg.BackendCACertFile, "backend-tls-ca", "", "CA certificate to verify backend")
	fs.StringVar(&cfg.BackendCertFile, "backend-tls-cert", "", "Client certificate for mTLS to backend")
	fs.StringVar(&cfg.BackendKeyFile, "backend-tls-key", "", "Client key for mTLS to backend")
	fs.BoolVar(&cfg.BackendTLSInsecure, "backend-tls-insecure", false, "Skip backend TLS certificate verification")

	fs.IntVar(&cfg.MaxConns, "max-conns", 1024, "Maximum concurrent client connections (0 = unlimited)")
	fs.DurationVar(&cfg.HandshakeTimeout, "handshake-timeout", 15*time.Second, "Deadline for auth/handshake phase")
	fs.DurationVar(&cfg.IdleTimeout, "idle-timeout", 5*time.Minute, "Idle deadline during relay (0 = none)")
	fs.DurationVar(&cfg.BackendDialTimeout, "backend-dial-timeout", 5*time.Second, "Backend dial timeout")
	fs.DurationVar(&cfg.ShutdownGracePeriod, "shutdown-grace-period", 30*time.Second, "Graceful drain window on SIGINT/SIGTERM")

	// 9091 avoids conflict with Prometheus server's default port 9090.
	fs.StringVar(&cfg.MetricsAddr, "metrics-addr", GetEnv("PROXY_METRICS_ADDR", "127.0.0.1:9091"), "Address for /healthz + /metrics (empty disables, env: PROXY_METRICS_ADDR)")

	// Accept-side rate limit (phase 2.1). Defaults mirror the portal — 60/min
	// per IP is aggressive enough to stop a SCRAM-spam attacker without
	// impacting connection-pool-backed clients that reconnect in bursts.
	fs.IntVar(&cfg.AuthRatePerIP, "auth-rate-per-ip", GetEnvInt("PROXY_AUTH_RATE_PER_IP", 60), "Accepts allowed per minute per source IP (env: PROXY_AUTH_RATE_PER_IP; 0 disables)")
	fs.IntVar(&cfg.AuthRatePerUser, "auth-rate-per-user", GetEnvInt("PROXY_AUTH_RATE_PER_USER", 30), "Reserved: per-user accept budget (env: PROXY_AUTH_RATE_PER_USER; unused today)")
	fs.DurationVar(&cfg.RateLimitCloseDelay, "rate-limit-close-delay", 100*time.Millisecond, "Sleep-then-close window on rate-limited accepts")

	return cfg
}

// Validate reports invalid or mutually inconsistent flag combinations. Call
// after fs.Parse() to fail fast instead of surfacing the problem on first
// connection.
func (c *Config) Validate() error {
	if c.ListenAddr == "" {
		return fmt.Errorf("listen address must not be empty")
	}
	if c.BackendAddr == "" {
		return fmt.Errorf("backend address must not be empty")
	}
	if c.ClientTLSEnabled && (c.ClientCertFile == "" || c.ClientKeyFile == "") {
		return fmt.Errorf("client-tls requires client-tls-cert and client-tls-key")
	}
	if c.ClientTLSRequired && c.ClientCACertFile == "" {
		return fmt.Errorf("client-tls-required needs client-tls-ca to verify against")
	}
	if c.BackendTLSEnabled && c.BackendTLSInsecure && c.BackendCACertFile != "" {
		return fmt.Errorf("backend-tls-insecure conflicts with backend-tls-ca — pick one")
	}
	if c.MaxConns < 0 {
		return fmt.Errorf("max-conns must be >= 0")
	}
	if c.HandshakeTimeout < 0 {
		return fmt.Errorf("handshake-timeout must be >= 0")
	}
	if c.BackendDialTimeout < 0 {
		return fmt.Errorf("backend-dial-timeout must be >= 0")
	}
	return nil
}
