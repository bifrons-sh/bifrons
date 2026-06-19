package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/babs/poc-proxies/internal/auth"
	"github.com/babs/poc-proxies/internal/config"
	"github.com/babs/poc-proxies/internal/obs"
	"github.com/babs/poc-proxies/internal/protocol/postgres"
	"github.com/babs/poc-proxies/internal/proxy"
	"github.com/babs/poc-proxies/internal/tlsutil"
)

var (
	Version        = "v0.0.0"
	CommitHash     = "0000000"
	BuildTimestamp = "unknown"
	Builder        = "unknown"
)

func main() {
	cfg := config.RegisterFlags(flag.CommandLine, "127.0.0.1:15432", "127.0.0.1:5432")
	authURL := flag.String("auth-url", config.GetEnv("PROXY_AUTH_URL", ""), "Portal auth URL (env: PROXY_AUTH_URL, enables auth re-mapping)")
	auditURL := flag.String("audit-url", config.GetEnv("PROXY_AUDIT_URL", ""), "Portal audit URL (env: PROXY_AUDIT_URL, enables audit shipping)")
	portalBase := flag.String("portal-url", config.GetEnv("PROXY_PORTAL_URL", ""), "Portal base URL for mid-session revoke polling (env: PROXY_PORTAL_URL, enables revoke watcher)")
	portalToken := flag.String("portal-token", config.GetEnv("PROXY_PORTAL_TOKEN", ""), "Shared secret sent as X-Portal-Token (env: PROXY_PORTAL_TOKEN)")
	clientAuthMethod := flag.String("client-auth-method", "scram", "client-facing auth method when re-mapping: scram | cleartext")
	scramCacheSize := flag.Int("scram-cache-size", 1024, "Max entries in the PBKDF2 stored-credentials cache (0 disables caching)")
	scramCacheTTL := flag.Duration("scram-cache-ttl", 5*time.Minute, "Lifetime for SCRAM stored-credentials cache entries")
	flag.Parse()

	// Validate the client-auth-method up front (only meaningful when re-mapping
	// is on). Bad config is a usage error → exit 2, matching the other flags.
	authMethod := postgres.ClientAuthMethod(*clientAuthMethod)
	if *authURL != "" {
		switch authMethod {
		case postgres.ClientAuthSCRAM, postgres.ClientAuthCleartext:
			// ok
		default:
			fmt.Fprintf(os.Stderr, "invalid -client-auth-method %q (allowed: scram|cleartext)\n", *clientAuthMethod)
			os.Exit(2)
		}
	}

	err := proxy.RunService(proxy.ServiceSpec{
		Name:        "postgres-proxy",
		DBSystem:    "postgresql",
		ForcePlain:  true, // PG negotiates TLS via SSLRequest on an open TCP conn
		Build:       obs.BuildInfo{Version: Version, CommitHash: CommitHash, BuildTimestamp: BuildTimestamp, Builder: Builder},
		Cfg:         cfg,
		AuthURL:     *authURL,
		AuditURL:    *auditURL,
		PortalBase:  *portalBase,
		PortalToken: *portalToken,
		BuildHandler: func(deps proxy.HandlerDeps) (proxy.BuiltHandler, error) {
			if deps.AuthClient != nil {
				deps.Logger.Info("postgres client auth method", "client_auth_method", *clientAuthMethod)
			}
			// PostgreSQL must always listen plaintext: the wire protocol negotiates
			// TLS via SSLRequest on an already-open TCP connection. The handler
			// upgrades inside handleStartup when a cert/key is supplied.
			var sslRequestTLS *tls.Config
			if deps.Cfg.ClientCertFile != "" && deps.Cfg.ClientKeyFile != "" {
				var terr error
				sslRequestTLS, terr = tlsutil.ListenerTLSConfig(deps.Cfg.ClientCertFile, deps.Cfg.ClientKeyFile, deps.Cfg.ClientCACertFile, deps.Cfg.ClientTLSRequired)
				if terr != nil {
					return proxy.BuiltHandler{}, fmt.Errorf("load SSL request TLS config: %w", terr)
				}
			}

			h := postgres.NewFromConfig(deps.Logger, sslRequestTLS, deps.AuthClient, deps.AuditClient, authMethod, deps.Cfg).WithMetrics(deps.Metrics)
			if deps.PortalBase != "" {
				h.WithRevokeClient(proxy.NewHTTPGrantStatusClient(deps.PortalBase, deps.PortalToken, 3*time.Second))
				deps.Logger.Info("mid-session revoke watcher enabled", "portal_url", deps.PortalBase)
			}
			// PBKDF2 caching only matters on the SCRAM path; cleartext client auth
			// doesn't hit PBKDF2 and pass-through mode has no stored-creds derivation.
			var scramStats obs.ScramCacheStatsFn
			if deps.AuthClient != nil && authMethod == postgres.ClientAuthSCRAM && *scramCacheSize > 0 {
				cache := auth.NewSCRAMCache(*scramCacheSize, *scramCacheTTL)
				h.WithSCRAMCache(cache)
				scramStats = cache.Stats
				deps.Logger.Info("scram stored-creds cache enabled", "size", *scramCacheSize, "ttl", *scramCacheTTL)
			}
			return proxy.BuiltHandler{Handler: h, ScramCacheStats: scramStats}, nil
		},
	})
	if err != nil {
		os.Exit(1)
	}
}
