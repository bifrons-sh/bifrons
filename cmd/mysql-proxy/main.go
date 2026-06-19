package main

import (
	"flag"
	"os"
	"time"

	"github.com/babs/poc-proxies/internal/config"
	"github.com/babs/poc-proxies/internal/obs"
	"github.com/babs/poc-proxies/internal/protocol/mysql"
	"github.com/babs/poc-proxies/internal/proxy"
)

var (
	Version        = "v0.0.0"
	CommitHash     = "0000000"
	BuildTimestamp = "unknown"
	Builder        = "unknown"
)

func main() {
	cfg := config.RegisterFlags(flag.CommandLine, "127.0.0.1:13306", "127.0.0.1:3306")
	authURL := flag.String("auth-url", config.GetEnv("PROXY_AUTH_URL", ""), "Portal auth URL (env: PROXY_AUTH_URL, enables auth re-mapping)")
	auditURL := flag.String("audit-url", config.GetEnv("PROXY_AUDIT_URL", ""), "Portal audit URL (env: PROXY_AUDIT_URL, enables audit shipping)")
	portalBase := flag.String("portal-url", config.GetEnv("PROXY_PORTAL_URL", ""), "Portal base URL for mid-session revoke polling (env: PROXY_PORTAL_URL, enables revoke watcher)")
	portalToken := flag.String("portal-token", config.GetEnv("PROXY_PORTAL_TOKEN", ""), "Shared secret sent as X-Portal-Token (env: PROXY_PORTAL_TOKEN)")
	flag.Parse()

	err := proxy.RunService(proxy.ServiceSpec{
		Name:        "mysql-proxy",
		DBSystem:    "mysql",
		Build:       obs.BuildInfo{Version: Version, CommitHash: CommitHash, BuildTimestamp: BuildTimestamp, Builder: Builder},
		Cfg:         cfg,
		AuthURL:     *authURL,
		AuditURL:    *auditURL,
		PortalBase:  *portalBase,
		PortalToken: *portalToken,
		BuildHandler: func(deps proxy.HandlerDeps) (proxy.BuiltHandler, error) {
			h := mysql.NewFromConfig(deps.Logger, deps.AuthClient, deps.AuditClient, deps.Cfg).WithMetrics(deps.Metrics)
			if deps.PortalBase != "" {
				h.WithRevokeClient(proxy.NewHTTPGrantStatusClient(deps.PortalBase, deps.PortalToken, 3*time.Second))
				deps.Logger.Info("mid-session revoke watcher enabled", "portal_url", deps.PortalBase)
			}
			return proxy.BuiltHandler{Handler: h}, nil
		},
	})
	if err != nil {
		os.Exit(1)
	}
}
