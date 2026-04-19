// Package portal exposes a public factory for embedding the portal HTTP service
// (router + in-memory store) into other processes, notably end-to-end tests.
// Production binaries should use the CLI in cmd/portal.
package portal

import (
	"log/slog"
	"net/http"

	"github.com/babs/poc-proxies/portal/internal/api"
	"github.com/babs/poc-proxies/portal/internal/config"
	"github.com/babs/poc-proxies/portal/internal/domain"
	"github.com/babs/poc-proxies/portal/internal/ephemeral"
	"github.com/babs/poc-proxies/portal/internal/oidc"
	"github.com/babs/poc-proxies/portal/internal/policy"
	"github.com/babs/poc-proxies/portal/internal/store"
)

// Ephemeral re-exports the backend-account provisioner package so embedders
// (notably e2e tests) can wire a real or mocked provisioner without reaching
// into internal/.
type (
	EphemeralManager        = ephemeral.Manager
	EphemeralProvisioner    = ephemeral.Provisioner
	EphemeralProvisionReq   = ephemeral.ProvisionRequest
	EphemeralProvisionedAct = ephemeral.ProvisionedAccount
	EphemeralBackendType    = ephemeral.BackendType
	EphemeralDBACredential  = ephemeral.DBACredential
	EphemeralDBALookup      = ephemeral.DBALookup
)

const (
	EphemeralBackendPostgres = ephemeral.BackendPostgres
	EphemeralBackendMySQL    = ephemeral.BackendMySQL
	EphemeralBackendMongo    = ephemeral.BackendMongo
)

// NewEphemeralManager wires a Manager with the given provisioner map. See
// ephemeral.NewManager.
func NewEphemeralManager(provs map[EphemeralBackendType]EphemeralProvisioner, logger *slog.Logger) *EphemeralManager {
	return ephemeral.NewManager(provs, ephemeral.NewMetrics(), logger)
}

// NewStoreDBALookup returns a DBALookup that reads the BackendAccount with
// role=dba from the given store. See ephemeral.NewStoreDBALookup.
func NewStoreDBALookup(s Store) EphemeralDBALookup {
	return ephemeral.NewStoreDBALookup(s)
}

// NewPostgresProvisioner re-exports ephemeral.NewPostgresProvisioner.
func NewPostgresProvisioner(lookup EphemeralDBALookup) EphemeralProvisioner {
	return ephemeral.NewPostgresProvisioner(lookup, nil)
}

// NewMySQLProvisioner re-exports ephemeral.NewMySQLProvisioner.
func NewMySQLProvisioner(lookup EphemeralDBALookup) EphemeralProvisioner {
	return ephemeral.NewMySQLProvisioner(lookup, nil)
}

// NewMongoProvisioner re-exports ephemeral.NewMongoProvisioner.
func NewMongoProvisioner(lookup EphemeralDBALookup) EphemeralProvisioner {
	return ephemeral.NewMongoProvisioner(lookup, nil)
}

// Store aliases the internal Store interface so callers don't need to reach into internal/.
type Store = store.Store

// AuditFilter re-exports the store's filter so e2e callers can list audit entries.
type AuditFilter = store.AuditFilter

// AuditEntry re-exports the audit record shape for embedders.
type AuditEntry = domain.AuditEntry

// Config aliases the internal config struct.
type Config = config.Config

// OIDCProvider is re-exported so embedders can pass a provider built via
// oidc.New into NewHandlerWithOIDC without importing the internal package.
type OIDCProvider = oidc.Provider

// Grant, Backend, User, GrantStatus re-exported so e2e / embedder callers can
// assert on portal state without touching internal packages.
type (
	Grant       = domain.Grant
	Backend     = domain.Backend
	User        = domain.User
	GrantStatus = domain.GrantStatus
	Role        = domain.Role
	ProxyType   = domain.ProxyType
)

const (
	GrantApproved = domain.GrantApproved
	GrantRevoked  = domain.GrantRevoked
	GrantExpired  = domain.GrantExpired
)

// NewMemoryStore returns a fresh in-memory Store.
func NewMemoryStore() Store { return store.NewMemory() }

// NewHandler builds the HTTP handler serving all portal endpoints, without
// OIDC. Equivalent to NewHandlerWithOIDC(cfg, s, nil, logger).
func NewHandler(cfg *Config, s Store, logger *slog.Logger) http.Handler {
	return NewHandlerWithOIDC(cfg, s, nil, logger)
}

// NewHandlerWithOIDC builds the HTTP handler with optional OIDC session auth.
// When provider is nil, behaves exactly like NewHandler (static bearer only).
func NewHandlerWithOIDC(cfg *Config, s Store, provider *OIDCProvider, logger *slog.Logger) http.Handler {
	return api.NewRouter(cfg, s, policy.New(s), provider, logger)
}

// NewHandlerWithEphemeral builds the HTTP handler wired to the given
// ephemeral-account Manager. Pass a nil manager to disable ephemeral
// provisioning (handler falls back to the shared BackendAccount path).
func NewHandlerWithEphemeral(cfg *Config, s Store, provider *OIDCProvider, mgr *EphemeralManager, logger *slog.Logger) http.Handler {
	return api.NewRouterWithEphemeral(cfg, s, policy.New(s), provider, mgr, logger)
}
