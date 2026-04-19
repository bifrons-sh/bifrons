package ephemeral

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/babs/poc-proxies/portal/internal/domain"
	"github.com/babs/poc-proxies/portal/internal/secrets"
	"github.com/babs/poc-proxies/portal/internal/store"
)

// DBALookup returns the DBA credential for a given backend. Concrete
// implementations pull from the Store's BackendAccount (role=dba). Abstracted
// so tests can plant a stub without seeding a real store.
type DBALookup func(ctx context.Context, backendID string) (DBACredential, error)

// NewStoreDBALookup returns a DBALookup that reads the BackendAccount with
// role=dba from the given store and resolves PasswordRef via the secrets
// package. Fail-closed: a missing DBA account surfaces as ErrNoDBACredential
// so the approve handler can fall back to the shared-account path and log a
// warning instead of silently provisioning nothing.
func NewStoreDBALookup(s store.Store) DBALookup {
	return func(ctx context.Context, backendID string) (DBACredential, error) {
		acct, err := s.GetBackendAccount(ctx, backendID, domain.RoleDBA)
		if err != nil {
			return DBACredential{}, ErrNoDBACredential
		}
		// PasswordRef (external secret) takes precedence; fall back to
		// the row-stored Password (decrypted by the Encrypting store).
		pw := acct.Password
		if acct.PasswordRef != "" {
			resolved, rerr := secrets.Resolve(acct.PasswordRef)
			if rerr != nil {
				return DBACredential{}, fmt.Errorf("resolve DBA password: %w", rerr)
			}
			pw = resolved
		}
		return DBACredential{Username: acct.Username, Password: pw}, nil
	}
}

// Manager routes Provision/Revoke calls to the per-backend driver. One Manager
// per portal process; lookups are threadsafe once constructed.
type Manager struct {
	provs   map[BackendType]Provisioner
	logger  *slog.Logger
	metrics *Metrics
}

// NewManager wires drivers keyed by backend type. Passing a nil driver
// disables that backend — callers should not register nil entries.
func NewManager(provs map[BackendType]Provisioner, m *Metrics, logger *slog.Logger) *Manager {
	if logger == nil {
		logger = slog.Default()
	}
	return &Manager{provs: provs, logger: logger, metrics: m}
}

// Provision dispatches to the driver for req.BackendType.
func (m *Manager) Provision(ctx context.Context, req ProvisionRequest) (ProvisionedAccount, error) {
	p, ok := m.provs[req.BackendType]
	if !ok {
		m.metrics.IncProvisionFailed()
		return ProvisionedAccount{}, fmt.Errorf("ephemeral: no provisioner for backend type %q", req.BackendType)
	}
	acct, err := p.Provision(ctx, req)
	if err != nil {
		m.metrics.IncProvisionFailed()
		return ProvisionedAccount{}, err
	}
	m.metrics.IncProvisioned()
	return acct, nil
}

// Revoke dispatches to the driver, picking the backend type from the stored
// grant. backendType is decoupled from the account struct because the account
// deliberately doesn't carry protocol metadata.
func (m *Manager) Revoke(ctx context.Context, backendType BackendType, acct ProvisionedAccount) error {
	p, ok := m.provs[backendType]
	if !ok {
		m.metrics.IncRevokeFailed()
		return fmt.Errorf("ephemeral: no provisioner for backend type %q", backendType)
	}
	if err := p.Revoke(ctx, acct); err != nil {
		m.metrics.IncRevokeFailed()
		return err
	}
	m.metrics.IncRevoked()
	return nil
}

// Metrics exposes the underlying counter holder so the obs sidecar can
// snapshot it.
func (m *Manager) Metrics() *Metrics { return m.metrics }

// MapBackendType translates a proxy type to the ephemeral package's
// BackendType. Returns "" when no provisioner exists for that proxy.
func MapBackendType(pt domain.ProxyType) BackendType {
	switch pt {
	case domain.ProxyPostgres:
		return BackendPostgres
	case domain.ProxyMySQL:
		return BackendMySQL
	case domain.ProxyMongo:
		return BackendMongo
	}
	return ""
}
