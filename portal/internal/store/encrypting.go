package store

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/babs/poc-proxies/portal/internal/domain"
	"github.com/babs/poc-proxies/portal/internal/secrets"
)

// Encrypting wraps a Store so the at-rest secret columns are transparently
// SecretBox-encrypted on write and decrypted on read. The wrapped fields are:
//
//   * BackendAccount.Password
//   * Grant.PortalPassword
//   * Grant.EphemeralPassword
//
// Other columns (usernames, hashes, IDs) go through untouched. Plaintext rows
// predating the cipher keep working: the Cipher's DecryptIfEncrypted checks
// the version prefix and passes legacy values through, so a partially-migrated
// DB is still fully readable. Next write re-encrypts.
//
// The decorator preserves every method of the underlying Store via embedding;
// only the methods that touch one of the three secret fields override.
type Encrypting struct {
	Store
	cipher secrets.Cipher
	logger *slog.Logger
}

// NewEncrypting wraps s so reads and writes of the known secret columns are
// run through cipher. A nil cipher falls back to Noop so callers can pass it
// unconditionally.
func NewEncrypting(s Store, cipher secrets.Cipher, logger *slog.Logger) *Encrypting {
	if cipher == nil {
		cipher = secrets.Noop{}
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Encrypting{Store: s, cipher: cipher, logger: logger}
}

// --- backend accounts ---

func (e *Encrypting) UpsertBackendAccount(ctx context.Context, a domain.BackendAccount) error {
	enc, err := e.cipher.EncryptIfPlaintext(a.Password)
	if err != nil {
		return fmt.Errorf("encrypt backend account password: %w", err)
	}
	a.Password = enc
	return e.Store.UpsertBackendAccount(ctx, a)
}

func (e *Encrypting) GetBackendAccount(ctx context.Context, backendID string, role domain.Role) (domain.BackendAccount, error) {
	a, err := e.Store.GetBackendAccount(ctx, backendID, role)
	if err != nil {
		return a, err
	}
	pt, err := e.cipher.DecryptIfEncrypted(a.Password)
	if err != nil {
		// Decryption failure on a row that LOOKS encrypted means either the
		// key rotated without a re-encryption sweep, or the ciphertext was
		// tampered with. Either way we must NOT return the blob to callers.
		e.logger.Error("backend_account_decrypt_failed", "backend_id", backendID, "role", string(role), "err", err)
		return domain.BackendAccount{}, fmt.Errorf("decrypt backend account password: %w", err)
	}
	a.Password = pt
	return a, nil
}

// --- grants ---

func (e *Encrypting) CreateGrant(ctx context.Context, g domain.Grant) error {
	g, err := e.encryptGrantSecrets(g)
	if err != nil {
		return err
	}
	return e.Store.CreateGrant(ctx, g)
}

func (e *Encrypting) UpdateGrant(ctx context.Context, g domain.Grant) error {
	g, err := e.encryptGrantSecrets(g)
	if err != nil {
		return err
	}
	return e.Store.UpdateGrant(ctx, g)
}

func (e *Encrypting) UpdateGrantIfStatus(ctx context.Context, g domain.Grant, expect domain.GrantStatus) error {
	g, err := e.encryptGrantSecrets(g)
	if err != nil {
		return err
	}
	return e.Store.UpdateGrantIfStatus(ctx, g, expect)
}

func (e *Encrypting) SetGrantEphemeral(ctx context.Context, id, username, password string) error {
	enc, err := e.cipher.EncryptIfPlaintext(password)
	if err != nil {
		return fmt.Errorf("encrypt ephemeral password: %w", err)
	}
	return e.Store.SetGrantEphemeral(ctx, id, username, enc)
}

func (e *Encrypting) GetGrant(ctx context.Context, id string) (domain.Grant, error) {
	g, err := e.Store.GetGrant(ctx, id)
	if err != nil {
		return g, err
	}
	return e.decryptGrantSecrets(g, id)
}

func (e *Encrypting) ListGrants(ctx context.Context, filter GrantFilter) ([]domain.Grant, error) {
	gs, err := e.Store.ListGrants(ctx, filter)
	if err != nil {
		return gs, err
	}
	for i, g := range gs {
		dec, err := e.decryptGrantSecrets(g, g.ID)
		if err != nil {
			// Drop the unreadable row from the list rather than 500-ing the
			// whole query — admin UIs keep working while operators fix the key.
			e.logger.Error("grant_decrypt_skipped_in_list", "grant_id", g.ID, "err", err)
			continue
		}
		gs[i] = dec
	}
	return gs, nil
}

// ExpireStaleGrants and ExpireUnclaimedGrants are pure status flips that never
// read/write the secret columns, so the embedded Store's impl passes through
// unchanged — no override needed.

// ListEphemeralOrphans is surfaced to the sweeper; the rows it returns feed
// straight into provisioner.Revoke, which needs the EphemeralUsername (not the
// password). We still decrypt both so the struct is consistent — revoke logic
// should never rely on the password anyway.
func (e *Encrypting) ListEphemeralOrphans(ctx context.Context) ([]domain.Grant, error) {
	gs, err := e.Store.ListEphemeralOrphans(ctx)
	if err != nil {
		return gs, err
	}
	for i, g := range gs {
		dec, err := e.decryptGrantSecrets(g, g.ID)
		if err != nil {
			e.logger.Error("orphan_grant_decrypt_failed", "grant_id", g.ID, "err", err)
			continue
		}
		gs[i] = dec
	}
	return gs, nil
}

// --- helpers ---

func (e *Encrypting) encryptGrantSecrets(g domain.Grant) (domain.Grant, error) {
	if pp, err := e.cipher.EncryptIfPlaintext(g.PortalPassword); err != nil {
		return g, fmt.Errorf("encrypt portal password: %w", err)
	} else {
		g.PortalPassword = pp
	}
	if ep, err := e.cipher.EncryptIfPlaintext(g.EphemeralPassword); err != nil {
		return g, fmt.Errorf("encrypt ephemeral password: %w", err)
	} else {
		g.EphemeralPassword = ep
	}
	return g, nil
}

func (e *Encrypting) decryptGrantSecrets(g domain.Grant, grantID string) (domain.Grant, error) {
	pp, err := e.cipher.DecryptIfEncrypted(g.PortalPassword)
	if err != nil {
		e.logger.Error("grant_portal_password_decrypt_failed", "grant_id", grantID, "err", err)
		return g, err
	}
	g.PortalPassword = pp
	ep, err := e.cipher.DecryptIfEncrypted(g.EphemeralPassword)
	if err != nil {
		e.logger.Error("grant_ephemeral_password_decrypt_failed", "grant_id", grantID, "err", err)
		return g, err
	}
	g.EphemeralPassword = ep
	return g, nil
}

// _ keeps the unused-import linter happy during incremental builds before the
// wrapper is wired up in main.go.
var _ time.Time
