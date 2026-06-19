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
//   - BackendAccount.Password
//   - Grant.PortalPassword
//   - Grant.EphemeralPassword
//
// Other columns (usernames, hashes, IDs) pass through untouched via struct
// embedding. Any value written to one of the three secret columns MUST go
// through this wrapper — the Cipher treats a non-encrypted read as corruption.
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
	enc, err := e.cipher.Encrypt(a.Password)
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
	pt, err := e.cipher.Decrypt(a.Password)
	if err != nil {
		// Key rotated without re-encryption, or ciphertext tampered. Never
		// return the blob to callers — fail loud.
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
	enc, err := e.cipher.Encrypt(password)
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
		dec, derr := e.decryptGrantSecrets(g, g.ID)
		if derr != nil {
			// Drop the unreadable row from the list rather than 500-ing the
			// whole query — admin UIs keep working while operators fix the key.
			e.logger.Error("grant_decrypt_skipped_in_list", "grant_id", g.ID, "err", derr)
			continue
		}
		gs[i] = dec
	}
	return gs, nil
}

// ExpireStaleGrants / ExpireUnclaimedGrants are pure status flips that never
// touch the secret columns, so the embedded Store's impls pass through.

// ListEphemeralOrphans feeds into provisioner.Revoke, which needs the
// EphemeralUsername. Decrypt both secrets for struct consistency even though
// revoke should not rely on the password.
func (e *Encrypting) ListEphemeralOrphans(ctx context.Context) ([]domain.Grant, error) {
	gs, err := e.Store.ListEphemeralOrphans(ctx)
	if err != nil {
		return gs, err
	}
	for i, g := range gs {
		dec, derr := e.decryptGrantSecrets(g, g.ID)
		if derr != nil {
			e.logger.Error("orphan_grant_decrypt_failed", "grant_id", g.ID, "err", derr)
			continue
		}
		gs[i] = dec
	}
	return gs, nil
}

// --- provisioning outbox ---
//
// Both result columns are encrypted at rest (the username is sensitive infra
// detail, not just the password — spec §8.4.1). InsertIntent carries no result
// (the portal emits an empty-result row; the worker fills it later via
// CompleteIntent), so it needs no wrapping and passes through the embed.

// CompleteIntent encrypts the worker-provisioned credential before it lands in
// the result columns.
func (e *Encrypting) CompleteIntent(ctx context.Context, id, workerID, resultUsername, resultPassword string) error {
	encUser, err := e.cipher.Encrypt(resultUsername)
	if err != nil {
		return fmt.Errorf("encrypt intent result username: %w", err)
	}
	encPass, err := e.cipher.Encrypt(resultPassword)
	if err != nil {
		return fmt.Errorf("encrypt intent result password: %w", err)
	}
	return e.Store.CompleteIntent(ctx, id, workerID, encUser, encPass)
}

func (e *Encrypting) GetIntent(ctx context.Context, id string) (domain.Intent, error) {
	in, err := e.Store.GetIntent(ctx, id)
	if err != nil {
		return in, err
	}
	return e.decryptIntentSecrets(in)
}

func (e *Encrypting) GetLatestIntentForGrant(ctx context.Context, grantID string, kind domain.IntentKind) (domain.Intent, error) {
	in, err := e.Store.GetLatestIntentForGrant(ctx, grantID, kind)
	if err != nil {
		return in, err
	}
	return e.decryptIntentSecrets(in)
}

// ClaimPendingIntents decrypts result columns defensively: a stale-reclaimed
// in_flight row could already carry a partial result written by the worker
// that died, so a freshly-claimed row is not guaranteed to be result-empty.
func (e *Encrypting) ClaimPendingIntents(ctx context.Context, workerID string, instanceWhitelist []string, lease time.Duration, limit int) ([]domain.Intent, error) {
	ins, err := e.Store.ClaimPendingIntents(ctx, workerID, instanceWhitelist, lease, limit)
	if err != nil {
		return ins, err
	}
	for i := range ins {
		dec, derr := e.decryptIntentSecrets(ins[i])
		if derr != nil {
			// Surface the failure: a claimed row the caller can't decrypt is a
			// key-rotation / corruption signal, not something to silently hide.
			e.logger.Error("intent_decrypt_failed_in_claim", "intent_id", ins[i].ID, "err", derr)
			return nil, fmt.Errorf("decrypt claimed intent %s: %w", ins[i].ID, derr)
		}
		ins[i] = dec
	}
	return ins, nil
}

// --- worker liveness ---
//
// Heartbeat rows carry no secrets — backend_ids and per-instance health are
// operational metadata, not credentials — so UpsertWorkerHeartbeat /
// ListWorkerHeartbeats / PruneStaleWorkers are intentionally NOT overridden
// here; they pass straight through the embedded Store.

func (e *Encrypting) decryptIntentSecrets(in domain.Intent) (domain.Intent, error) {
	// Empty result columns (the common pending/in_flight case) decrypt to
	// empty under the Noop and SecretBox ciphers alike, so no special-casing.
	u, err := e.cipher.Decrypt(in.ResultUsername)
	if err != nil {
		e.logger.Error("intent_result_username_decrypt_failed", "intent_id", in.ID, "err", err)
		return in, err
	}
	in.ResultUsername = u
	p, err := e.cipher.Decrypt(in.ResultPassword)
	if err != nil {
		e.logger.Error("intent_result_password_decrypt_failed", "intent_id", in.ID, "err", err)
		return in, err
	}
	in.ResultPassword = p
	return in, nil
}

// --- helpers ---

func (e *Encrypting) encryptGrantSecrets(g domain.Grant) (domain.Grant, error) {
	pp, err := e.cipher.Encrypt(g.PortalPassword)
	if err != nil {
		return g, fmt.Errorf("encrypt portal password: %w", err)
	}
	g.PortalPassword = pp
	ep, err := e.cipher.Encrypt(g.EphemeralPassword)
	if err != nil {
		return g, fmt.Errorf("encrypt ephemeral password: %w", err)
	}
	g.EphemeralPassword = ep
	return g, nil
}

func (e *Encrypting) decryptGrantSecrets(g domain.Grant, grantID string) (domain.Grant, error) {
	pp, err := e.cipher.Decrypt(g.PortalPassword)
	if err != nil {
		e.logger.Error("grant_portal_password_decrypt_failed", "grant_id", grantID, "err", err)
		return g, err
	}
	g.PortalPassword = pp
	ep, err := e.cipher.Decrypt(g.EphemeralPassword)
	if err != nil {
		e.logger.Error("grant_ephemeral_password_decrypt_failed", "grant_id", grantID, "err", err)
		return g, err
	}
	g.EphemeralPassword = ep
	return g, nil
}
