package store_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/babs/poc-proxies/portal/internal/domain"
	"github.com/babs/poc-proxies/portal/internal/secrets"
	"github.com/babs/poc-proxies/portal/internal/secrets/secretbox"
	"github.com/babs/poc-proxies/portal/internal/store"
)

func newTestCipher(t *testing.T) secrets.Cipher {
	t.Helper()
	key := make([]byte, secretbox.KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	c, err := secrets.NewSecretboxCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestEncrypting_BackendAccountRoundtrip verifies the invariant: what we Get
// matches what we Upsert, AND the raw row in the underlying Store is in
// cipher form (never reveals plaintext even if the DB file leaks).
func TestEncrypting_BackendAccountRoundtrip(t *testing.T) {
	raw := store.NewMemory()
	enc := store.NewEncrypting(raw, newTestCipher(t), slog.New(slog.NewJSONHandler(io.Discard, nil)))
	ctx := context.Background()

	_ = raw.CreateBackend(ctx, domain.Backend{ID: "b-1", Name: "pg", Type: domain.ProxyPostgres, Host: "h", Port: 5432})
	acct := domain.BackendAccount{
		ID: "ba-1", BackendID: "b-1", Role: domain.RoleApp,
		Username: "app", Password: "the-very-secret-pw",
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := enc.UpsertBackendAccount(ctx, acct); err != nil {
		t.Fatal(err)
	}

	// Raw store holds ciphertext.
	stored, err := raw.GetBackendAccount(ctx, "b-1", domain.RoleApp)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(stored.Password, secretbox.VersionPrefix) {
		t.Errorf("stored password missing %q prefix: %q", secretbox.VersionPrefix, stored.Password)
	}
	if strings.Contains(stored.Password, "the-very-secret-pw") {
		t.Errorf("plaintext leaked into stored row: %q", stored.Password)
	}

	// Wrapped store returns plaintext.
	got, err := enc.GetBackendAccount(ctx, "b-1", domain.RoleApp)
	if err != nil {
		t.Fatal(err)
	}
	if got.Password != "the-very-secret-pw" {
		t.Errorf("decrypted=%q want original plaintext", got.Password)
	}
}

// TestEncrypting_GrantSecretsRoundtrip: PortalPassword + EphemeralPassword
// follow the same encrypt-at-rest / decrypt-on-read contract.
func TestEncrypting_GrantSecretsRoundtrip(t *testing.T) {
	raw := store.NewMemory()
	enc := store.NewEncrypting(raw, newTestCipher(t), slog.New(slog.NewJSONHandler(io.Discard, nil)))
	ctx := context.Background()

	_ = raw.CreateUser(ctx, domain.User{ID: "u-1", Username: "alice", Status: "active"})
	_ = raw.CreateBackend(ctx, domain.Backend{ID: "b-1", Name: "pg", Type: domain.ProxyPostgres, Host: "h", Port: 5432})
	exp := time.Now().Add(time.Hour)
	g := domain.Grant{
		ID: "g-1", UserID: "u-1", BackendID: "b-1", Status: domain.GrantActive,
		Role: domain.RoleApp, Database: "orders",
		PortalPassword:    "portal-shh",
		EphemeralUsername: "portal_grant_xx",
		EphemeralPassword: "ephemeral-shh",
		ExpiresAt:         &exp,
		RequestedAt:       time.Now(), CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := enc.CreateGrant(ctx, g); err != nil {
		t.Fatal(err)
	}

	stored, _ := raw.GetGrant(ctx, "g-1")
	for name, v := range map[string]string{"portal": stored.PortalPassword, "ephemeral": stored.EphemeralPassword} {
		if !strings.HasPrefix(v, secretbox.VersionPrefix) {
			t.Errorf("%s password not encrypted at rest: %q", name, v)
		}
	}
	if bytes.Contains([]byte(stored.PortalPassword+stored.EphemeralPassword), []byte("shh")) {
		t.Errorf("plaintext substring leaked into stored grant")
	}

	got, _ := enc.GetGrant(ctx, "g-1")
	if got.PortalPassword != "portal-shh" || got.EphemeralPassword != "ephemeral-shh" {
		t.Errorf("decrypted round-trip mismatch: %+v", got)
	}

	// ListGrants must also decrypt.
	gs, _ := enc.ListGrants(ctx, store.GrantFilter{UserID: "u-1"})
	if len(gs) != 1 || gs[0].PortalPassword != "portal-shh" {
		t.Errorf("ListGrants decrypt failed: %+v", gs)
	}
}

// TestEncrypting_LegacyPlaintextStillReadable: rows written before the cipher
// landed continue to read cleanly, bumping the legacy-reads counter so the
// migration's tail is observable.
func TestEncrypting_LegacyPlaintextStillReadable(t *testing.T) {
	raw := store.NewMemory()
	cipher := newTestCipher(t).(*secrets.SecretboxCipher)
	enc := store.NewEncrypting(raw, cipher, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	ctx := context.Background()

	// Seed the RAW store directly — simulating a pre-cipher row.
	_ = raw.CreateBackend(ctx, domain.Backend{ID: "b-1", Name: "pg", Type: domain.ProxyPostgres, Host: "h", Port: 5432})
	_ = raw.UpsertBackendAccount(ctx, domain.BackendAccount{
		ID: "ba-1", BackendID: "b-1", Role: domain.RoleApp,
		Username: "app", Password: "legacy-plaintext",
	})
	before := cipher.LegacyReads()

	got, err := enc.GetBackendAccount(ctx, "b-1", domain.RoleApp)
	if err != nil {
		t.Fatalf("legacy read: %v", err)
	}
	if got.Password != "legacy-plaintext" {
		t.Errorf("legacy read mismatch: %q", got.Password)
	}
	if cipher.LegacyReads() != before+1 {
		t.Errorf("legacy-reads counter not bumped (before=%d after=%d)", before, cipher.LegacyReads())
	}
}

// TestEncrypting_NoopPassthrough: Noop cipher leaves plaintext untouched at
// rest — confirms operators who haven't configured SECRETBOX_KEY still get a
// working portal.
func TestEncrypting_NoopPassthrough(t *testing.T) {
	raw := store.NewMemory()
	enc := store.NewEncrypting(raw, secrets.Noop{}, nil)
	ctx := context.Background()

	_ = raw.CreateBackend(ctx, domain.Backend{ID: "b-1", Name: "pg", Type: domain.ProxyPostgres, Host: "h", Port: 5432})
	_ = enc.UpsertBackendAccount(ctx, domain.BackendAccount{
		ID: "ba-1", BackendID: "b-1", Role: domain.RoleApp, Username: "app", Password: "pt",
	})
	stored, _ := raw.GetBackendAccount(ctx, "b-1", domain.RoleApp)
	if stored.Password != "pt" {
		t.Errorf("noop should pass through, got %q", stored.Password)
	}
}

// TestEncrypting_SetGrantEphemeral: the dedicated ephemeral write path must
// also encrypt.
func TestEncrypting_SetGrantEphemeral(t *testing.T) {
	raw := store.NewMemory()
	enc := store.NewEncrypting(raw, newTestCipher(t), slog.New(slog.NewJSONHandler(io.Discard, nil)))
	ctx := context.Background()

	_ = raw.CreateUser(ctx, domain.User{ID: "u-1", Username: "alice", Status: "active"})
	_ = raw.CreateBackend(ctx, domain.Backend{ID: "b-1", Name: "pg", Type: domain.ProxyPostgres, Host: "h", Port: 5432})
	exp := time.Now().Add(time.Hour)
	_ = enc.CreateGrant(ctx, domain.Grant{
		ID: "g-1", UserID: "u-1", BackendID: "b-1", Status: domain.GrantActive,
		Role: domain.RoleApp, PortalPassword: "p", ExpiresAt: &exp,
		RequestedAt: time.Now(), CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	if err := enc.SetGrantEphemeral(ctx, "g-1", "portal_grant_x", "ephemeral-pw"); err != nil {
		t.Fatal(err)
	}
	stored, _ := raw.GetGrant(ctx, "g-1")
	if !strings.HasPrefix(stored.EphemeralPassword, secretbox.VersionPrefix) {
		t.Errorf("SetGrantEphemeral left plaintext at rest: %q", stored.EphemeralPassword)
	}
	got, _ := enc.GetGrant(ctx, "g-1")
	if got.EphemeralPassword != "ephemeral-pw" {
		t.Errorf("decrypt mismatch: %q", got.EphemeralPassword)
	}
}
