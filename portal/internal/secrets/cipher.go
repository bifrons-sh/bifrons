package secrets

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"sync/atomic"

	"github.com/babs/poc-proxies/portal/internal/secrets/secretbox"
)

// Cipher transparently wraps a plaintext secret on write and unwraps it on
// read. Two impls ship: Noop (passthrough, default) and SecretboxCipher
// (SecretBox envelope — see portal/internal/secrets/secretbox).
//
// The interface deliberately uses strings (not []byte) because every caller
// already has strings — the underlying columns are TEXT/VARCHAR and every
// consumer (policy engine, /claim response) hands them to an HTTP body.
// Converting to []byte at the boundary would add noise without adding safety.
type Cipher interface {
	// EncryptIfPlaintext wraps s unless it's already in cipher format.
	// Returns s unchanged when already encrypted (idempotent on repeated writes)
	// or when s is empty (stores NULL / "" without ever invoking crypto).
	EncryptIfPlaintext(s string) (string, error)
	// DecryptIfEncrypted unwraps s if it carries the cipher's version prefix;
	// otherwise returns s unchanged so legacy plaintext rows continue to read.
	// Legacy plaintext is a one-time migration signal, not a steady state —
	// callers should re-write via EncryptIfPlaintext at the next opportunity.
	DecryptIfEncrypted(s string) (string, error)
}

// Noop is the zero-behaviour Cipher — returns its input unchanged.
// Used when no SECRETBOX_KEY is configured (local dev / tests).
type Noop struct{}

// EncryptIfPlaintext implements Cipher.
func (Noop) EncryptIfPlaintext(s string) (string, error) { return s, nil }

// DecryptIfEncrypted implements Cipher.
func (Noop) DecryptIfEncrypted(s string) (string, error) { return s, nil }

// SecretboxCipher encrypts with the SecretBox format. The key is
// 32 bytes of raw key material — typically loaded via LoadKeyFromEnv which
// base64-decodes the env var value.
type SecretboxCipher struct {
	key []byte
	// legacyReads counts how many plaintext reads slipped through — operators
	// watch this to know when the migration is done (should hit zero once
	// every row has been re-written once).
	legacyReads atomic.Uint64
}

// NewSecretboxCipher returns a Cipher that wraps values with secretbox.Encrypt.
// Returns an error when key is not exactly secretbox.KeySize (32) bytes —
// an undersized key is a boot-time configuration error, not a runtime surprise.
func NewSecretboxCipher(key []byte) (*SecretboxCipher, error) {
	if len(key) != secretbox.KeySize {
		return nil, fmt.Errorf("secrets: secretbox key must be %d bytes, got %d", secretbox.KeySize, len(key))
	}
	buf := make([]byte, secretbox.KeySize)
	copy(buf, key)
	return &SecretboxCipher{key: buf}, nil
}

// EncryptIfPlaintext implements Cipher. Empty and already-encrypted inputs
// pass through untouched.
func (c *SecretboxCipher) EncryptIfPlaintext(s string) (string, error) {
	if s == "" {
		return "", nil
	}
	if secretbox.IsEncrypted(s) {
		return s, nil
	}
	return secretbox.Encrypt([]byte(s), c.key)
}

// DecryptIfEncrypted implements Cipher.
func (c *SecretboxCipher) DecryptIfEncrypted(s string) (string, error) {
	if s == "" {
		return "", nil
	}
	if !secretbox.IsEncrypted(s) {
		// Legacy plaintext — readable for back-compat with pre-cipher rows,
		// but bump the counter so operators can see the migration's tail.
		c.legacyReads.Add(1)
		return s, nil
	}
	pt, err := secretbox.Decrypt(s, c.key)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

// LegacyReads returns the number of unencrypted reads observed since boot.
// Exported for the obs sidecar; zero means the migration is complete.
func (c *SecretboxCipher) LegacyReads() uint64 { return c.legacyReads.Load() }

// LoadKeyFromEnv returns the decoded key bytes from envVar or an error. The
// expected format is base64-encoded 32 bytes (matching the  PHP/Python
// impls, which use `base64_decode($_ENV['SECRETBOX_KEY'])`).
func LoadKeyFromEnv(envVar string) ([]byte, error) {
	raw, ok := os.LookupEnv(envVar)
	if !ok || raw == "" {
		return nil, fmt.Errorf("secrets: %s not set", envVar)
	}
	key, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("secrets: %s not valid base64: %w", envVar, err)
	}
	if len(key) != secretbox.KeySize {
		return nil, fmt.Errorf("secrets: %s decoded to %d bytes, want %d", envVar, len(key), secretbox.KeySize)
	}
	return key, nil
}

// ErrEmptyKey is returned by LoadKeyFromEnv when the env var is unset — split
// out so callers can distinguish "no key configured" (fall back to Noop) from
// "configured but broken" (fail boot).
var ErrEmptyKey = errors.New("secrets: env var not set")
