package secrets

import (
	"encoding/base64"
	"fmt"
	"os"

	"github.com/babs/poc-proxies/portal/internal/secrets/secretbox"
)

// Cipher encrypts a plaintext secret on write and decrypts ciphertext on read.
// Two impls ship: Noop (passthrough — tests / local dev) and SecretboxCipher
// (SecretBox envelope — see portal/internal/secrets/secretbox).
//
// The interface uses strings because every caller already has strings — the
// underlying columns are TEXT/VARCHAR and every consumer (policy engine,
// /claim response) hands them to an HTTP body. Converting to []byte at the
// boundary would add noise without adding safety.
type Cipher interface {
	// Encrypt wraps s with the cipher's envelope. Empty string maps to empty
	// string — "no secret" is not a secret.
	Encrypt(s string) (string, error)
	// Decrypt unwraps s. Empty string maps to empty string. Any non-empty
	// input that does not carry the cipher's version header is an error —
	// the wire contract is "encrypted or absent", and any other state is
	// corruption. Callers MUST treat a decrypt error as a hard failure.
	Decrypt(s string) (string, error)
}

// Noop is the zero-behaviour Cipher — returns its input unchanged. Used in
// tests and explicitly-opted-out local dev.
type Noop struct{}

// Encrypt implements Cipher.
func (Noop) Encrypt(s string) (string, error) { return s, nil }

// Decrypt implements Cipher.
func (Noop) Decrypt(s string) (string, error) { return s, nil }

// SecretboxCipher encrypts with the SecretBox envelope defined in
// portal/internal/secrets/secretbox. The key is 32 bytes of raw key material,
// typically loaded via LoadKeyFromEnv (base64-decoded from the env var value).
type SecretboxCipher struct {
	key []byte
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

// Encrypt implements Cipher. Empty input passes through.
func (c *SecretboxCipher) Encrypt(s string) (string, error) {
	if s == "" {
		return "", nil
	}
	return secretbox.Encrypt([]byte(s), c.key)
}

// Decrypt implements Cipher. Empty input passes through. Anything non-empty
// that doesn't carry the SecretBox version header surfaces
// secretbox.ErrInvalidVersion — a loud signal that something wrote to the
// column bypassing the cipher, not a valid state to silently accept.
func (c *SecretboxCipher) Decrypt(s string) (string, error) {
	if s == "" {
		return "", nil
	}
	pt, err := secretbox.Decrypt(s, c.key)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

// LoadKeyFromEnv returns the decoded key bytes from envVar or an error. The
// expected format is a base64-encoded 32-byte key.
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
