// Package secretbox implements an in-application secret-storage envelope on
// top of libsodium's crypto_secretbox (XSalsa20-Poly1305).
//
// Layout (bytes):
//
//   version (3) | nonce (24) | secretbox_output
//
// where `secretbox_output` is NaCl's standard crypto_secretbox — the 16-byte
// Poly1305 tag followed by the XSalsa20-encrypted plaintext.
//
// The 3-byte version tag is `0x00 0x00 0x01`. The whole binary blob is
// base64-encoded for transport; because the version tag aligns on a 3-byte
// boundary, its base64 encoding is the constant 4-character prefix `AAAB` —
// callers use IsEncrypted to recognise an envelope without attempting a
// decrypt. A future algorithm revision gets a new version tag (e.g.
// `0x00 0x00 0x02`, base64 `AAAC`), letting Decrypt refuse to touch payloads
// it doesn't know how to handle.
package secretbox

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"golang.org/x/crypto/nacl/secretbox"
)

const (
	// KeySize is the required symmetric key length, in bytes. XSalsa20 needs
	// a 32-byte key (SODIUM_CRYPTO_SECRETBOX_KEYBYTES).
	KeySize = 32
	// NonceSize is the XSalsa20 nonce length. 24 bytes → random nonces are
	// safe; collision probability is negligible.
	NonceSize = 24
	// MACSize is the Poly1305 authentication tag NaCl prepends to ciphertext.
	MACSize = 16
)

// VersionPrefix is the base64 prefix that identifies an encrypted payload.
// Kept in both base64 and binary form so callers can fast-reject strings
// before decoding (IsEncrypted) and we can assert on the header bytes.
const VersionPrefix = "AAAB"

// versionBytes is the binary form of VersionPrefix. base64("AAAB") == 0x00 0x00 0x01.
var versionBytes = []byte{0x00, 0x00, 0x01}

// Sentinel errors so callers can distinguish "wrong format" from
// "authentication failed" from "bad key length".
var (
	// ErrInvalidKey is returned when the caller-supplied key is not KeySize bytes.
	ErrInvalidKey = errors.New("secretbox: key must be 32 bytes")
	// ErrInvalidVersion is returned when the decoded payload does not start with
	// the expected version header — either not our format at all, or a future
	// version we don't yet understand.
	ErrInvalidVersion = errors.New("secretbox: invalid version header")
	// ErrDecryption is returned on authentication failure or short ciphertext.
	// The underlying cause is intentionally coarse so a tampered payload and
	// a random blob produce the same error — leaks nothing about which layer
	// of the envelope rejected the input.
	ErrDecryption = errors.New("secretbox: decryption failed")
	// ErrBadBase64 is returned when the encoded input isn't valid base64.
	ErrBadBase64 = errors.New("secretbox: invalid base64")
)

// IsEncrypted returns true when s carries the SecretBox version prefix — a
// cheap string check that lets callers recognise our envelope without
// attempting a decrypt. Does NOT validate the ciphertext.
func IsEncrypted(s string) bool {
	return len(s) >= len(VersionPrefix) && s[:len(VersionPrefix)] == VersionPrefix
}

// Encrypt seals plaintext with key and returns the base64-encoded envelope.
// The nonce is generated from crypto/rand on every call — callers MUST NOT
// try to reuse nonces externally; the format intentionally hides it from them.
func Encrypt(plaintext, key []byte) (string, error) {
	if len(key) != KeySize {
		return "", ErrInvalidKey
	}
	var nonce [NonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", fmt.Errorf("secretbox: generate nonce: %w", err)
	}
	var secretKey [KeySize]byte
	copy(secretKey[:], key)

	// secretbox.Seal returns out = MAC || ciphertext. We prepend version + nonce.
	envelope := make([]byte, 0, len(versionBytes)+NonceSize+MACSize+len(plaintext))
	envelope = append(envelope, versionBytes...)
	envelope = append(envelope, nonce[:]...)
	envelope = secretbox.Seal(envelope, plaintext, &nonce, &secretKey)

	return base64.StdEncoding.EncodeToString(envelope), nil
}

// Decrypt reverses Encrypt. Returns ErrInvalidVersion when the header doesn't
// match (i.e. the value is either not SecretBox-encrypted or is a version
// we don't support). Returns ErrDecryption on authentication failure — the
// caller should treat that as potential tampering and NOT retry.
func Decrypt(encoded string, key []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKey
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadBase64, err)
	}
	// Minimum valid length: version + nonce + at least the MAC.
	if len(raw) < len(versionBytes)+NonceSize+MACSize {
		return nil, fmt.Errorf("%w: ciphertext too short", ErrDecryption)
	}
	if !bytesEqual(raw[:len(versionBytes)], versionBytes) {
		return nil, ErrInvalidVersion
	}
	var nonce [NonceSize]byte
	copy(nonce[:], raw[len(versionBytes):len(versionBytes)+NonceSize])
	var secretKey [KeySize]byte
	copy(secretKey[:], key)

	ciphertext := raw[len(versionBytes)+NonceSize:]
	plaintext, ok := secretbox.Open(nil, ciphertext, &nonce, &secretKey)
	if !ok {
		return nil, ErrDecryption
	}
	return plaintext, nil
}

// bytesEqual is a tiny standalone equal without pulling in bytes just for one
// comparison. Not constant-time — the version header isn't secret.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
