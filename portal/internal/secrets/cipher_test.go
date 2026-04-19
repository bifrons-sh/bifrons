package secrets

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/babs/poc-proxies/portal/internal/secrets/secretbox"
)

func newCipher(t *testing.T) *SecretboxCipher {
	t.Helper()
	key := make([]byte, secretbox.KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	c, err := NewSecretboxCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestSecretboxCipher_RoundTrip(t *testing.T) {
	c := newCipher(t)
	enc, err := c.Encrypt("hello")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(enc, secretbox.VersionPrefix) {
		t.Errorf("missing version prefix: %q", enc)
	}
	pt, err := c.Decrypt(enc)
	if err != nil {
		t.Fatal(err)
	}
	if pt != "hello" {
		t.Errorf("roundtrip mismatch: %q", pt)
	}
}

func TestSecretboxCipher_EmptyPassthrough(t *testing.T) {
	c := newCipher(t)
	for _, op := range []struct {
		name string
		fn   func(string) (string, error)
	}{
		{"Encrypt", c.Encrypt},
		{"Decrypt", c.Decrypt},
	} {
		got, err := op.fn("")
		if err != nil {
			t.Errorf("%s(\"\"): %v", op.name, err)
		}
		if got != "" {
			t.Errorf("%s(\"\") = %q, want \"\"", op.name, got)
		}
	}
}

// TestSecretboxCipher_DecryptNonEnvelopedFailsClosed: any non-empty value
// that doesn't carry the SecretBox header MUST surface an error — there is
// no "legacy plaintext" fallback.
func TestSecretboxCipher_DecryptNonEnvelopedFailsClosed(t *testing.T) {
	c := newCipher(t)
	// Base64-valid but long enough to pass the minimum-length check — the
	// version header "CCCC" (0x08 0x20 0x82) is NOT 0x00 0x00 0x01.
	junk := strings.Repeat("C", 80)
	if _, err := c.Decrypt(junk); !errors.Is(err, secretbox.ErrInvalidVersion) {
		t.Errorf("want ErrInvalidVersion on non-enveloped base64, got %v", err)
	}
}

func TestNoop_PassThrough(t *testing.T) {
	n := Noop{}
	got, err := n.Encrypt("abc")
	if err != nil || got != "abc" {
		t.Errorf("Noop.Encrypt(abc) = %q, %v", got, err)
	}
	got, err = n.Decrypt("abc")
	if err != nil || got != "abc" {
		t.Errorf("Noop.Decrypt(abc) = %q, %v", got, err)
	}
}

func TestNewSecretboxCipher_RejectsBadKey(t *testing.T) {
	if _, err := NewSecretboxCipher(make([]byte, 16)); err == nil {
		t.Error("16-byte key should be rejected")
	}
}

func TestLoadKeyFromEnv_Unset(t *testing.T) {
	if _, err := LoadKeyFromEnv("PORTAL_TEST_UNSET_VAR"); err == nil {
		t.Error("unset env var should surface error")
	}
}

func TestLoadKeyFromEnv_Roundtrip(t *testing.T) {
	key := make([]byte, secretbox.KeySize)
	_, _ = rand.Read(key)
	t.Setenv("PORTAL_TEST_KEY", b64(key))
	got, err := LoadKeyFromEnv("PORTAL_TEST_KEY")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != secretbox.KeySize {
		t.Errorf("wrong length: %d", len(got))
	}
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
