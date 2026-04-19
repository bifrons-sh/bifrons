package secretbox

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func newKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, KeySize)
	if _, err := rand.Read(k); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return k
}

func TestRoundtrip(t *testing.T) {
	key := newKey(t)
	inputs := [][]byte{
		[]byte("hello"),
		[]byte(""),
		bytes.Repeat([]byte{0xAA}, 10_000),
		[]byte("multi\nline\n\x00with nulls"),
	}
	for i, in := range inputs {
		enc, err := Encrypt(in, key)
		if err != nil {
			t.Fatalf("[%d] Encrypt: %v", i, err)
		}
		if !IsEncrypted(enc) {
			t.Errorf("[%d] IsEncrypted=false for our own output", i)
		}
		if !strings.HasPrefix(enc, VersionPrefix) {
			t.Errorf("[%d] missing AAAB prefix", i)
		}
		got, err := Decrypt(enc, key)
		if err != nil {
			t.Fatalf("[%d] Decrypt: %v", i, err)
		}
		if !bytes.Equal(got, in) {
			t.Errorf("[%d] roundtrip mismatch", i)
		}
	}
}

func TestNonceUniqueness(t *testing.T) {
	key := newKey(t)
	a, _ := Encrypt([]byte("same"), key)
	b, _ := Encrypt([]byte("same"), key)
	if a == b {
		t.Fatal("two encrypts of identical plaintext produced identical ciphertext — nonce reuse")
	}
}

func TestTamperDetection(t *testing.T) {
	key := newKey(t)
	enc, err := Encrypt([]byte("payload"), key)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.StdEncoding.DecodeString(enc)
	// Flip a bit in the ciphertext region (after version+nonce).
	raw[len(versionBytes)+NonceSize+MACSize] ^= 0x01
	tampered := base64.StdEncoding.EncodeToString(raw)
	if _, err := Decrypt(tampered, key); !errors.Is(err, ErrDecryption) {
		t.Errorf("tampered ciphertext should fail auth, got %v", err)
	}
}

func TestInvalidVersion(t *testing.T) {
	key := newKey(t)
	// Manually-crafted payload with wrong version bytes.
	raw := make([]byte, 3+NonceSize+MACSize+8)
	raw[0], raw[1], raw[2] = 0xDE, 0xAD, 0xBE
	if _, err := Decrypt(base64.StdEncoding.EncodeToString(raw), key); !errors.Is(err, ErrInvalidVersion) {
		t.Errorf("want ErrInvalidVersion, got %v", err)
	}
}

func TestBadKey(t *testing.T) {
	if _, err := Encrypt([]byte("x"), []byte("short")); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("Encrypt short key: want ErrInvalidKey, got %v", err)
	}
	if _, err := Decrypt("AAAB", []byte("short")); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("Decrypt short key: want ErrInvalidKey, got %v", err)
	}
}

func TestShortCiphertext(t *testing.T) {
	key := newKey(t)
	// Valid base64, valid version, but truncated before a full MAC.
	raw := append([]byte{}, versionBytes...)
	raw = append(raw, bytes.Repeat([]byte{0x00}, NonceSize)...) // nonce placeholder
	raw = append(raw, 0x00, 0x01)                                // < MACSize bytes of "ciphertext"
	if _, err := Decrypt(base64.StdEncoding.EncodeToString(raw), key); !errors.Is(err, ErrDecryption) {
		t.Errorf("want ErrDecryption on short ciphertext, got %v", err)
	}
}

func TestBadBase64(t *testing.T) {
	key := newKey(t)
	if _, err := Decrypt("!!!not-base64!!!", key); !errors.Is(err, ErrBadBase64) {
		t.Errorf("want ErrBadBase64, got %v", err)
	}
}

func TestIsEncrypted(t *testing.T) {
	if IsEncrypted("") {
		t.Error("empty string")
	}
	if IsEncrypted("plaintext") {
		t.Error("plaintext")
	}
	if !IsEncrypted("AAAB...") {
		t.Error("AAAB-prefix should match")
	}
}

// TestInteropHeader guards the on-the-wire invariant: the first three binary
// bytes are 0x00 0x00 0x01, which is exactly base64 "AAAB". If either side of
// this drifts the cross-format interop is lost.
func TestInteropHeader(t *testing.T) {
	key := newKey(t)
	enc, _ := Encrypt([]byte("x"), key)
	raw, _ := base64.StdEncoding.DecodeString(enc)
	if !bytes.Equal(raw[:3], []byte{0x00, 0x00, 0x01}) {
		t.Errorf("version bytes=%v want 0x00 0x00 0x01", raw[:3])
	}
	if !strings.HasPrefix(enc, "AAAB") {
		t.Errorf("prefix=%q want AAAB", enc[:4])
	}
}
