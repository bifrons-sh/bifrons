package mysql

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // RSA-OAEP with SHA-1 is the algorithm the MySQL caching_sha2 wire format uses.
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestTrimPluginData(t *testing.T) {
	if got := trimPluginData([]byte{1, 2, 3, 0}); !bytes.Equal(got, []byte{1, 2, 3}) {
		t.Errorf("trailing NUL not trimmed: %v", got)
	}
	if got := trimPluginData([]byte{1, 2, 3}); !bytes.Equal(got, []byte{1, 2, 3}) {
		t.Errorf("unchanged data mutated: %v", got)
	}
	if got := trimPluginData(nil); got != nil && len(got) != 0 {
		t.Errorf("nil input: %v", got)
	}
}

func TestFirstByte(t *testing.T) {
	if firstByte(nil) != 0 {
		t.Error("nil should yield 0")
	}
	if firstByte([]byte{0xAB}) != 0xAB {
		t.Error("byte mismatch")
	}
}

func TestBuildHandshakeResponse41Plugin_PluginName(t *testing.T) {
	pkt := buildHandshakeResponse41Plugin("alice", bytes.Repeat([]byte{0xCC}, 32), "orders", cachingSha2Password)
	if !bytes.Contains(pkt, []byte(cachingSha2Password)) {
		t.Error("plugin name missing from packet")
	}
	if !bytes.Contains(pkt, []byte("alice")) {
		t.Error("username missing")
	}
	if !bytes.Contains(pkt, []byte("orders")) {
		t.Error("database missing")
	}
}

// TestEncryptCachingSHA2Password_RoundTrip verifies the masking + RSA-OAEP-SHA1
// encryption is reversible with a freshly-generated test keypair, and that the
// recovered plaintext matches `password||NUL`.
func TestEncryptCachingSHA2Password_RoundTrip(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	nonce := []byte("nonce1234567890ABCDE") // 20 bytes
	password := "s3cret!"

	ct, err := encryptCachingSHA2Password(password, nonce, &priv.PublicKey)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	plain, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, priv, ct, nil)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	// Unmask: XOR with the repeated nonce, expect `password||NUL`.
	for i := range plain {
		plain[i] ^= nonce[i%len(nonce)]
	}
	want := append([]byte(password), 0x00)
	if !bytes.Equal(plain, want) {
		t.Errorf("recovered plaintext mismatch:\n got: %x\nwant: %x", plain, want)
	}
}

func TestEncryptCachingSHA2Password_EmptyNonce(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	if _, err := encryptCachingSHA2Password("x", nil, &priv.PublicKey); err == nil {
		t.Fatal("expected error for empty nonce")
	}
}

func TestParseInitialHandshake_PluginName(t *testing.T) {
	// buildInitialHandshake emits "mysql_native_password" as the advertised
	// plugin — roundtrip must capture that so dispatch logic stays correct.
	salt := bytes.Repeat([]byte{'A'}, 20)
	pkt, err := buildInitialHandshake(salt, 7)
	if err != nil {
		t.Fatal(err)
	}
	info, err := parseInitialHandshake(packetPayload(pkt))
	if err != nil {
		t.Fatal(err)
	}
	if info.plugin != mysqlNativePassword {
		t.Errorf("plugin=%q, want %q", info.plugin, mysqlNativePassword)
	}
}

func TestParseRSAPublicKey(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})

	pub, err := parseRSAPublicKey(pemBytes)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if pub.N.Cmp(priv.PublicKey.N) != 0 {
		t.Error("modulus mismatch")
	}

	if _, err := parseRSAPublicKey([]byte("not pem")); err == nil {
		t.Error("expected error for non-PEM input")
	}
}
