package auth

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

// computeOracle recomputes the caching_sha2_password scramble directly from the
// RFC formula using crypto/sha256 primitives so the test doubles as an
// executable specification, independent of the code under test.
//
//	scramble = SHA256(pw) XOR SHA256( SHA256(SHA256(pw)) || nonce )
func computeOracle(pw string, nonce []byte) []byte {
	if pw == "" {
		return []byte{}
	}
	h1 := sha256.Sum256([]byte(pw))
	h2 := sha256.Sum256(h1[:])
	h3 := sha256.New()
	h3.Write(h2[:])
	h3.Write(nonce)
	h3Sum := h3.Sum(nil)

	out := make([]byte, sha256.Size)
	for i := range out {
		out[i] = h1[i] ^ h3Sum[i]
	}
	return out
}

func TestMySQLCachingSHA2AuthResponse_EmptyPassword(t *testing.T) {
	nonce := bytes.Repeat([]byte{0xAB}, MySQLCachingSHA2NonceLen)
	got := MySQLCachingSHA2AuthResponse("", nonce)
	if len(got) != 0 {
		t.Fatalf("empty password must produce zero-length response, got %d bytes", len(got))
	}
}

func TestMySQLCachingSHA2AuthResponse_Golden(t *testing.T) {
	// Known nonce/password pair. Oracle is the direct SHA-256 formula above;
	// equality against MySQLCachingSHA2AuthResponse proves both the math and
	// the exact byte layout (no length prefix, no trailing NUL).
	pw := "secret"
	nonce := []byte("12345678901234567890") // 20 bytes — caching_sha2 nonce is 20 bytes on the wire
	got := MySQLCachingSHA2AuthResponse(pw, nonce)
	want := computeOracle(pw, nonce)

	if len(got) != 32 {
		t.Fatalf("scramble len=%d, want 32", len(got))
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("scramble mismatch:\n got: %x\nwant: %x", got, want)
	}
}

func TestMySQLCachingSHA2AuthResponse_DifferentNonce(t *testing.T) {
	// Different nonces for the same password must produce different scrambles.
	pw := "hunter2"
	a := MySQLCachingSHA2AuthResponse(pw, bytes.Repeat([]byte{0x01}, 20))
	b := MySQLCachingSHA2AuthResponse(pw, bytes.Repeat([]byte{0x02}, 20))
	if bytes.Equal(a, b) {
		t.Fatal("different nonces produced identical scrambles")
	}
}
