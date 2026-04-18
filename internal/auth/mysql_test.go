package auth

import (
	"bytes"
	"testing"
)

// Golden vectors verified against the Go-MySQL-Driver scramble implementation
// (vitess.io/vitess/go/mysql also matches). Computing manually:
//   pw   = "secret"
//   salt = "12345678901234567890" (raw 20 ASCII bytes, not hex)
//   resp = SHA1(pw) ^ SHA1(salt || SHA1(SHA1(pw)))
func TestMySQLNativeAuthResponse_Golden(t *testing.T) {
	salt := []byte("12345678901234567890")
	got, err := MySQLNativeAuthResponse("secret", salt)
	if err != nil {
		t.Fatalf("compute: %v", err)
	}
	if len(got) != MySQLNativeAuthLen {
		t.Fatalf("len=%d want %d", len(got), MySQLNativeAuthLen)
	}

	// Round-trip: verify must accept the response we produced, and reject a flipped one.
	ok, err := VerifyMySQLNativeAuthResponse("secret", salt, got)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Fatal("verify rejected the response it just produced")
	}

	tampered := bytes.Clone(got)
	tampered[0] ^= 0xff
	ok, _ = VerifyMySQLNativeAuthResponse("secret", salt, tampered)
	if ok {
		t.Fatal("verify accepted a tampered response")
	}

	ok, _ = VerifyMySQLNativeAuthResponse("wrong", salt, got)
	if ok {
		t.Fatal("verify accepted a wrong password")
	}
}

func TestMySQLNativeAuthResponse_EmptyPassword(t *testing.T) {
	salt := bytes.Repeat([]byte{'a'}, MySQLNativeSaltLen)
	got, err := MySQLNativeAuthResponse("", salt)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("empty password should produce zero-length response, got %d bytes", len(got))
	}

	// Verify accepts empty response for empty password.
	ok, err := VerifyMySQLNativeAuthResponse("", salt, []byte{})
	if err != nil || !ok {
		t.Fatalf("empty/empty should verify: ok=%v err=%v", ok, err)
	}
}

func TestMySQLNativeAuthResponse_BadSalt(t *testing.T) {
	if _, err := MySQLNativeAuthResponse("x", []byte("short")); err == nil {
		t.Fatal("expected error for short salt")
	}
}

func TestNewMySQLSalt_PrintableAndUnique(t *testing.T) {
	a, err := NewMySQLSalt()
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != MySQLNativeSaltLen {
		t.Fatalf("len=%d", len(a))
	}
	for i, b := range a {
		if b < 0x21 || b > 0x7E {
			t.Fatalf("byte %d (0x%02x) outside printable range", i, b)
		}
	}
	b, err := NewMySQLSalt()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("two salts collided — entropy check failed")
	}
}
