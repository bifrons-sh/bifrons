package auth

import (
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // mysql_native_password is SHA1-based by spec; security comes from challenge nonce, not algorithm strength.
	"crypto/subtle"
	"fmt"
)

// MySQLNativeAuthLen is the fixed length in bytes of a mysql_native_password
// scramble response.
const MySQLNativeAuthLen = 20

// MySQLNativeSaltLen is the fixed length of the salt the MySQL server includes
// in its initial handshake. The wire protocol splits this into auth-plugin-data
// part 1 (8 bytes) and part 2 (12 bytes + trailing NUL).
const MySQLNativeSaltLen = 20

// MySQLNativeAuthResponse computes the scramble per the mysql_native_password
// spec:
//
//	SHA1(password) XOR SHA1(salt || SHA1(SHA1(password)))
//
// An empty password returns a zero-length response per protocol convention.
func MySQLNativeAuthResponse(password string, salt []byte) ([]byte, error) {
	if len(salt) != MySQLNativeSaltLen {
		return nil, fmt.Errorf("mysql salt: got %d bytes, want %d", len(salt), MySQLNativeSaltLen)
	}
	if password == "" {
		return []byte{}, nil
	}

	hPw := sha1.Sum([]byte(password))
	hHPw := sha1.Sum(hPw[:])

	saltConcat := make([]byte, 0, len(salt)+len(hHPw))
	saltConcat = append(saltConcat, salt...)
	saltConcat = append(saltConcat, hHPw[:]...)
	hSalt := sha1.Sum(saltConcat)

	out := make([]byte, MySQLNativeAuthLen)
	for i := range out {
		out[i] = hPw[i] ^ hSalt[i]
	}
	return out, nil
}

// VerifyMySQLNativeAuthResponse runs MySQLNativeAuthResponse and constant-time
// compares the result to the client-supplied response.
func VerifyMySQLNativeAuthResponse(password string, salt, response []byte) (bool, error) {
	expected, err := MySQLNativeAuthResponse(password, salt)
	if err != nil {
		return false, err
	}
	if len(expected) != len(response) {
		return false, nil
	}
	return subtle.ConstantTimeCompare(expected, response) == 1, nil
}

// NewMySQLSalt returns a cryptographically random 20-byte salt suitable for
// use as the auth-plugin-data field in a Protocol::Handshake packet.
//
// The MySQL spec requires bytes in the printable ASCII range (0x21..0x7E) to
// avoid ambiguity with the NUL terminator embedded in the legacy split layout.
// We rejection-sample with crypto/rand to keep entropy without bias.
func NewMySQLSalt() ([]byte, error) {
	out := make([]byte, MySQLNativeSaltLen)
	buf := make([]byte, 64)
	filled := 0
	for filled < MySQLNativeSaltLen {
		if _, err := rand.Read(buf); err != nil {
			return nil, err
		}
		for _, b := range buf {
			if b >= 0x21 && b <= 0x7E {
				out[filled] = b
				filled++
				if filled == MySQLNativeSaltLen {
					break
				}
			}
		}
	}
	return out, nil
}
