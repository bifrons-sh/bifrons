package auth

import "crypto/sha256"

// MySQLCachingSHA2NonceLen is the expected length of the server-supplied nonce
// (auth-plugin-data) for the caching_sha2_password plugin. The wire format also
// uses a trailing NUL which callers are expected to strip before invoking
// MySQLCachingSHA2AuthResponse.
const MySQLCachingSHA2NonceLen = 20

// MySQLCachingSHA2AuthLen is the length of the fast-auth scramble response.
const MySQLCachingSHA2AuthLen = sha256.Size // 32

// MySQLCachingSHA2AuthResponse computes the fast-auth scramble per the
// caching_sha2_password spec:
//
//	scramble = SHA256(pw) XOR SHA256( SHA256(SHA256(pw)) || nonce )
//
// An empty password yields a zero-length response per MySQL convention.
// The nonce is whatever the server sent; we neither validate its length nor
// trim it (the wire framing already stripped the trailing NUL upstream).
func MySQLCachingSHA2AuthResponse(password string, nonce []byte) []byte {
	if password == "" {
		return []byte{}
	}
	h1 := sha256.Sum256([]byte(password))
	h2 := sha256.Sum256(h1[:])

	// SHA256(h2 || nonce) — streaming avoids an extra allocation for the concat.
	hh := sha256.New()
	hh.Write(h2[:])
	hh.Write(nonce)
	h3 := hh.Sum(nil)

	out := make([]byte, sha256.Size)
	for i := range out {
		out[i] = h1[i] ^ h3[i]
	}
	return out
}
