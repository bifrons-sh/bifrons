package mysql

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // RSA-OAEP with SHA-1 is what MySQL caching_sha2_password mandates on the wire; interop, not cryptographic choice.
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net"

	"github.com/babs/poc-proxies/internal/auth"
)

// pubkeyCacheKey is the sync.Map key — RemoteAddr().String() of the backend
// connection. Every caching_sha2 auth hits the same server address, so one
// entry per backend suffices in practice.
func pubkeyCacheKey(c net.Conn) string {
	if a := c.RemoteAddr(); a != nil {
		return a.String()
	}
	return ""
}

// cachingSha2Password is the plugin name used on the wire.
const cachingSha2Password = "caching_sha2_password"

// cachingSha2PubKeyReq is the single-byte client→server request asking the
// server to return its RSA public key during full-auth.
const cachingSha2PubKeyReq = 0x02

// authenticateBackendCachingSHA2 completes a caching_sha2_password handshake
// against the backend. It sends HandshakeResponse41 with the fast-auth scramble
// and then drives any fast-auth / full-auth sub-flow through to an OK packet.
//
// When the backend connection is already wrapped in TLS the full-auth path
// short-circuits the RSA dance: the server accepts the cleartext password
// (NUL-terminated) because the channel is already encrypted. Otherwise the
// proxy requests the server's RSA public key, XORs password||NUL with the
// nonce, RSA-OAEP-SHA1 encrypts the result, and sends it back.
//
// The password is never logged; only shape/state transitions are.
func (h *Handler) authenticateBackendCachingSHA2(backend net.Conn, info *initialHandshakeInfo, creds *auth.AuthResponse, database string, log *slog.Logger) error {
	scramble := auth.MySQLCachingSHA2AuthResponse(creds.BackendPass, info.salt)
	pkt := buildHandshakeResponse41Plugin(creds.BackendUser, scramble, database, cachingSha2Password)
	if err := writePacket(backend, makePacketRaw(1, pkt)); err != nil {
		return fmt.Errorf("send backend handshake response: %w", err)
	}
	return h.driveBackendCachingSHA2(backend, creds, info.salt, log)
}

// driveBackendCachingSHA2 handles all server responses after the initial
// HandshakeResponse41 has been sent: OK/ERR/AuthSwitch/AuthMoreData. It is
// also reused when the server triggers an AuthSwitch to caching_sha2_password
// from a different plugin mid-handshake.
func (h *Handler) driveBackendCachingSHA2(backend net.Conn, creds *auth.AuthResponse, nonce []byte, log *slog.Logger) error {
	for i := 0; i < maxHandshakePackets; i++ {
		ans, err := readPacket(backend)
		if err != nil {
			return fmt.Errorf("read backend auth result: %w", err)
		}
		payload := packetPayload(ans)
		if len(payload) == 0 {
			return fmt.Errorf("empty backend auth result")
		}
		seq := ans[3]
		switch payload[0] {
		case pktHdrOK:
			log.Info("backend authenticated", "user", creds.BackendUser, "plugin", cachingSha2Password)
			return nil
		case pktHdrErr:
			return fmt.Errorf("backend rejected auth: %s", parseErrMessage(payload))
		case pktHdrAuthSwitchReq:
			// Backend asked us to switch — only caching_sha2_password or
			// mysql_native_password are handled. Reject anything else.
			pluginEnd := indexNull(payload[1:])
			if pluginEnd < 0 {
				return fmt.Errorf("backend AuthSwitch plugin name not terminated")
			}
			plugin := string(payload[1 : 1+pluginEnd])
			rest := payload[1+pluginEnd+1:]
			newNonce := trimPluginData(rest)
			switch plugin {
			case cachingSha2Password:
				nonce = newNonce
				scramble := auth.MySQLCachingSHA2AuthResponse(creds.BackendPass, nonce)
				if err := writePacket(backend, makePacketRaw(seq+1, scramble)); err != nil {
					return fmt.Errorf("send AuthSwitchResponse (caching_sha2): %w", err)
				}
			case mysqlNativePassword:
				if len(newNonce) > auth.MySQLNativeSaltLen {
					newNonce = newNonce[:auth.MySQLNativeSaltLen]
				}
				if len(newNonce) != auth.MySQLNativeSaltLen {
					return fmt.Errorf("backend AuthSwitch salt length=%d", len(newNonce))
				}
				scramble, err := auth.MySQLNativeAuthResponse(creds.BackendPass, newNonce)
				if err != nil {
					return fmt.Errorf("recompute scramble after AuthSwitch: %w", err)
				}
				if err := writePacket(backend, makePacketRaw(seq+1, scramble)); err != nil {
					return fmt.Errorf("send AuthSwitchResponse (native): %w", err)
				}
			default:
				return fmt.Errorf("backend requested unsupported plugin %q", plugin)
			}
		case pktHdrAuthMore:
			// caching_sha2 uses AuthMoreData to signal fast-auth result or
			// request full-auth. payload[1] carries the sub-status.
			if len(payload) < 2 {
				return fmt.Errorf("backend AuthMoreData too short")
			}
			switch payload[1] {
			case cachingSha2FastAuthOK:
				// Server will now send OK (or ERR); loop to read it.
				continue
			case cachingSha2FullAuthReq:
				nextSeq, err := h.runFullAuthBackend(backend, creds, nonce, seq+1, log)
				if err != nil {
					return err
				}
				// Continue loop — server should now send OK/ERR. Next seq
				// must match whatever we last produced.
				_ = nextSeq
			default:
				return fmt.Errorf("unexpected AuthMoreData status 0x%02x", payload[1])
			}
		default:
			return fmt.Errorf("unexpected backend auth byte 0x%02x", payload[0])
		}
	}
	return fmt.Errorf("backend handshake did not converge in %d packets", maxHandshakePackets)
}

// runFullAuthBackend runs the full-auth sub-flow. seq is the sequence id of
// the next packet we will send. Returns the sequence id of the last server
// packet we read (caller loop reads the OK/ERR that follows).
func (h *Handler) runFullAuthBackend(backend net.Conn, creds *auth.AuthResponse, nonce []byte, seq byte, log *slog.Logger) (byte, error) {
	// TLS short-circuit: channel is already encrypted, send cleartext+NUL.
	if _, ok := backend.(*tls.Conn); ok {
		log.Debug("caching_sha2 full-auth: TLS short-circuit, sending cleartext password")
		cleartext := append([]byte(creds.BackendPass), 0x00)
		if err := writePacket(backend, makePacketRaw(seq, cleartext)); err != nil {
			// Zero-out our copy on the error path to limit password exposure
			// in post-mortem memory dumps; the original creds.BackendPass is
			// outside our reach but this is cheap insurance.
			for i := range cleartext {
				cleartext[i] = 0
			}
			return 0, fmt.Errorf("send cleartext password over TLS: %w", err)
		}
		for i := range cleartext {
			cleartext[i] = 0
		}
		return seq, nil
	}

	// Plaintext: use cached pubkey if we've auth'd against this backend
	// before, otherwise fetch it. Cached-hit skips one RTT per connect.
	var (
		pub     *rsa.PublicKey
		nextSeq byte
	)
	cacheKey := pubkeyCacheKey(backend)
	if cacheKey != "" {
		if v, ok := h.pubKeyCache.get(cacheKey); ok {
			pub = v
			nextSeq = seq
		}
	}
	if pub == nil {
		log.Debug("caching_sha2 full-auth: requesting backend public key")
		if err := writePacket(backend, makePacketRaw(seq, []byte{cachingSha2PubKeyReq})); err != nil {
			return 0, fmt.Errorf("request backend pubkey: %w", err)
		}
		pkPkt, err := readPacket(backend)
		if err != nil {
			return 0, fmt.Errorf("read backend pubkey: %w", err)
		}
		pkPayload := packetPayload(pkPkt)
		if len(pkPayload) < 2 || pkPayload[0] != pktHdrAuthMore {
			return 0, fmt.Errorf("unexpected pubkey packet header 0x%02x", firstByte(pkPayload))
		}
		pubPEM := pkPayload[1:]
		pub, err = parseRSAPublicKey(pubPEM)
		if err != nil {
			return 0, fmt.Errorf("parse backend pubkey: %w", err)
		}
		if cacheKey != "" {
			h.pubKeyCache.put(cacheKey, pub)
		}
		// Seq id continues from the server's pubkey packet.
		nextSeq = pkPkt[3] + 1
	}

	ciphertext, err := encryptCachingSHA2Password(creds.BackendPass, nonce, pub)
	if err != nil {
		return 0, fmt.Errorf("encrypt password for backend: %w", err)
	}

	if err := writePacket(backend, makePacketRaw(nextSeq, ciphertext)); err != nil {
		return 0, fmt.Errorf("send encrypted password: %w", err)
	}
	return nextSeq, nil
}

// encryptCachingSHA2Password builds (password||NUL) XOR repeat(nonce) and
// RSA-OAEP-SHA1 encrypts with the server's public key. The plaintext buffer
// is zeroed before return to minimise password residency in memory.
func encryptCachingSHA2Password(password string, nonce []byte, pub *rsa.PublicKey) ([]byte, error) {
	if len(nonce) == 0 {
		return nil, fmt.Errorf("empty nonce")
	}
	plain := make([]byte, len(password)+1)
	copy(plain, password)
	// plain[len(password)] already 0x00 (make zeroes)
	for i := range plain {
		plain[i] ^= nonce[i%len(nonce)]
	}
	ct, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, pub, plain, nil)
	// Zero our masked-plaintext copy; RSA ciphertext already contains no
	// password material in the clear.
	for i := range plain {
		plain[i] = 0
	}
	if err != nil {
		return nil, err
	}
	return ct, nil
}

// parseRSAPublicKey decodes a PEM-wrapped PKIX RSA public key (the format
// MySQL returns in the pubkey AuthMoreData payload).
func parseRSAPublicKey(pemBytes []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in pubkey payload")
	}
	pubAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := pubAny.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("pubkey is not RSA (%T)", pubAny)
	}
	return pub, nil
}

// trimPluginData strips an optional trailing NUL from auth-plugin-data.
func trimPluginData(b []byte) []byte {
	if len(b) > 0 && b[len(b)-1] == 0 {
		return b[:len(b)-1]
	}
	return b
}

func firstByte(b []byte) byte {
	if len(b) == 0 {
		return 0
	}
	return b[0]
}

// buildHandshakeResponse41Plugin is buildHandshakeResponse41 with a caller-
// chosen plugin name. The scramble layout (1-byte length prefix) is identical
// across mysql_native_password and caching_sha2_password — only the plugin
// name advertised to the server differs.
func buildHandshakeResponse41Plugin(username string, authResponse []byte, database, plugin string) []byte {
	caps := proxyCapabilities
	if database != "" {
		caps |= capConnectWithDB
	} else {
		caps &^= capConnectWithDB
	}
	var b []byte
	b = appendUint32LE(b, caps)
	b = appendUint32LE(b, 1<<24)       // max packet size = 16MB
	b = append(b, 0x21)                // charset utf8_general_ci
	b = append(b, make([]byte, 23)...) // filler
	b = append(b, []byte(username)...)
	b = append(b, 0x00)
	b = append(b, byte(len(authResponse))) // 1-byte length-prefixed scramble
	b = append(b, authResponse...)
	if database != "" {
		b = append(b, []byte(database)...)
		b = append(b, 0x00)
	}
	b = append(b, []byte(plugin)...)
	b = append(b, 0x00)
	return b
}
