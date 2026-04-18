package mysql

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"

	"github.com/babs/poc-proxies/internal/auth"
	"github.com/babs/poc-proxies/internal/proxy"
)

// MySQL capability flags (subset we care about for auth re-mapping).
const (
	capLongPassword      = 0x00000001
	capLongFlag          = 0x00000004
	capConnectWithDB     = 0x00000008
	capProtocol41        = 0x00000200
	capTransactions      = 0x00002000
	capSecureConnection  = 0x00008000
	capPluginAuth        = 0x00080000
	capPluginAuthLenenc  = 0x00200000
	capDeprecateEOF      = 0x01000000

	mysqlNativePassword = "mysql_native_password"

	authPluginNameMaxLen = 64 // sanity cap when parsing client-supplied plugin name

	// Packet headers.
	pktHdrOK            = 0x00
	pktHdrErr           = 0xFF
	pktHdrAuthMore      = 0x01
	pktHdrAuthSwitchReq = 0xFE

	// Status flag baseline for the OK packet sent to the client.
	statusAutocommit = 0x0002
)

// proxyCapabilities is what the proxy advertises to the client *and* sends
// to the backend. We force mysql_native_password and require
// CLIENT_SECURE_CONNECTION so the client always uses the 20-byte length-
// prefixed scramble layout. CLIENT_DEPRECATE_EOF is intentionally omitted so
// that client and backend agree on EOF framing: go-sql-driver v1.9 does not
// advertise DEPRECATE_EOF in its HandshakeResponse41, and the proxy relays
// result-set bytes verbatim — a capability mismatch here corrupts column
// definition framing and panics the driver.
var proxyCapabilities uint32 = capLongPassword |
	capLongFlag |
	capConnectWithDB |
	capProtocol41 |
	capTransactions |
	capSecureConnection |
	capPluginAuth

// handleAuth runs the full auth re-mapping handshake when h.authClient != nil.
// On success the client has been sent an OK packet and the backend session is
// authenticated; the caller may enter the relay phase. Returns the audit
// session context populated with the authenticated identity.
func (h *Handler) handleAuth(ctx context.Context, client, backend net.Conn, log *slog.Logger) (*sessionAudit, error) {
	// 1. Read backend Initial Handshake first so we have its salt + capabilities
	//    available when computing our HandshakeResponse41 below.
	backendHandshake, err := readPacket(backend)
	if err != nil {
		return nil, fmt.Errorf("read backend handshake: %w", err)
	}
	backendInfo, err := parseInitialHandshake(packetPayload(backendHandshake))
	if err != nil {
		return nil, fmt.Errorf("parse backend handshake: %w", err)
	}

	// 2. Build our own Initial Handshake (independent salt) and send to client.
	clientSalt, err := auth.NewMySQLSalt()
	if err != nil {
		return nil, fmt.Errorf("generate client salt: %w", err)
	}
	greet, err := buildInitialHandshake(clientSalt, backendInfo.connID)
	if err != nil {
		return nil, fmt.Errorf("build client handshake: %w", err)
	}
	if err := writePacket(client, greet); err != nil {
		return nil, fmt.Errorf("send client handshake: %w", err)
	}

	// 3. Read client HandshakeResponse41.
	respPkt, err := readPacket(client)
	if err != nil {
		return nil, fmt.Errorf("read client handshake response: %w", err)
	}
	cresp, err := parseHandshakeResponse41(packetPayload(respPkt))
	if err != nil {
		_ = sendErrPacket(client, 1045, "28000", "Bad handshake")
		return nil, fmt.Errorf("parse client handshake response: %w", err)
	}

	// 4. Look up portal credentials and validate client's scramble.
	if cresp.username == "" {
		_ = sendErrPacket(client, 1045, "28000", "Access denied: missing user")
		return nil, fmt.Errorf("client supplied empty username")
	}
	creds, err := h.authClient.Lookup(ctx, auth.LookupRequest{
		Username:      cresp.username,
		SourceIP:      proxy.SourceIP(client.RemoteAddr().String()),
		ProxyType:     proxyType,
		BackendServer: h.backendAddr,
	})
	if err != nil {
		_ = sendErrPacket(client, 1045, "28000", "Access denied")
		return nil, fmt.Errorf("auth lookup for %q: %w", cresp.username, err)
	}

	// Sequence id for the next packet WE send to the client. Client just
	// finished sending HandshakeResponse41 with seq=1 (server greeting was 0).
	nextClientSeq := byte(2)

	// Force AuthSwitch if the client preferred a different plugin so we always
	// validate against mysql_native_password — keeps a single verification path.
	if cresp.authPlugin != mysqlNativePassword {
		switched, switchedSeq, err := authSwitchToNative(client, clientSalt, nextClientSeq)
		if err != nil {
			return nil, fmt.Errorf("auth switch: %w", err)
		}
		cresp.authResponse = switched
		nextClientSeq = switchedSeq + 1
	}

	ok, err := auth.VerifyMySQLNativeAuthResponse(creds.Password, clientSalt, cresp.authResponse)
	if err != nil {
		return nil, fmt.Errorf("verify client auth: %w", err)
	}
	if !ok {
		_ = sendErrPacketSeq(client, nextClientSeq, 1045, "28000", "Access denied for user '"+cresp.username+"'")
		return nil, fmt.Errorf("client auth response did not match for user %q", cresp.username)
	}
	log.Info("client authenticated", "user", cresp.username)

	// 5. Authenticate to backend with mapped credentials. When the grant
	// nominates exactly one allowed database, force the session default schema
	// to that — matches the PG path behaviour and means the user lands in a
	// usable database even if the client didn't pass one in HandshakeResponse41.
	backendDB := cresp.database
	if len(creds.AllowedDBs) == 1 {
		backendDB = creds.AllowedDBs[0]
	}
	if err := h.authenticateBackend(backend, backendInfo, creds, backendDB, log); err != nil {
		_ = sendErrPacketSeq(client, nextClientSeq, 1045, "28000", "Backend authentication failed")
		return nil, err
	}

	// 6. Tell the client we're ready.
	if err := writePacket(client, buildOKPacket(nextClientSeq)); err != nil {
		return nil, fmt.Errorf("send client OK: %w", err)
	}

	return &sessionAudit{
		username:      cresp.username,
		grantID:       creds.GrantID,
		role:          creds.Role,
		sourceIP:      proxy.SourceIP(client.RemoteAddr().String()),
		backendServer: h.backendAddr,
		database:      backendDB,
	}, nil
}

// initialHandshakeInfo holds the bits of the server greeting we need later.
type initialHandshakeInfo struct {
	salt   []byte // assembled scramble / nonce (20 bytes for native and caching_sha2)
	connID uint32
	plugin string // server-advertised default auth plugin, "" if not advertised
}

// parseInitialHandshake parses Protocol::HandshakeV10. Only the fields the
// proxy needs are returned; the rest is validated then discarded.
func parseInitialHandshake(payload []byte) (*initialHandshakeInfo, error) {
	if len(payload) < 1 {
		return nil, fmt.Errorf("empty handshake payload")
	}
	if payload[0] != 0x0A {
		return nil, fmt.Errorf("unsupported protocol version: %d", payload[0])
	}
	p := payload[1:]

	// server_version (NUL-terminated)
	idx := indexNull(p)
	if idx < 0 {
		return nil, fmt.Errorf("server version not terminated")
	}
	p = p[idx+1:]

	if len(p) < 4+8+1+2 {
		return nil, fmt.Errorf("handshake truncated before capabilities")
	}
	connID := binary.LittleEndian.Uint32(p[0:4])
	p = p[4:]

	salt1 := append([]byte(nil), p[:8]...)
	p = p[8:]

	// filler 0x00
	p = p[1:]

	// capability_flags (lower 2 bytes)
	capLo := uint32(binary.LittleEndian.Uint16(p[0:2]))
	p = p[2:]

	if len(p) == 0 {
		// Older server without extended fields — only 8-byte salt available.
		return &initialHandshakeInfo{salt: salt1, connID: connID}, nil
	}
	if len(p) < 1+2+2+1+10 {
		return nil, fmt.Errorf("handshake truncated before capability hi")
	}
	// charset
	p = p[1:]
	// status flags
	p = p[2:]
	// capability flags upper
	capHi := uint32(binary.LittleEndian.Uint16(p[0:2]))
	p = p[2:]
	caps := capLo | (capHi << 16)

	// Require both CLIENT_PROTOCOL_41 and CLIENT_SECURE_CONNECTION from the
	// backend: both are universal on any supported MySQL/MariaDB server (since
	// 4.1), and both are preconditions for the 20-byte length-prefixed scramble
	// layout the proxy uses. Reject pre-4.1 servers cleanly rather than letting
	// scramble computation go subtly wrong later.
	if caps&capProtocol41 == 0 || caps&capSecureConnection == 0 {
		return nil, fmt.Errorf("backend lacks required capabilities (caps=0x%08x)", caps)
	}

	// auth_plugin_data length. Per spec this is either 0 or a length ≥ 8 (the
	// split-layout has a mandatory 8-byte part 1); reject anything shorter to
	// avoid negative part2Len arithmetic below.
	apdLen := int(p[0])
	p = p[1:]
	if apdLen != 0 && apdLen < 8 {
		return nil, fmt.Errorf("invalid auth-plugin-data length: %d", apdLen)
	}
	// 10 bytes filler
	p = p[10:]

	// auth_plugin_data part 2: max(13, apdLen-8) bytes, but trailing NUL.
	part2Len := apdLen - 8
	if part2Len < 13 {
		part2Len = 13
	}
	if len(p) < part2Len {
		return nil, fmt.Errorf("handshake truncated in salt part 2")
	}
	salt2 := p[:part2Len]
	// Strip trailing NUL terminator if present.
	if len(salt2) > 0 && salt2[len(salt2)-1] == 0 {
		salt2 = salt2[:len(salt2)-1]
	}
	// Use first 12 bytes of salt2 to assemble standard 20-byte scramble.
	if len(salt2) > 12 {
		salt2 = salt2[:12]
	}

	salt := make([]byte, 0, 20)
	salt = append(salt, salt1...)
	salt = append(salt, salt2...)
	if len(salt) != auth.MySQLNativeSaltLen {
		return nil, fmt.Errorf("assembled salt is %d bytes, want %d", len(salt), auth.MySQLNativeSaltLen)
	}
	// Advance past the raw 13-byte part 2 (we already trimmed the tail copy,
	// but the wire bytes still consume 13 bytes — max(13, apdLen-8)).
	advance := apdLen - 8
	if advance < 13 {
		advance = 13
	}
	if len(p) >= advance {
		p = p[advance:]
	}
	// Auth plugin name (NUL-terminated) when CLIENT_PLUGIN_AUTH is set.
	var plugin string
	if caps&capPluginAuth != 0 && len(p) > 0 {
		if idx := indexNull(p); idx >= 0 && idx <= authPluginNameMaxLen {
			plugin = string(p[:idx])
		}
	}
	return &initialHandshakeInfo{salt: salt, connID: connID, plugin: plugin}, nil
}

// buildInitialHandshake constructs a Protocol::HandshakeV10 packet whose
// capability flags advertise mysql_native_password and CLIENT_SECURE_CONNECTION.
// The connection ID is echoed from the backend so log correlation works.
// Returns an error instead of panicking if salt is not the expected length so
// a single bad caller never brings down the listener goroutine.
func buildInitialHandshake(salt []byte, connID uint32) ([]byte, error) {
	if len(salt) != auth.MySQLNativeSaltLen {
		return nil, fmt.Errorf("buildInitialHandshake: salt len=%d, want %d", len(salt), auth.MySQLNativeSaltLen)
	}
	var body []byte
	body = append(body, 0x0A) // protocol version
	body = append(body, []byte("8.0.0-portal-proxy")...)
	body = append(body, 0x00) // NUL terminator
	body = appendUint32LE(body, connID)
	body = append(body, salt[:8]...)
	body = append(body, 0x00) // filler
	caps := proxyCapabilities
	body = appendUint16LE(body, uint16(caps&0xFFFF))
	body = append(body, 0x21)             // charset = utf8_general_ci
	body = appendUint16LE(body, statusAutocommit)
	body = appendUint16LE(body, uint16(caps>>16))
	body = append(body, byte(auth.MySQLNativeSaltLen+1)) // auth-plugin-data length (incl NUL)
	body = append(body, make([]byte, 10)...)             // reserved
	body = append(body, salt[8:]...)                     // 12 bytes
	body = append(body, 0x00)                            // NUL after part 2
	body = append(body, []byte(mysqlNativePassword)...)
	body = append(body, 0x00)
	return makePacketRaw(0, body), nil
}

// clientHandshakeResponse holds parsed fields from HandshakeResponse41.
type clientHandshakeResponse struct {
	capabilities uint32
	username     string
	authResponse []byte
	database     string
	authPlugin   string
}

func parseHandshakeResponse41(payload []byte) (*clientHandshakeResponse, error) {
	if len(payload) < 4+4+1+23 {
		return nil, fmt.Errorf("handshake response too short: %d", len(payload))
	}
	caps := binary.LittleEndian.Uint32(payload[0:4])
	if caps&capProtocol41 == 0 {
		return nil, fmt.Errorf("client did not negotiate CLIENT_PROTOCOL_41")
	}
	p := payload[4+4+1+23:] // skip max_packet, charset, filler

	// username
	idx := indexNull(p)
	if idx < 0 {
		return nil, fmt.Errorf("username not terminated")
	}
	username := string(p[:idx])
	p = p[idx+1:]

	// auth_response
	var authResp []byte
	switch {
	case caps&capPluginAuthLenenc != 0:
		n, consumed, err := readLenEncInt(p)
		if err != nil {
			return nil, fmt.Errorf("read lenenc auth response length: %w", err)
		}
		p = p[consumed:]
		if int(n) > len(p) {
			return nil, fmt.Errorf("auth response length %d exceeds remaining %d", n, len(p))
		}
		authResp = append([]byte(nil), p[:n]...)
		p = p[n:]
	case caps&capSecureConnection != 0:
		if len(p) < 1 {
			return nil, fmt.Errorf("missing auth response length")
		}
		n := int(p[0])
		p = p[1:]
		if n > len(p) {
			return nil, fmt.Errorf("auth response length %d exceeds remaining %d", n, len(p))
		}
		authResp = append([]byte(nil), p[:n]...)
		p = p[n:]
	default:
		idx := indexNull(p)
		if idx < 0 {
			return nil, fmt.Errorf("auth response not terminated")
		}
		authResp = append([]byte(nil), p[:idx]...)
		p = p[idx+1:]
	}

	out := &clientHandshakeResponse{
		capabilities: caps,
		username:     username,
		authResponse: authResp,
	}

	// database (optional)
	if caps&capConnectWithDB != 0 && len(p) > 0 {
		idx := indexNull(p)
		if idx < 0 {
			return nil, fmt.Errorf("database not terminated")
		}
		out.database = string(p[:idx])
		p = p[idx+1:]
	}

	// auth_plugin name (optional)
	if caps&capPluginAuth != 0 && len(p) > 0 {
		idx := indexNull(p)
		if idx < 0 {
			return nil, fmt.Errorf("auth plugin not terminated")
		}
		if idx > authPluginNameMaxLen {
			return nil, fmt.Errorf("auth plugin name too long: %d", idx)
		}
		out.authPlugin = string(p[:idx])
	}
	return out, nil
}

// authSwitchToNative sends an AuthSwitchRequest with the given seq id to
// mysql_native_password and reads the client's 20-byte scramble response.
// Returns the scramble plus the seq id of the client response so the caller
// knows what to use next.
func authSwitchToNative(client net.Conn, salt []byte, seq byte) ([]byte, byte, error) {
	var pkt []byte
	pkt = append(pkt, pktHdrAuthSwitchReq)
	pkt = append(pkt, []byte(mysqlNativePassword)...)
	pkt = append(pkt, 0x00)
	pkt = append(pkt, salt...)
	pkt = append(pkt, 0x00) // historical NUL after plugin data
	if err := writePacket(client, makePacketRaw(seq, pkt)); err != nil {
		return nil, 0, fmt.Errorf("send AuthSwitchRequest: %w", err)
	}
	resp, err := readPacket(client)
	if err != nil {
		return nil, 0, fmt.Errorf("read AuthSwitchResponse: %w", err)
	}
	return packetPayload(resp), resp[3], nil
}

// authenticateBackend performs HandshakeResponse41 + (optional) AuthSwitch
// against the backend using the mapped credentials, then waits for OK.
// Dispatches on the server-advertised auth plugin: caching_sha2_password has a
// dedicated code path that understands AuthMoreData; everything else falls
// back to mysql_native_password (which remains the compatibility default).
func (h *Handler) authenticateBackend(backend net.Conn, info *initialHandshakeInfo, creds *auth.AuthResponse, database string, log *slog.Logger) error {
	if info.plugin == cachingSha2Password {
		return h.authenticateBackendCachingSHA2(backend, info, creds, database, log)
	}
	resp, err := auth.MySQLNativeAuthResponse(creds.BackendPass, info.salt)
	if err != nil {
		return fmt.Errorf("compute backend scramble: %w", err)
	}
	pkt := buildHandshakeResponse41(creds.BackendUser, resp, database)
	if err := writePacket(backend, makePacketRaw(1, pkt)); err != nil {
		return fmt.Errorf("send backend handshake response: %w", err)
	}

	// Server may reply with OK, ERR, or AuthSwitchRequest.
	for i := 0; i < maxHandshakePackets; i++ {
		ans, err := readPacket(backend)
		if err != nil {
			return fmt.Errorf("read backend auth result: %w", err)
		}
		payload := packetPayload(ans)
		if len(payload) == 0 {
			return fmt.Errorf("empty backend auth result")
		}
		switch payload[0] {
		case pktHdrOK:
			log.Info("backend authenticated", "user", creds.BackendUser)
			return nil
		case pktHdrErr:
			return fmt.Errorf("backend rejected auth: %s", parseErrMessage(payload))
		case pktHdrAuthSwitchReq:
			pluginEnd := indexNull(payload[1:])
			if pluginEnd < 0 {
				return fmt.Errorf("backend AuthSwitch plugin name not terminated")
			}
			plugin := string(payload[1 : 1+pluginEnd])
			rest := payload[1+pluginEnd+1:]
			newSalt := trimPluginData(rest)
			switch plugin {
			case mysqlNativePassword:
				if len(newSalt) > auth.MySQLNativeSaltLen {
					newSalt = newSalt[:auth.MySQLNativeSaltLen]
				}
				if len(newSalt) != auth.MySQLNativeSaltLen {
					return fmt.Errorf("backend AuthSwitch salt length=%d", len(newSalt))
				}
				scramble, err := auth.MySQLNativeAuthResponse(creds.BackendPass, newSalt)
				if err != nil {
					return fmt.Errorf("recompute scramble after AuthSwitch: %w", err)
				}
				if err := writePacket(backend, makePacketRaw(ans[3]+1, scramble)); err != nil {
					return fmt.Errorf("send AuthSwitchResponse to backend: %w", err)
				}
			case cachingSha2Password:
				// Server switched us into caching_sha2 mid-handshake — send the
				// fast-auth scramble and hand off to the caching_sha2 driver.
				scramble := auth.MySQLCachingSHA2AuthResponse(creds.BackendPass, newSalt)
				if err := writePacket(backend, makePacketRaw(ans[3]+1, scramble)); err != nil {
					return fmt.Errorf("send AuthSwitchResponse (caching_sha2): %w", err)
				}
				return h.driveBackendCachingSHA2(backend, creds, newSalt, log)
			default:
				return fmt.Errorf("backend requested unsupported plugin %q", plugin)
			}
		case pktHdrAuthMore:
			// Should not happen on the native path (only caching_sha2 emits it
			// and we would have branched earlier). Surface as a protocol error.
			return fmt.Errorf("unexpected AuthMoreData on mysql_native_password path")
		default:
			return fmt.Errorf("unexpected backend auth byte 0x%02x", payload[0])
		}
	}
	return fmt.Errorf("backend handshake did not converge in %d packets", maxHandshakePackets)
}

func buildHandshakeResponse41(username string, authResponse []byte, database string) []byte {
	caps := proxyCapabilities
	if database != "" {
		caps |= capConnectWithDB
	} else {
		caps &^= capConnectWithDB
	}
	var b []byte
	b = appendUint32LE(b, caps)
	b = appendUint32LE(b, 1<<24)            // max packet size = 16MB
	b = append(b, 0x21)                     // charset utf8_general_ci
	b = append(b, make([]byte, 23)...)      // filler
	b = append(b, []byte(username)...)
	b = append(b, 0x00)
	b = append(b, byte(len(authResponse)))  // 1-byte length-prefixed scramble
	b = append(b, authResponse...)
	if database != "" {
		b = append(b, []byte(database)...)
		b = append(b, 0x00)
	}
	b = append(b, []byte(mysqlNativePassword)...)
	b = append(b, 0x00)
	return b
}

// buildOKPacket produces a minimal OK packet.
func buildOKPacket(seq byte) []byte {
	body := []byte{
		pktHdrOK,
		0x00, // affected rows = 0 (lenenc int)
		0x00, // last insert id = 0
		byte(statusAutocommit & 0xFF), byte(statusAutocommit >> 8),
		0x00, 0x00, // warnings
	}
	return makePacketRaw(seq, body)
}

// sendErrPacket emits an ERR packet at seq=2; useful before any auth round
// trip when the proxy has only seen the client HandshakeResponse41 (seq=1).
func sendErrPacket(w net.Conn, code uint16, sqlState string, msg string) error {
	return sendErrPacketSeq(w, 2, code, sqlState, msg)
}

// sendErrPacketSeq emits an ERR packet at the given sequence id, used when the
// auth phase has progressed past the initial handshake exchange.
func sendErrPacketSeq(w net.Conn, seq byte, code uint16, sqlState string, msg string) error {
	body := []byte{pktHdrErr}
	body = appendUint16LE(body, code)
	body = append(body, '#')
	if len(sqlState) != 5 {
		sqlState = "HY000"
	}
	body = append(body, []byte(sqlState)...)
	body = append(body, []byte(msg)...)
	return writePacket(w, makePacketRaw(seq, body))
}

func parseErrMessage(payload []byte) string {
	// payload[0]=0xFF, [1:3]=code, [3]='#', [4:9]=sqlstate, [9:]=msg
	if len(payload) >= 9 && payload[3] == '#' {
		return string(payload[9:])
	}
	if len(payload) >= 3 {
		return string(payload[3:])
	}
	return "<malformed err>"
}

// makePacketRaw frames a payload as a MySQL wire packet with the given seq id.
func makePacketRaw(seq byte, payload []byte) []byte {
	pkt := make([]byte, 4+len(payload))
	pkt[0] = byte(len(payload))
	pkt[1] = byte(len(payload) >> 8)
	pkt[2] = byte(len(payload) >> 16)
	pkt[3] = seq
	copy(pkt[4:], payload)
	return pkt
}

func appendUint16LE(b []byte, v uint16) []byte {
	return append(b, byte(v), byte(v>>8))
}

func appendUint32LE(b []byte, v uint32) []byte {
	return append(b, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}

func indexNull(b []byte) int {
	for i, c := range b {
		if c == 0 {
			return i
		}
	}
	return -1
}

// readLenEncInt decodes a MySQL length-encoded integer. Returns (value, bytes consumed).
func readLenEncInt(b []byte) (uint64, int, error) {
	if len(b) == 0 {
		return 0, 0, fmt.Errorf("empty buffer")
	}
	switch b[0] {
	case 0xFB:
		return 0, 1, fmt.Errorf("NULL marker not valid here")
	case 0xFC:
		if len(b) < 3 {
			return 0, 0, fmt.Errorf("short 2-byte lenenc")
		}
		return uint64(binary.LittleEndian.Uint16(b[1:3])), 3, nil
	case 0xFD:
		if len(b) < 4 {
			return 0, 0, fmt.Errorf("short 3-byte lenenc")
		}
		return uint64(b[1]) | uint64(b[2])<<8 | uint64(b[3])<<16, 4, nil
	case 0xFE:
		if len(b) < 9 {
			return 0, 0, fmt.Errorf("short 8-byte lenenc")
		}
		return binary.LittleEndian.Uint64(b[1:9]), 9, nil
	default:
		return uint64(b[0]), 1, nil
	}
}

