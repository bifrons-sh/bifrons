package postgres

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/xdg-go/scram"

	"github.com/babs/poc-proxies/internal/auth"
	"github.com/babs/poc-proxies/internal/proxy"
)

// PostgreSQL message type bytes.
const (
	msgAuthRequest    = 'R'
	msgErrorResponse  = 'E'
	msgPasswordOrSASL = 'p'
	msgParameterStat  = 'S'
	msgBackendKeyData = 'K'
	msgReadyForQuery  = 'Z'
	msgNoticeResponse = 'N'

	// AuthenticationRequest sub-types (first 4 bytes of payload).
	authOK             uint32 = 0
	authCleartextPass  uint32 = 3
	authMD5Pass        uint32 = 5
	authSASL           uint32 = 10
	authSASLContinue   uint32 = 11
	authSASLFinal      uint32 = 12

	scramMech     = "SCRAM-SHA-256"
	scramMechPlus = "SCRAM-SHA-256-PLUS"

	// Cap on backend messages processed during auth + bring-up before
	// ReadyForQuery is seen. 256 is comfortable for a backend that emits many
	// NoticeResponse / ParameterStatus frames on cold start; the purpose is
	// defence-in-depth against a compromised/looping backend, not a tight limit.
	maxPostAuthMessages = 256

	proxyType = "postgres"
)

// ClientAuthMethod selects how the proxy authenticates the connecting client.
type ClientAuthMethod string

const (
	// ClientAuthSCRAM is the modern default; matches what `psql` does out of the box.
	ClientAuthSCRAM ClientAuthMethod = "scram"
	// ClientAuthCleartext is for legacy clients that only support `password` auth.
	// Safe only over TLS — proxy should be deployed with -client-tls when used.
	ClientAuthCleartext ClientAuthMethod = "cleartext"
)

// startupParams represents parsed key/value parameters from a Startup message.
type startupParams struct {
	protocolVersion uint32
	params          map[string]string
}

// parseStartupParams pulls out the K/V parameters that follow the protocol
// version. The wire layout is: [len:4][version:4](key\0value\0)*\0
func parseStartupParams(msg []byte) (*startupParams, error) {
	if len(msg) < 8 {
		return nil, fmt.Errorf("startup message too short: %d", len(msg))
	}
	out := &startupParams{
		protocolVersion: binary.BigEndian.Uint32(msg[4:8]),
		params:          make(map[string]string),
	}
	p := msg[8:]
	for len(p) > 0 {
		if p[0] == 0 {
			break
		}
		k, rest, ok := readCString(p)
		if !ok {
			return nil, fmt.Errorf("startup key not terminated")
		}
		v, rest2, ok := readCString(rest)
		if !ok {
			return nil, fmt.Errorf("startup value not terminated for %q", k)
		}
		out.params[k] = v
		p = rest2
	}
	return out, nil
}

// buildStartupMessage rebuilds a Startup message from parsed params, using the
// supplied protocol version. Useful when forwarding a re-mapped user/database
// to the backend.
func buildStartupMessage(version uint32, params map[string]string) []byte {
	body := make([]byte, 4)
	binary.BigEndian.PutUint32(body, version)
	for k, v := range params {
		body = append(body, []byte(k)...)
		body = append(body, 0)
		body = append(body, []byte(v)...)
		body = append(body, 0)
	}
	body = append(body, 0) // terminator
	msg := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(msg[0:4], uint32(len(body)+4))
	copy(msg[4:], body)
	return msg
}

func readCString(p []byte) (string, []byte, bool) {
	for i, c := range p {
		if c == 0 {
			return string(p[:i]), p[i+1:], true
		}
	}
	return "", nil, false
}

// handleAuth runs the proxy's auth re-mapping flow once the startup message
// has been read from the client. On success the client has been told
// AuthenticationOk + ParameterStatus + BackendKeyData + ReadyForQuery and the
// caller should enter the relay phase. Returns the audit session context
// populated with the authenticated identity.
func (h *Handler) handleAuth(ctx context.Context, client, backend net.Conn, startup []byte, log *slog.Logger) (*sessionAudit, error) {
	parsed, err := parseStartupParams(startup)
	if err != nil {
		_ = sendErrorResponse(client, "08P01", "invalid startup message")
		return nil, fmt.Errorf("parse startup: %w", err)
	}
	username := parsed.params["user"]
	if username == "" {
		_ = sendErrorResponse(client, "28000", "missing user parameter")
		return nil, fmt.Errorf("client startup missing user")
	}

	// Resolve credentials early so we can reject before any auth round-trip.
	lookupStart := time.Now()
	creds, err := h.authClient.Lookup(ctx, auth.LookupRequest{
		Username:      username,
		SourceIP:      proxy.SourceIP(client.RemoteAddr().String()),
		ProxyType:     proxyType,
		BackendServer: h.backendAddr,
	})
	if h.mAuthLookup != nil {
		h.mAuthLookup.Observe(time.Since(lookupStart))
	}
	if err != nil {
		_ = sendErrorResponse(client, "28000", "access denied")
		return nil, fmt.Errorf("auth lookup for %q: %w", username, err)
	}

	switch h.clientAuthMethod {
	case ClientAuthCleartext:
		if err := authClientCleartext(client, creds.Password); err != nil {
			_ = sendErrorResponse(client, "28P01", "authentication failed")
			return nil, fmt.Errorf("cleartext client auth: %w", err)
		}
	default:
		if err := authClientSCRAM(client, username, creds.Password, h.scramCache, h.clientTLSCBReq, h.clientTLSLeaf, log); err != nil {
			_ = sendErrorResponse(client, "28P01", "authentication failed")
			return nil, fmt.Errorf("scram client auth: %w", err)
		}
	}
	log.Info("client authenticated", "user", username)

	// Build a fresh startup with the mapped backend user. We forward only an
	// allow-list of client-supplied parameters: anything outside that set could
	// surprise portal policy (e.g. `options="-c role=admin"`, `replication=on`,
	// `search_path` overrides) so we drop silently rather than risk escalation.
	beParams := map[string]string{"user": creds.BackendUser}
	for _, k := range forwardedStartupParams {
		if v, ok := parsed.params[k]; ok {
			beParams[k] = v
		}
	}
	if len(creds.AllowedDBs) == 1 {
		beParams["database"] = creds.AllowedDBs[0]
	}

	beStartup := buildStartupMessage(parsed.protocolVersion, beParams)
	if _, err := backend.Write(beStartup); err != nil {
		_ = sendErrorResponse(client, "08006", "backend connection failed")
		return nil, fmt.Errorf("forward startup to backend: %w", err)
	}

	// Drive backend auth and capture its post-auth bring-up frames (parameter
	// status, backend key data, ready-for-query) into a buffer before we tell
	// the client anything. That way a failure during backend bring-up results
	// in an ErrorResponse to the client, not a half-open "authenticated but
	// unready" session.
	tail, err := authBackendAndCaptureTail(backend, creds.BackendUser, creds.BackendPass)
	if err != nil {
		// Report a generic message to the client: the internal error often
		// contains the mapped backend role name, which is portal-internal detail
		// the client has no business seeing. The full chain is still captured
		// in the proxy log via the returned error.
		_ = sendErrorResponse(client, "08006", "backend authentication failed")
		return nil, fmt.Errorf("backend bring-up: %w", err)
	}
	log.Info("backend authenticated", "user", creds.BackendUser)

	// Emit AuthenticationOk + captured tail atomically.
	if _, err := client.Write(buildAuthRequest(authOK, nil)); err != nil {
		return nil, fmt.Errorf("send AuthenticationOk to client: %w", err)
	}
	if _, err := client.Write(tail); err != nil {
		return nil, fmt.Errorf("forward backend tail to client: %w", err)
	}
	log.Info("auth remapping complete")

	// Populate the audit session that relayClientMessages will tag entries with.
	sess := &sessionAudit{
		username:         username,
		grantID:          creds.GrantID,
		role:             creds.Role,
		sourceIP:         proxy.SourceIP(client.RemoteAddr().String()),
		backendServer:    h.backendAddr,
		database:         beParams["database"],
		expiresAt:        creds.ExpiresAt,
		connectionTTLSec: creds.ConnectionTTLSeconds,
	}
	return sess, nil
}

// forwardedStartupParams is the allow-list of client-supplied Startup keys
// forwarded verbatim to the backend. `user` is always overwritten with the
// mapped role; anything outside this set is dropped to prevent privilege
// escalation via `options`, `replication`, etc.
var forwardedStartupParams = []string{
	"database",
	"application_name",
	"client_encoding",
	"DateStyle",
	"TimeZone",
	"IntervalStyle",
}

// authClientCleartext sends AuthenticationCleartextPassword and validates the
// returned password in constant time against the portal-supplied secret.
func authClientCleartext(client net.Conn, expected string) error {
	if _, err := client.Write(buildAuthRequest(authCleartextPass, nil)); err != nil {
		return fmt.Errorf("send auth request: %w", err)
	}
	msg, err := readMessage(client)
	if err != nil {
		return fmt.Errorf("read password message: %w", err)
	}
	if msg[0] != msgPasswordOrSASL {
		return fmt.Errorf("expected PasswordMessage, got %q", msg[0])
	}
	payload := messagePayload(msg)
	if len(payload) == 0 || payload[len(payload)-1] != 0 {
		return fmt.Errorf("malformed password message")
	}
	got := string(payload[:len(payload)-1])
	if !constantTimeStringEq(got, expected) {
		return fmt.Errorf("password mismatch")
	}
	return nil
}

// authClientSCRAM runs SCRAM-SHA-256 (or SCRAM-SHA-256-PLUS when the client
// connection is TLS-wrapped) with the proxy as server. `ctx` is not threaded
// through: cancellation is enforced via the client conn's deadline (set by
// HandleConn's handshakeTimeout) which unblocks every Read/Write and collapses
// the flow to a clean error — cheaper than checking ctx between every SCRAM
// step, and PBKDF2 itself cannot be interrupted mid-computation. A non-nil
// cache skips the PBKDF2 work on hits; nil falls back to a fresh
// random-salt compute each call.
//
// When `client` is a *tls.Conn, we advertise "SCRAM-SHA-256-PLUS,SCRAM-SHA-256"
// (PLUS first per RFC 5802 §6, so downgrade-aware clients prefer it). If
// cbRequired is true only PLUS is advertised and plain SCRAM is rejected.
//
// Channel-binding type: tls-server-end-point (RFC 5929) — this is what libpq /
// pgx / psycopg send for PostgreSQL SCRAM-SHA-256-PLUS. tls-unique (the task
// spec's first suggestion) is unusable on TLS 1.3 (ConnectionState.TLSUnique
// is nil) and tls-exporter (RFC 9266) is not implemented by PG clients. Using
// tls-server-end-point is the only interop-correct choice for this protocol.
func authClientSCRAM(client net.Conn, username, password string, cache *auth.SCRAMCache, cbRequired bool, tlsLeaf *x509.Certificate, log *slog.Logger) error {
	stored, err := auth.CachedSCRAMStoredCredentials(cache, password, auth.DefaultSCRAMIters)
	if err != nil {
		return fmt.Errorf("derive stored creds: %w", err)
	}

	tlsConn, isTLS := client.(*tls.Conn)
	if cbRequired && !isTLS {
		return fmt.Errorf("client-tls-cb-required set but client connection is not TLS")
	}

	var cbind scram.ChannelBinding
	if isTLS {
		cb, err := serverEndpointBinding(tlsConn, tlsLeaf)
		if err != nil {
			return fmt.Errorf("derive tls-server-end-point channel binding: %w", err)
		}
		cbind = cb
		// Channel-binding bytes are sensitive-ish (cert-hash-derived) and useless
		// to log plainly; always redact. Length tells us "bound" vs "empty";
		// fingerprintShort gives a debuggable breadcrumb without leaking the full hash.
		log.Debug("scram channel binding derived",
			"cb_type", string(cbind.Type),
			"cb_bytes", "[REDACTED]",
			"cb_len", len(cbind.Data),
			"leaf_fingerprint", fingerprintShort(tlsLeaf))
	}

	// AuthenticationSASL payload: NUL-terminated mech list, terminated by an
	// extra NUL. PLUS listed first on TLS so clients that accept either pick
	// the stronger one. We always advertise base SCRAM-SHA-256 alongside PLUS
	// even in cbRequired mode: pgx's SASL pre-flight checks for the presence
	// of `SCRAM-SHA-256` in the list and errors out ("server does not support
	// SCRAM-SHA-256") if it's missing, even when the user set
	// `channel_binding=require`. Enforcement of cbRequired happens at
	// mech-selection time below (we reject the client if it actually picks
	// base SCRAM), so advertising both here is a pgx-compat tweak with no
	// security cost.
	var mechs []byte
	if isTLS {
		mechs = append([]byte(scramMechPlus), 0)
		mechs = append(mechs, []byte(scramMech)...)
		mechs = append(mechs, 0)
	} else {
		mechs = append([]byte(scramMech), 0)
	}
	mechs = append(mechs, 0)
	if _, err := client.Write(buildAuthRequest(authSASL, mechs)); err != nil {
		return fmt.Errorf("send AuthSASL: %w", err)
	}

	// SASLInitialResponse: 'p' [mech\0][resp_len:4][resp_bytes]
	msg, err := readMessage(client)
	if err != nil {
		return fmt.Errorf("read SASLInitialResponse: %w", err)
	}
	if msg[0] != msgPasswordOrSASL {
		return fmt.Errorf("expected SASLInitialResponse, got %q", msg[0])
	}
	mech, clientFirst, err := parseSASLInitialResponse(messagePayload(msg))
	if err != nil {
		return fmt.Errorf("parse SASLInitialResponse: %w", err)
	}
	usePlus := false
	switch mech {
	case scramMech:
		if cbRequired {
			return fmt.Errorf("client picked %q but channel binding is required", mech)
		}
	case scramMechPlus:
		if !isTLS {
			return fmt.Errorf("client picked %q on non-TLS connection", mech)
		}
		usePlus = true
	default:
		return fmt.Errorf("client picked unsupported mechanism %q", mech)
	}

	// PostgreSQL SCRAM carries the username in the startup message, not in the
	// SCRAM `n=` field — libpq/pgx send `n=""`. We've already resolved the
	// user, so the callback just returns the stored creds we derived above.
	// lib/pq happens to send `n=username`; accept both (empty or matching).
	srv, err := scram.SHA256.NewServer(func(u string) (scram.StoredCredentials, error) {
		if u != "" && u != username {
			return scram.StoredCredentials{}, fmt.Errorf("scram n= mismatch: got %q want %q or empty", u, username)
		}
		return stored, nil
	})
	if err != nil {
		return fmt.Errorf("scram server: %w", err)
	}
	var conv *scram.ServerConversation
	switch {
	case usePlus:
		// Required variant: client MUST use channel binding. We only reach
		// this branch after the client already picked PLUS, so forbidding the
		// "y" (downgrade) flag is a defence-in-depth win with no UX cost.
		conv = srv.NewConversationWithChannelBindingRequired(cbind)
		log.Info("scram-plus selected", "mech", mech, "cb_type", string(cbind.Type))
	case isTLS:
		// Advertising variant: client saw PLUS but picked base. Library will
		// detect downgrade-attack attempts (client says "y" but server did
		// advertise PLUS) and error out of the conversation cleanly.
		conv = srv.NewConversationWithChannelBinding(cbind)
		log.Info("scram base selected on TLS (client declined PLUS)", "mech", mech)
	default:
		conv = srv.NewConversation()
	}

	serverFirst, err := conv.Step(string(clientFirst))
	if err != nil {
		return fmt.Errorf("scram step 1: %w", err)
	}
	if _, err := client.Write(buildAuthRequest(authSASLContinue, []byte(serverFirst))); err != nil {
		return fmt.Errorf("send SASLContinue: %w", err)
	}

	// SASLResponse: 'p' with raw client-final bytes.
	msg, err = readMessage(client)
	if err != nil {
		return fmt.Errorf("read SASLResponse: %w", err)
	}
	if msg[0] != msgPasswordOrSASL {
		return fmt.Errorf("expected SASLResponse, got %q", msg[0])
	}
	clientFinal := messagePayload(msg)
	serverFinal, err := conv.Step(string(clientFinal))
	if err != nil {
		return fmt.Errorf("scram step 2: %w", err)
	}
	if !conv.Valid() {
		return fmt.Errorf("scram conversation invalid")
	}
	if _, err := client.Write(buildAuthRequest(authSASLFinal, []byte(serverFinal))); err != nil {
		return fmt.Errorf("send SASLFinal: %w", err)
	}
	return nil
}

// authBackendAndCaptureTail authenticates to the backend as a SCRAM-SHA-256
// client (or accepts an immediate AuthenticationOk for trust/peer HBA setups)
// and buffers every post-auth frame up to and including ReadyForQuery. Nothing
// is written to the client — the caller is responsible for emitting the client-
// facing AuthenticationOk + the returned tail atomically so the client never
// sees a half-opened session.
func authBackendAndCaptureTail(backend net.Conn, username, password string) ([]byte, error) {
	cli, err := scram.SHA256.NewClient(username, password, "")
	if err != nil {
		return nil, fmt.Errorf("scram client: %w", err)
	}
	conv := cli.NewConversation()
	authDone := false

	for i := 0; i < maxPostAuthMessages; i++ {
		msg, err := readMessage(backend)
		if err != nil {
			return nil, fmt.Errorf("read backend msg: %w", err)
		}
		switch msg[0] {
		case msgErrorResponse:
			return nil, fmt.Errorf("backend rejected session: %s", parseErrorFields(messagePayload(msg)))
		case msgNoticeResponse:
			// Informational. Ignore during auth; forward after auth done.
			if authDone {
				return captureUntilReady(backend, msg)
			}
			continue
		case msgAuthRequest:
			payload := messagePayload(msg)
			if len(payload) < 4 {
				return nil, fmt.Errorf("short AuthenticationRequest")
			}
			sub := binary.BigEndian.Uint32(payload[0:4])
			switch sub {
			case authOK:
				// Either the backend accepted us without challenge (trust/peer
				// HBA) or we just finished SCRAM and AuthOk arrived. Both are
				// valid success paths.
				authDone = true
			case authSASL:
				if !mechsContain(payload[4:], scramMech) {
					return nil, fmt.Errorf("backend does not offer SCRAM-SHA-256")
				}
				clientFirst, err := conv.Step("")
				if err != nil {
					return nil, fmt.Errorf("scram client step 1: %w", err)
				}
				if _, err := backend.Write(buildSASLInitialResponse(scramMech, []byte(clientFirst))); err != nil {
					return nil, fmt.Errorf("send SASLInitialResponse: %w", err)
				}
			case authSASLContinue:
				clientFinal, err := conv.Step(string(payload[4:]))
				if err != nil {
					return nil, fmt.Errorf("scram client step 2: %w", err)
				}
				if _, err := backend.Write(buildSASLResponse([]byte(clientFinal))); err != nil {
					return nil, fmt.Errorf("send SASLResponse: %w", err)
				}
			case authSASLFinal:
				if _, err := conv.Step(string(payload[4:])); err != nil {
					return nil, fmt.Errorf("scram client step 3: %w", err)
				}
				// AuthenticationOk follows; next iteration handles it.
			default:
				return nil, fmt.Errorf("backend asked for unsupported auth sub-type %d", sub)
			}
		case msgParameterStat, msgBackendKeyData, msgReadyForQuery:
			if !authDone {
				return nil, fmt.Errorf("backend sent %q before AuthenticationOk", msg[0])
			}
			return captureUntilReady(backend, msg)
		default:
			return nil, fmt.Errorf("unexpected backend message type %q during bring-up", msg[0])
		}
	}
	return nil, fmt.Errorf("backend did not complete bring-up within %d messages", maxPostAuthMessages)
}

// captureUntilReady appends incoming backend messages to a buffer until the
// terminal ReadyForQuery frame is seen. `seed` is the first message already
// read by the caller (typically the first ParameterStatus or NoticeResponse).
func captureUntilReady(backend net.Conn, seed []byte) ([]byte, error) {
	buf := make([]byte, 0, 256)
	buf = append(buf, seed...)
	if seed[0] == msgReadyForQuery {
		return buf, nil
	}
	for i := 0; i < maxPostAuthMessages; i++ {
		msg, err := readMessage(backend)
		if err != nil {
			return nil, fmt.Errorf("read backend bring-up msg: %w", err)
		}
		switch msg[0] {
		case msgParameterStat, msgBackendKeyData, msgNoticeResponse:
			buf = append(buf, msg...)
		case msgReadyForQuery:
			buf = append(buf, msg...)
			return buf, nil
		case msgErrorResponse:
			return nil, fmt.Errorf("backend reported error during bring-up: %s", parseErrorFields(messagePayload(msg)))
		default:
			return nil, fmt.Errorf("unexpected backend message type %q during bring-up", msg[0])
		}
	}
	return nil, fmt.Errorf("backend did not signal ReadyForQuery within %d messages", maxPostAuthMessages)
}

// --- Wire format helpers ---

func buildAuthRequest(sub uint32, body []byte) []byte {
	payload := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(payload[0:4], sub)
	copy(payload[4:], body)
	return frameMessage(msgAuthRequest, payload)
}

func buildSASLInitialResponse(mech string, initialResp []byte) []byte {
	body := make([]byte, 0, len(mech)+1+4+len(initialResp))
	body = append(body, []byte(mech)...)
	body = append(body, 0)
	respLen := make([]byte, 4)
	binary.BigEndian.PutUint32(respLen, uint32(len(initialResp)))
	body = append(body, respLen...)
	body = append(body, initialResp...)
	return frameMessage(msgPasswordOrSASL, body)
}

func buildSASLResponse(b []byte) []byte {
	return frameMessage(msgPasswordOrSASL, b)
}

func parseSASLInitialResponse(body []byte) (string, []byte, error) {
	mech, rest, ok := readCString(body)
	if !ok {
		return "", nil, fmt.Errorf("mechanism not terminated")
	}
	if len(rest) < 4 {
		return "", nil, fmt.Errorf("missing response length")
	}
	respLen := int32(binary.BigEndian.Uint32(rest[0:4]))
	rest = rest[4:]
	// -1 means "no initial response"; clients that send SCRAM always include one.
	if respLen < 0 {
		return mech, nil, nil
	}
	if int(respLen) > len(rest) {
		return "", nil, fmt.Errorf("response length %d exceeds buffer %d", respLen, len(rest))
	}
	return mech, rest[:respLen], nil
}

// sendErrorResponse frames a PostgreSQL ErrorResponse with the minimum set of
// fields that drivers expect: S (severity, localised+non-localised), V
// (severity, always), C (SQLSTATE), M (message), and R (routine) — the last
// one is optional per spec but psql logs a blank "at: " when absent.
func sendErrorResponse(client net.Conn, sqlState, message string) error {
	body := make([]byte, 0, 96)
	body = appendErrField(body, 'S', "ERROR")
	body = appendErrField(body, 'V', "ERROR")
	body = appendErrField(body, 'C', sqlState)
	body = appendErrField(body, 'M', message)
	body = appendErrField(body, 'R', "proxy_auth")
	body = append(body, 0) // fields terminator
	_, err := client.Write(frameMessage(msgErrorResponse, body))
	return err
}

func appendErrField(b []byte, code byte, value string) []byte {
	b = append(b, code)
	b = append(b, []byte(value)...)
	b = append(b, 0)
	return b
}

func parseErrorFields(payload []byte) string {
	for len(payload) > 0 && payload[0] != 0 {
		field := payload[0]
		s, rest, ok := readCString(payload[1:])
		if !ok {
			return ""
		}
		if field == 'M' {
			return s
		}
		payload = rest
	}
	return ""
}

// frameMessage builds a regular PG message: [type:1][length:4 BE][payload].
// The length field counts itself but not the type byte.
func frameMessage(msgType byte, payload []byte) []byte {
	out := make([]byte, 1+4+len(payload))
	out[0] = msgType
	binary.BigEndian.PutUint32(out[1:5], uint32(4+len(payload)))
	copy(out[5:], payload)
	return out
}

func mechsContain(buf []byte, want string) bool {
	for {
		s, rest, ok := readCString(buf)
		if !ok || s == "" {
			return false
		}
		if s == want {
			return true
		}
		buf = rest
	}
}

// constantTimeStringEq wraps subtle.ConstantTimeCompare for string inputs.
// Length difference is *not* secret (revealed by cleartext PasswordMessage
// length anyway), so the early length check is safe.
func constantTimeStringEq(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}


