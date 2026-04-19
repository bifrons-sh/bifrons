package mongo

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/xdg-go/scram"
	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/babs/poc-proxies/internal/auth"
	"github.com/babs/poc-proxies/internal/proxy"
)

const maxAuthIterations = 16

// reqIDGen generates monotonic, per-connection request IDs for proxy-originated OP_MSGs.
type reqIDGen struct{ n uint32 }

func (g *reqIDGen) next() uint32 { return atomic.AddUint32(&g.n, 1) }

// handleAuth relays pre-auth commands and intercepts SASL to perform credential re-mapping.
// Returns the audit session context populated with the authenticated identity
// so the caller can tag subsequent audit entries.
func (h *Handler) handleAuth(ctx context.Context, client, backend net.Conn, log *slog.Logger) (*sessionAudit, error) {
	ids := &reqIDGen{n: 1000}
	for i := 0; i < maxAuthIterations; i++ {
		msg, err := readWireMessage(client)
		if err != nil {
			return nil, fmt.Errorf("read client message during auth: %w", err)
		}

		doc, err := extractFirstOpMsgDoc(msg)
		if err != nil || len(doc) == 0 {
			if err := forwardAndRelay(client, backend, msg); err != nil {
				return nil, err
			}
			continue
		}

		cmdName := doc[0].Key

		switch cmdName {
		case "saslStart":
			return h.handleSASLExchange(ctx, client, backend, msg, doc, ids, log)
		case "hello", "ismaster", "isMaster":
			if err := h.forwardHelloWithMechOverride(client, backend, msg, doc, ids); err != nil {
				return nil, err
			}
		default:
			if err := forwardAndRelay(client, backend, msg); err != nil {
				return nil, err
			}
		}
	}
	return nil, fmt.Errorf("exceeded max auth iterations (%d)", maxAuthIterations)
}

// handleSASLExchange authenticates the client via SCRAM, then authenticates to the backend.
func (h *Handler) handleSASLExchange(ctx context.Context, client, backend net.Conn, saslStartMsg []byte, saslStartDoc bson.D, ids *reqIDGen, log *slog.Logger) (*sessionAudit, error) {
	mechanism, _ := findKey(saslStartDoc, "mechanism").(string)
	if mechanism != "SCRAM-SHA-256" {
		_ = sendErrorResponse(client, saslStartMsg, fmt.Sprintf("unsupported mechanism: %s", mechanism), ids)
		return nil, fmt.Errorf("unsupported SASL mechanism: %s", mechanism)
	}

	payload, ok := findKey(saslStartDoc, "payload").(bson.Binary)
	if !ok {
		_ = sendErrorResponse(client, saslStartMsg, "missing payload", ids)
		return nil, fmt.Errorf("missing payload in saslStart")
	}
	clientFirst := string(payload.Data)

	username := extractSCRAMUsername(clientFirst)
	if username == "" {
		_ = sendErrorResponse(client, saslStartMsg, "could not extract username", ids)
		return nil, fmt.Errorf("could not extract username from SCRAM")
	}

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
		_ = sendErrorResponse(client, saslStartMsg, "authentication failed", ids)
		return nil, fmt.Errorf("auth lookup for %q: %w", username, err)
	}

	storedCreds, err := auth.CachedSCRAMStoredCredentials(h.scramCache, creds.Password, auth.DefaultSCRAMIters)
	if err != nil {
		return nil, fmt.Errorf("compute stored credentials: %w", err)
	}

	scramServer, err := scram.SHA256.NewServer(func(u string) (scram.StoredCredentials, error) {
		if u != username {
			return scram.StoredCredentials{}, fmt.Errorf("unknown user: %s", u)
		}
		return storedCreds, nil
	})
	if err != nil {
		return nil, fmt.Errorf("create SCRAM server: %w", err)
	}

	conv := scramServer.NewConversation()

	serverFirst, err := conv.Step(clientFirst)
	if err != nil {
		_ = sendErrorResponse(client, saslStartMsg, "SCRAM step 1 failed", ids)
		return nil, fmt.Errorf("SCRAM step 1: %w", err)
	}

	startReqID := getRequestID(saslStartMsg)
	if err := sendSASLResponse(client, startReqID, 1, false, []byte(serverFirst), ids); err != nil {
		return nil, fmt.Errorf("send server-first: %w", err)
	}

	contMsg, err := readWireMessage(client)
	if err != nil {
		return nil, fmt.Errorf("read saslContinue: %w", err)
	}
	contDoc, err := extractFirstOpMsgDoc(contMsg)
	if err != nil {
		return nil, fmt.Errorf("parse saslContinue: %w", err)
	}
	contPayload, ok := findKey(contDoc, "payload").(bson.Binary)
	if !ok {
		_ = sendErrorResponse(client, contMsg, "missing payload in saslContinue", ids)
		return nil, fmt.Errorf("missing payload in saslContinue")
	}
	clientFinal := string(contPayload.Data)

	serverFinal, err := conv.Step(clientFinal)
	if err != nil {
		_ = sendErrorResponse(client, contMsg, "authentication failed", ids)
		return nil, fmt.Errorf("SCRAM step 2 (validation): %w", err)
	}

	contReqID := getRequestID(contMsg)
	if err := sendSASLResponse(client, contReqID, 1, true, []byte(serverFinal), ids); err != nil {
		return nil, fmt.Errorf("send server-final: %w", err)
	}

	ackMsg, err := readWireMessage(client)
	if err != nil {
		return nil, fmt.Errorf("read SCRAM ack: %w", err)
	}
	ackReqID := getRequestID(ackMsg)
	if err := sendSASLResponse(client, ackReqID, 1, true, []byte{}, ids); err != nil {
		return nil, fmt.Errorf("send SCRAM ack: %w", err)
	}

	if !conv.Valid() {
		return nil, fmt.Errorf("SCRAM server conversation invalid")
	}

	log.Info("client authenticated", "user", username)

	if err := h.authenticateBackend(backend, creds, ids, log); err != nil {
		return nil, err
	}
	return &sessionAudit{
		username:         username,
		grantID:          creds.GrantID,
		role:             creds.Role,
		sourceIP:         proxy.SourceIP(client.RemoteAddr().String()),
		backendServer:    h.backendAddr,
		expiresAt:        creds.ExpiresAt,
		connectionTTLSec: creds.ConnectionTTLSeconds,
	}, nil
}

// authenticateBackend performs SCRAM-SHA-256 auth to the backend using the mapped credentials.
func (h *Handler) authenticateBackend(backend net.Conn, creds *auth.AuthResponse, ids *reqIDGen, log *slog.Logger) error {
	scramClient, err := scram.SHA256.NewClient(creds.BackendUser, creds.BackendPass, "")
	if err != nil {
		return fmt.Errorf("create SCRAM client: %w", err)
	}

	conv := scramClient.NewConversation()

	clientFirst, err := conv.Step("")
	if err != nil {
		return fmt.Errorf("SCRAM client step 1: %w", err)
	}

	saslStartDoc := bson.D{
		{Key: "saslStart", Value: int32(1)},
		{Key: "mechanism", Value: "SCRAM-SHA-256"},
		{Key: "payload", Value: bson.Binary{Data: []byte(clientFirst)}},
		{Key: "$db", Value: "admin"},
	}
	if err := writeOpMsg(backend, ids.next(), saslStartDoc); err != nil {
		return fmt.Errorf("send backend saslStart: %w", err)
	}

	resp, err := readWireMessage(backend)
	if err != nil {
		return fmt.Errorf("read backend saslStart response: %w", err)
	}
	respDoc, err := extractFirstOpMsgDoc(resp)
	if err != nil {
		return fmt.Errorf("parse backend response: %w", err)
	}

	if okVal, _ := findKey(respDoc, "ok").(float64); okVal != 1.0 {
		errmsg, _ := findKey(respDoc, "errmsg").(string)
		return fmt.Errorf("backend saslStart failed: %s", errmsg)
	}

	backendPayload, ok := findKey(respDoc, "payload").(bson.Binary)
	if !ok {
		return fmt.Errorf("backend saslStart missing payload")
	}
	serverFirst := string(backendPayload.Data)
	convID := findKey(respDoc, "conversationId")
	if convID == nil {
		return fmt.Errorf("backend saslStart missing conversationId")
	}

	clientFinal, err := conv.Step(serverFirst)
	if err != nil {
		return fmt.Errorf("SCRAM client step 2: %w", err)
	}

	saslContDoc := bson.D{
		{Key: "saslContinue", Value: int32(1)},
		{Key: "conversationId", Value: convID},
		{Key: "payload", Value: bson.Binary{Data: []byte(clientFinal)}},
		{Key: "$db", Value: "admin"},
	}
	if err := writeOpMsg(backend, ids.next(), saslContDoc); err != nil {
		return fmt.Errorf("send backend saslContinue: %w", err)
	}

	resp, err = readWireMessage(backend)
	if err != nil {
		return fmt.Errorf("read backend saslContinue response: %w", err)
	}
	respDoc, err = extractFirstOpMsgDoc(resp)
	if err != nil {
		return fmt.Errorf("parse backend saslContinue response: %w", err)
	}
	if okVal, _ := findKey(respDoc, "ok").(float64); okVal != 1.0 {
		errmsg, _ := findKey(respDoc, "errmsg").(string)
		return fmt.Errorf("backend saslContinue failed: %s", errmsg)
	}

	finalPayload, ok := findKey(respDoc, "payload").(bson.Binary)
	if !ok {
		return fmt.Errorf("backend saslContinue missing payload")
	}
	serverFinal := string(finalPayload.Data)
	done, _ := findKey(respDoc, "done").(bool)

	if _, err := conv.Step(serverFinal); err != nil {
		return fmt.Errorf("SCRAM client step 3 (verify server): %w", err)
	}

	if !done {
		ackDoc := bson.D{
			{Key: "saslContinue", Value: int32(1)},
			{Key: "conversationId", Value: convID},
			{Key: "payload", Value: bson.Binary{Data: []byte{}}},
			{Key: "$db", Value: "admin"},
		}
		if err := writeOpMsg(backend, ids.next(), ackDoc); err != nil {
			return fmt.Errorf("send backend SCRAM ack: %w", err)
		}
		if _, err := readWireMessage(backend); err != nil {
			return fmt.Errorf("read backend SCRAM ack: %w", err)
		}
	}

	if !conv.Done() {
		return fmt.Errorf("backend SCRAM exchange not complete")
	}

	log.Info("backend authenticated", "user", creds.BackendUser)
	return nil
}

// forwardHelloWithMechOverride forwards hello/ismaster to backend after stripping
// speculativeAuthenticate (driver-side 1-RTT auth won't work with re-mapping and
// leaking it to backend generates noisy auth failures). It then patches the response
// to advertise SCRAM-SHA-256 and removes any speculativeAuthenticate echo so drivers
// retry with explicit saslStart.
func (h *Handler) forwardHelloWithMechOverride(client, backend net.Conn, msg []byte, doc bson.D, ids *reqIDGen) error {
	// Strip speculativeAuthenticate from client hello before forwarding.
	outgoing := msg
	if stripped, ok := rewriteHelloWithoutSpeculative(msg, doc, ids); ok {
		outgoing = stripped
	}
	if _, err := backend.Write(outgoing); err != nil {
		return fmt.Errorf("forward hello: %w", err)
	}
	resp, err := readWireMessage(backend)
	if err != nil {
		return fmt.Errorf("read hello response: %w", err)
	}

	respDoc, err := extractFirstOpMsgDoc(resp)
	if err == nil {
		patched := false
		for i, elem := range respDoc {
			if elem.Key == "saslSupportedMechs" {
				respDoc[i].Value = bson.A{"SCRAM-SHA-256"}
				patched = true
				break
			}
		}
		if !patched {
			respDoc = append(respDoc, bson.E{Key: "saslSupportedMechs", Value: bson.A{"SCRAM-SHA-256"}})
		}
		// Remove any speculativeAuthenticate echo so the client falls back to explicit saslStart.
		respDoc = removeKey(respDoc, "speculativeAuthenticate")

		reqID := getRequestID(resp)
		responseTo := binary.LittleEndian.Uint32(resp[8:12])
		patchedMsg, marshalErr := buildOpMsgResponse(reqID, responseTo, respDoc)
		if marshalErr == nil {
			resp = patchedMsg
		}
	}

	if _, err := client.Write(resp); err != nil {
		return fmt.Errorf("relay hello response: %w", err)
	}
	return nil
}

// rewriteHelloWithoutSpeculative returns a re-marshalled hello message with
// speculativeAuthenticate removed. Client hello carries responseTo=0, so we use
// buildOpMsg and preserve the original requestID. Returns ok=false if no rewrite
// was needed or marshalling failed.
func rewriteHelloWithoutSpeculative(msg []byte, doc bson.D, _ *reqIDGen) ([]byte, bool) {
	if findKey(doc, "speculativeAuthenticate") == nil {
		return msg, false
	}
	newDoc := removeKey(doc, "speculativeAuthenticate")
	rebuilt, err := buildOpMsg(getRequestID(msg), newDoc)
	if err != nil {
		return msg, false
	}
	return rebuilt, true
}

func removeKey(doc bson.D, key string) bson.D {
	out := make(bson.D, 0, len(doc))
	for _, e := range doc {
		if e.Key == key {
			continue
		}
		out = append(out, e)
	}
	return out
}

// --- OP_MSG helpers ---

// extractFirstOpMsgDoc extracts the first BSON document from an OP_MSG (kind=0 section).
func extractFirstOpMsgDoc(msg []byte) (bson.D, error) {
	if len(msg) < headerSize+5 {
		return nil, fmt.Errorf("message too short for OP_MSG")
	}

	opCode := int(binary.LittleEndian.Uint32(msg[12:16]))
	if opCode != opMsg {
		return nil, fmt.Errorf("not OP_MSG (opcode=%d)", opCode)
	}

	offset := headerSize + 4 // skip header + flagBits
	if offset >= len(msg) {
		return nil, fmt.Errorf("no section data")
	}

	kind := msg[offset]
	offset++

	if kind != 0 {
		return nil, fmt.Errorf("first section is not kind 0")
	}

	if offset+4 > len(msg) {
		return nil, fmt.Errorf("no BSON doc length")
	}

	docLen := int(binary.LittleEndian.Uint32(msg[offset : offset+4]))
	if docLen < 5 || offset+docLen > len(msg) {
		return nil, fmt.Errorf("BSON doc exceeds message")
	}

	var doc bson.D
	if err := bson.Unmarshal(msg[offset:offset+docLen], &doc); err != nil {
		return nil, err
	}
	return doc, nil
}

// buildOpMsg constructs an OP_MSG with a single kind-0 section from a BSON document.
func buildOpMsg(requestID uint32, doc bson.D) ([]byte, error) {
	bsonDoc, err := bson.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("bson marshal: %w", err)
	}

	bodyLen := 4 + 1 + len(bsonDoc) // flagBits + kind + doc
	msgLen := headerSize + bodyLen

	msg := make([]byte, msgLen)
	binary.LittleEndian.PutUint32(msg[0:4], uint32(msgLen))
	binary.LittleEndian.PutUint32(msg[4:8], requestID)
	binary.LittleEndian.PutUint32(msg[8:12], 0)
	binary.LittleEndian.PutUint32(msg[12:16], uint32(opMsg))
	msg[headerSize+4] = 0 // kind = 0
	copy(msg[headerSize+5:], bsonDoc)

	return msg, nil
}

// buildOpMsgResponse constructs an OP_MSG response with responseTo set.
func buildOpMsgResponse(requestID, responseTo uint32, doc bson.D) ([]byte, error) {
	msg, err := buildOpMsg(requestID, doc)
	if err != nil {
		return nil, err
	}
	binary.LittleEndian.PutUint32(msg[8:12], responseTo)
	return msg, nil
}

// writeOpMsg builds and writes an OP_MSG; errors on either step propagate.
func writeOpMsg(conn net.Conn, requestID uint32, doc bson.D) error {
	msg, err := buildOpMsg(requestID, doc)
	if err != nil {
		return err
	}
	if _, err := conn.Write(msg); err != nil {
		return err
	}
	return nil
}

func getRequestID(msg []byte) uint32 {
	if len(msg) < 8 {
		return 0
	}
	return binary.LittleEndian.Uint32(msg[4:8])
}

// sendSASLResponse sends a SASL response OP_MSG to the client.
func sendSASLResponse(conn net.Conn, responseTo uint32, convID int32, done bool, payload []byte, ids *reqIDGen) error {
	doc := bson.D{
		{Key: "conversationId", Value: convID},
		{Key: "done", Value: done},
		{Key: "payload", Value: bson.Binary{Data: payload}},
		{Key: "ok", Value: float64(1)},
	}
	msg, err := buildOpMsgResponse(ids.next(), responseTo, doc)
	if err != nil {
		return err
	}
	_, err = conn.Write(msg)
	return err
}

// sendErrorResponse sends an error OP_MSG response.
func sendErrorResponse(conn net.Conn, requestMsg []byte, errMsg string, ids *reqIDGen) error {
	doc := bson.D{
		{Key: "ok", Value: float64(0)},
		{Key: "errmsg", Value: errMsg},
		{Key: "code", Value: int32(18)}, // AuthenticationFailed
		{Key: "codeName", Value: "AuthenticationFailed"},
	}
	msg, err := buildOpMsgResponse(ids.next(), getRequestID(requestMsg), doc)
	if err != nil {
		return err
	}
	_, err = conn.Write(msg)
	return err
}

// forwardAndRelay forwards a message to backend and relays the response to client.
func forwardAndRelay(client, backend net.Conn, msg []byte) error {
	if _, err := backend.Write(msg); err != nil {
		return fmt.Errorf("forward to backend: %w", err)
	}
	resp, err := readWireMessage(backend)
	if err != nil {
		return fmt.Errorf("read backend response: %w", err)
	}
	if _, err := client.Write(resp); err != nil {
		return fmt.Errorf("relay to client: %w", err)
	}
	return nil
}

func findKey(doc bson.D, key string) interface{} {
	for _, elem := range doc {
		if elem.Key == key {
			return elem.Value
		}
	}
	return nil
}

// extractSCRAMUsername extracts the username from a SCRAM client-first-message.
// RFC 5802 gs2-header + client-first-message-bare:
//
//	gs2-cbind-flag "," [ authzid ] "," username-attr "," nonce-attr [ "," extensions ]
//
// Attributes use `key=value`; username may contain `=2C` (comma) and `=3D` (equals).
func extractSCRAMUsername(clientFirst string) string {
	first := strings.IndexByte(clientFirst, ',')
	if first < 0 {
		return ""
	}
	second := strings.IndexByte(clientFirst[first+1:], ',')
	if second < 0 {
		return ""
	}
	bare := clientFirst[first+1+second+1:]

	for _, attr := range strings.Split(bare, ",") {
		if strings.HasPrefix(attr, "n=") {
			return scramUnescape(attr[2:])
		}
	}
	return ""
}

// scramUnescape decodes =2C/=3D per SCRAM saslname rules.
func scramUnescape(s string) string {
	if !strings.ContainsRune(s, '=') {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '=' && i+2 < len(s) {
			switch s[i+1 : i+3] {
			case "2C":
				b.WriteByte(',')
				i += 2
				continue
			case "3D":
				b.WriteByte('=')
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
