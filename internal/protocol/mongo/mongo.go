package mongo

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/babs/poc-proxies/internal/audit"
	"github.com/babs/poc-proxies/internal/auth"
	"github.com/babs/poc-proxies/internal/config"
	"github.com/babs/poc-proxies/internal/metrics"
	"github.com/babs/poc-proxies/internal/proxy"
)

const (
	opMsg        = 2013
	maxLogQuery  = 4096
	headerSize   = 16 // messageLength(4) + requestID(4) + responseTo(4) + opCode(4)
	maxMsgLen    = 48 * 1024 * 1024
	maxTargetLen = 128
	proxyType    = "mongo"
)

// Commands whose bodies must never be logged verbatim — they carry SCRAM payloads.
// Lookup keys MUST be lowercase; callers normalize cmdName before checking.
var sensitiveCommands = map[string]struct{}{
	"saslstart":    {},
	"saslcontinue": {},
	"createuser":   {},
	"updateuser":   {},
}

// Handler implements proxy.Handler for the MongoDB wire protocol.
type Handler struct {
	logger           *slog.Logger
	authClient       *auth.Client            // nil = pass-through (no auth re-mapping)
	auditClient      *audit.Client           // nil = local-log only, no portal shipping
	revokeClient     proxy.GrantStatusClient // nil = no mid-session revoke polling
	scramCache       *auth.SCRAMCache        // nil = compute stored creds on every auth
	backendAddr      string                  // passed to auth.LookupRequest for per-backend policy
	handshakeTimeout time.Duration
	idleTimeout      time.Duration

	// Observers — nil = no-op. Wired by WithMetrics.
	mAuthLookup  metrics.Observer
	mBackendDial metrics.Observer
	mHandshake   metrics.Observer
	mConnection  metrics.Observer
}

// WithMetrics wires a metrics.Registry. Nil-safe.
func (h *Handler) WithMetrics(r *metrics.Registry) *Handler {
	if r != nil {
		h.mAuthLookup = r.AuthLookup(proxyType)
		h.mBackendDial = r.BackendDial(proxyType)
		h.mHandshake = r.Handshake(proxyType)
		h.mConnection = r.Connection(proxyType)
	}
	return h
}

// WithRevokeClient enables mid-session revoke polling. Must be called before Serve.
func (h *Handler) WithRevokeClient(c proxy.GrantStatusClient) *Handler {
	h.revokeClient = c
	return h
}

// WithSCRAMCache attaches a PBKDF2 stored-credentials cache. Must be called
// before Serve. Passing nil disables caching (equivalent to the default).
func (h *Handler) WithSCRAMCache(c *auth.SCRAMCache) *Handler {
	h.scramCache = c
	return h
}

// sessionAudit carries per-connection identity into the relay goroutine so
// each shipped audit entry is tagged with the authenticated user + grant.
// ExpiresAt + ConnectionTTLSec are consumed by the revoke watcher only.
type sessionAudit struct {
	username         string
	grantID          string
	role             string
	sourceIP         string
	backendServer    string
	expiresAt        time.Time
	connectionTTLSec int
}

func NewHandler(logger *slog.Logger, authClient *auth.Client) *Handler {
	return &Handler{
		logger:           logger.With("proxy", proxyType),
		authClient:       authClient,
		handshakeTimeout: 15 * time.Second,
		idleTimeout:      5 * time.Minute,
	}
}

// NewFromConfig builds a Mongo handler whose deadlines + auth + audit clients come from cfg.
// Pass authClient=nil for pass-through, auditClient=nil for local-log only.
// Zero durations fall back to the same defaults as NewHandler so partially-populated
// test configs don't accidentally create already-expired handshake contexts.
func NewFromConfig(logger *slog.Logger, authClient *auth.Client, auditClient *audit.Client, cfg *config.Config) *Handler {
	h := &Handler{
		logger:           logger.With("proxy", proxyType),
		authClient:       authClient,
		auditClient:      auditClient,
		backendAddr:      cfg.BackendAddr,
		handshakeTimeout: cfg.HandshakeTimeout,
		idleTimeout:      cfg.IdleTimeout,
	}
	if h.handshakeTimeout <= 0 {
		h.handshakeTimeout = 15 * time.Second
	}
	if h.idleTimeout < 0 {
		h.idleTimeout = 0
	}
	return h
}

func (h *Handler) HandleConn(ctx context.Context, client net.Conn, dialBackend func(ctx context.Context) (net.Conn, error)) {
	start := time.Now()
	clientAddr := client.RemoteAddr().String()
	log := h.logger.With("client", clientAddr)
	log.Info("connect")

	defer func() {
		dur := time.Since(start)
		log.Info("disconnect", "duration", dur.Round(time.Millisecond))
		if h.mConnection != nil {
			h.mConnection.Observe(dur)
		}
	}()

	// childCtx is cancelled by the revoke watcher (mid-session revoke or hard
	// TTL expiry) and by the deferred cancel below on any exit path.
	childCtx, cancelChild := context.WithCancel(ctx)
	defer cancelChild()

	dialCtx, cancel := context.WithTimeout(childCtx, h.handshakeTimeout)
	dialStart := time.Now()
	backend, err := dialBackend(dialCtx)
	cancel()
	if h.mBackendDial != nil {
		h.mBackendDial.Observe(time.Since(dialStart))
	}
	if err != nil {
		log.Error("dial backend", "err", err)
		return
	}
	defer backend.Close()

	// Close-on-done wires both directions to childCtx: either side's closure
	// unblocks the relay goroutines so they can exit.
	stopBackendWatch := proxy.CloseOnDone(childCtx, backend)
	defer stopBackendWatch()
	stopClientWatch := proxy.CloseOnDone(childCtx, client)
	defer stopClientWatch()

	sess := sessionAudit{
		sourceIP:      proxy.SourceIP(clientAddr),
		backendServer: h.backendAddr,
	}
	if h.authClient != nil {
		if h.handshakeTimeout > 0 {
			_ = client.SetDeadline(time.Now().Add(h.handshakeTimeout))
			_ = backend.SetDeadline(time.Now().Add(h.handshakeTimeout))
		}
		hsStart := time.Now()
		s, err := h.handleAuth(childCtx, client, backend, log)
		if h.mHandshake != nil {
			h.mHandshake.Observe(time.Since(hsStart))
		}
		if err != nil {
			log.Error("auth failed", "err", err)
			return
		}
		if s != nil {
			sess = *s
		}
		_ = client.SetDeadline(time.Time{})
		_ = backend.SetDeadline(time.Time{})
		log.Info("auth remapping complete")

		if h.revokeClient != nil && sess.grantID != "" {
			proxy.StartRevokeWatcher(childCtx, cancelChild, proxy.RevokeWatcherConfig{
				GrantID:              sess.grantID,
				ExpiresAt:            sess.expiresAt,
				ConnectionTTLSeconds: sess.connectionTTLSec,
				Client:               h.revokeClient,
				Logger:               log,
			})
		}
	}

	done := make(chan error, 2)
	proxy.SafeGo(log, "mongo client→backend", func() error { return h.relayClientMessages(client, backend, log, sess) }, done)
	proxy.SafeGo(log, "mongo backend→client", func() error { return proxy.Relay(client, backend, nil, h.idleTimeout) }, done)

	select {
	case <-done:
	case <-childCtx.Done():
	}
	proxy.HalfClose(client)
	proxy.HalfClose(backend)
	<-done
}

// relayClientMessages reads MongoDB wire messages from client, logs commands
// locally AND ships them to the portal audit endpoint (when configured), then
// forwards to backend. Returns nil on EOF/ErrClosed, underlying error otherwise.
func (h *Handler) relayClientMessages(client, backend net.Conn, log *slog.Logger, sess sessionAudit) error {
	for {
		if h.idleTimeout > 0 {
			_ = client.SetReadDeadline(time.Now().Add(h.idleTimeout))
		}
		msg, err := readWireMessage(client)
		if err != nil {
			if proxy.IsClosed(err) {
				return nil
			}
			return err
		}

		h.inspectMessage(msg, log, &sess)

		if _, err := backend.Write(msg); err != nil {
			return err
		}
	}
}

func (h *Handler) inspectMessage(msg []byte, log *slog.Logger, sess *sessionAudit) {
	if len(msg) < headerSize {
		return
	}

	opCode := int(binary.LittleEndian.Uint32(msg[12:16]))
	if opCode != opMsg {
		log.Debug("non-OP_MSG", "opcode", opCode)
		return
	}

	body := msg[headerSize:]
	if len(body) < 5 {
		return
	}

	flagBits := binary.LittleEndian.Uint32(body[0:4])
	checksumPresent := flagBits&1 != 0

	sectionData := body[4:]
	if checksumPresent && len(sectionData) >= 4 {
		sectionData = sectionData[:len(sectionData)-4]
	}
	if len(sectionData) == 0 {
		return
	}

	for len(sectionData) > 0 {
		kind := sectionData[0]
		sectionData = sectionData[1:]

		var ok bool
		switch kind {
		case 0:
			sectionData, ok = h.parseMongoBSONSection(sectionData, log, sess)
		case 1:
			sectionData, ok = parseMongoDocSequenceSection(sectionData, log)
		default:
			return
		}
		// A malformed or truncated section means we cannot trust subsequent
		// offsets; stop inspecting rather than risk reading past the buffer.
		if !ok {
			return
		}
	}
}

// parseMongoBSONSection consumes a kind-0 (single BSON document) OP_MSG section,
// logs the command, and returns the remaining section data. ok is false when the
// section is truncated, signalling the caller to stop parsing.
func (h *Handler) parseMongoBSONSection(sectionData []byte, log *slog.Logger, sess *sessionAudit) (rest []byte, ok bool) {
	if len(sectionData) < 4 {
		return nil, false
	}
	docLen := int(binary.LittleEndian.Uint32(sectionData[0:4]))
	if docLen < 5 || docLen > len(sectionData) {
		return nil, false
	}
	h.logBSONCommand(sectionData[:docLen], log, sess)
	return sectionData[docLen:], true
}

// parseMongoDocSequenceSection consumes a kind-1 (document sequence) OP_MSG
// section, logging its identifier, and returns the remaining section data. ok is
// false when the section is truncated, signalling the caller to stop parsing.
func parseMongoDocSequenceSection(sectionData []byte, log *slog.Logger) (rest []byte, ok bool) {
	if len(sectionData) < 4 {
		return nil, false
	}
	seqLen := int(binary.LittleEndian.Uint32(sectionData[0:4]))
	if seqLen < 4 || seqLen > len(sectionData) {
		return nil, false
	}
	identEnd := 4
	for identEnd < seqLen && sectionData[identEnd] != 0 {
		identEnd++
	}
	if identEnd < seqLen {
		log.Info("document_sequence", "identifier", string(sectionData[4:identEnd]))
	}
	return sectionData[seqLen:], true
}

func (h *Handler) logBSONCommand(doc []byte, log *slog.Logger, sess *sessionAudit) {
	var parsed bson.D
	if err := bson.Unmarshal(doc, &parsed); err != nil {
		log.Debug("bson unmarshal error", "err", err)
		return
	}
	if len(parsed) == 0 {
		return
	}

	cmdName := parsed[0].Key
	target := commandTarget(parsed)

	if _, sensitive := sensitiveCommands[strings.ToLower(cmdName)]; sensitive {
		log.Info("command", "command", cmdName, "target", target, "body", "[REDACTED]")
		// Do NOT ship sensitive auth commands to the audit endpoint either.
		return
	}

	full := fmt.Sprintf("%v", parsed)
	truncated := false
	if len(full) > maxLogQuery {
		full = full[:maxLogQuery]
		truncated = true
	}

	log.Info("command",
		"command", cmdName,
		"target", target,
		"doc", full,
		"truncated", truncated,
	)

	if h.auditClient != nil && sess != nil {
		h.auditClient.Submit(audit.Entry{
			Timestamp:     time.Now().UTC(),
			GrantID:       sess.grantID,
			Username:      sess.username,
			ProxyType:     proxyType,
			BackendServer: sess.backendServer,
			Database:      target,
			Query:         cmdName + " " + full,
			Truncated:     truncated,
			SourceIP:      sess.sourceIP,
		})
	}
}

// commandTarget returns a short, log-safe stringification of the first command value.
// For admin commands the first value is an int (e.g. ping:1); for data commands it is
// the collection name. Output is capped to maxTargetLen characters.
func commandTarget(doc bson.D) string {
	if len(doc) == 0 {
		return ""
	}
	var s string
	if v, ok := doc[0].Value.(string); ok {
		s = v
	} else {
		s = fmt.Sprintf("%v", doc[0].Value)
	}
	if len(s) > maxTargetLen {
		return s[:maxTargetLen] + "…"
	}
	return s
}

// readWireMessage reads a complete MongoDB wire protocol message.
func readWireMessage(r io.Reader) ([]byte, error) {
	header := make([]byte, headerSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}

	msgLen := int(binary.LittleEndian.Uint32(header[0:4]))
	if msgLen < headerSize || msgLen > maxMsgLen {
		return nil, fmt.Errorf("invalid message length: %d", msgLen)
	}

	msg := make([]byte, msgLen)
	copy(msg, header)
	if _, err := io.ReadFull(r, msg[headerSize:]); err != nil {
		return nil, err
	}

	return msg, nil
}
