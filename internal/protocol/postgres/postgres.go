package postgres

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/babs/poc-proxies/internal/audit"
	"github.com/babs/poc-proxies/internal/auth"
	"github.com/babs/poc-proxies/internal/config"
	"github.com/babs/poc-proxies/internal/proxy"
)

const (
	sslRequestCode    = 80877103
	gssEncRequestCode = 80877104
	cancelRequestCode = 80877102
	maxLogQuery       = 4096
	maxStartupLen     = 10 * 1024 * 1024
	maxMessageLen     = 16 * 1024 * 1024
	maxAuthMessages   = 32 // defence-in-depth cap on auth-phase relay loop
)

// Handler implements proxy.Handler for the PostgreSQL wire protocol.
type Handler struct {
	logger           *slog.Logger
	clientTLSCfg     *tls.Config             // optional: for SSLRequest upgrade when listener is plain TCP
	authClient       *auth.Client            // nil = pass-through (no auth re-mapping)
	auditClient      *audit.Client           // nil = local-log only, no portal shipping
	revokeClient     proxy.GrantStatusClient // nil = no mid-session revoke polling
	backendAddr      string                  // forwarded to auth.LookupRequest for per-backend policy
	clientAuthMethod ClientAuthMethod        // SCRAM (default) or cleartext for legacy clients
	clientTLSCBReq   bool                    // force SCRAM-SHA-256-PLUS on TLS client conns
	clientTLSLeaf    *x509.Certificate       // parsed leaf for tls-server-end-point (nil when no TLS configured)
	handshakeTimeout time.Duration
	idleTimeout      time.Duration
}

// WithRevokeClient enables mid-session revoke polling. Must be called before Serve.
func (h *Handler) WithRevokeClient(c proxy.GrantStatusClient) *Handler {
	h.revokeClient = c
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
	database         string
	expiresAt        time.Time
	connectionTTLSec int
}

func NewHandler(logger *slog.Logger, clientTLSCfg *tls.Config) *Handler {
	h := &Handler{
		logger:           logger.With("proxy", proxyType),
		clientTLSCfg:     clientTLSCfg,
		clientAuthMethod: ClientAuthSCRAM,
		handshakeTimeout: 15 * time.Second,
		idleTimeout:      5 * time.Minute,
	}
	h.populateTLSLeaf()
	return h
}

// populateTLSLeaf parses the first TLS certificate out of clientTLSCfg and
// caches its x509 form. This is what feeds tls-server-end-point channel
// binding (RFC 5929) for SCRAM-SHA-256-PLUS: on the server side of a
// non-mTLS TLS handshake, tls.ConnectionState.PeerCertificates is empty, so
// we need the leaf from another source. Errors are logged-and-ignored: if a
// PLUS client connects later it will fail cleanly in the SCRAM flow, which is
// strictly better than blocking all connections at startup for a
// misconfigured cert when only non-TLS clients may ever connect.
func (h *Handler) populateTLSLeaf() {
	if h.clientTLSCfg == nil || len(h.clientTLSCfg.Certificates) == 0 {
		return
	}
	leaf, err := parseLeaf(&h.clientTLSCfg.Certificates[0])
	if err != nil {
		h.logger.Warn("parse TLS leaf for channel binding", "err", err)
		return
	}
	h.clientTLSLeaf = leaf
}

// NewFromConfig builds a Postgres handler whose deadlines + auth + audit clients come from cfg.
// Pass authClient=nil for pass-through behavior, auditClient=nil for local-log only.
// Zero durations fall back to defaults.
func NewFromConfig(logger *slog.Logger, clientTLSCfg *tls.Config, authClient *auth.Client, auditClient *audit.Client, clientAuth ClientAuthMethod, cfg *config.Config) *Handler {
	if clientAuth == "" {
		clientAuth = ClientAuthSCRAM
	}
	h := &Handler{
		logger:           logger.With("proxy", proxyType),
		clientTLSCfg:     clientTLSCfg,
		authClient:       authClient,
		auditClient:      auditClient,
		backendAddr:      cfg.BackendAddr,
		clientAuthMethod: clientAuth,
		clientTLSCBReq:   cfg.ClientTLSCBRequired,
		handshakeTimeout: cfg.HandshakeTimeout,
		idleTimeout:      cfg.IdleTimeout,
	}
	if h.handshakeTimeout <= 0 {
		h.handshakeTimeout = 15 * time.Second
	}
	if h.idleTimeout < 0 {
		h.idleTimeout = 0
	}
	h.populateTLSLeaf()
	return h
}

// errCancelForwarded is a sentinel used to unwind handleStartup for CancelRequest;
// the startup caller closes the connection without entering the relay phase.
var errCancelForwarded = errors.New("cancel request forwarded")

func (h *Handler) HandleConn(ctx context.Context, client net.Conn, dialBackend func(ctx context.Context) (net.Conn, error)) {
	start := time.Now()
	clientAddr := client.RemoteAddr().String()
	log := h.logger.With("client", clientAddr)
	log.Info("connect")

	defer func() {
		log.Info("disconnect", "duration", time.Since(start).Round(time.Millisecond))
	}()

	// childCtx is cancelled by the revoke watcher (mid-session revoke or hard
	// TTL expiry) and by the deferred cancel below on any exit path.
	childCtx, cancelChild := context.WithCancel(ctx)
	defer cancelChild()

	dialCtx, cancel := context.WithTimeout(childCtx, h.handshakeTimeout)
	backend, err := dialBackend(dialCtx)
	cancel()
	if err != nil {
		log.Error("dial backend", "err", err)
		return
	}
	defer backend.Close()

	stopBackendWatch := proxy.CloseOnDone(childCtx, backend)
	defer stopBackendWatch()
	stopClientWatch := proxy.CloseOnDone(childCtx, client)
	defer stopClientWatch()

	if h.handshakeTimeout > 0 {
		_ = client.SetDeadline(time.Now().Add(h.handshakeTimeout))
		_ = backend.SetDeadline(time.Now().Add(h.handshakeTimeout))
	}
	sess := sessionAudit{
		sourceIP:      proxy.SourceIP(clientAddr),
		backendServer: h.backendAddr,
	}
	client, s, err := h.handleStartup(childCtx, client, backend, log)
	if err != nil {
		if errors.Is(err, errCancelForwarded) {
			log.Info("cancel request forwarded")
			return
		}
		log.Error("startup failed", "err", err)
		return
	}
	if s != nil {
		sess = *s
	}
	_ = client.SetDeadline(time.Time{})
	_ = backend.SetDeadline(time.Time{})

	log.Info("authenticated")

	// Mid-session revoke watcher. See mysql/mongo handlers for rationale.
	if h.revokeClient != nil && sess.grantID != "" {
		proxy.StartRevokeWatcher(childCtx, cancelChild, proxy.RevokeWatcherConfig{
			GrantID:              sess.grantID,
			ExpiresAt:            sess.expiresAt,
			ConnectionTTLSeconds: sess.connectionTTLSec,
			Client:               h.revokeClient,
			Logger:               log,
		})
	}

	done := make(chan error, 2)
	proxy.SafeGo(log, "pg client→backend", func() error { return h.relayClientMessages(client, backend, log, sess) }, done)
	proxy.SafeGo(log, "pg backend→client", func() error { return proxy.Relay(client, backend, nil, h.idleTimeout) }, done)

	select {
	case <-done:
	case <-childCtx.Done():
	}
	proxy.HalfClose(client)
	proxy.HalfClose(backend)
	<-done
}

// handleStartup handles SSLRequest/GSSENCRequest/CancelRequest, startup message, and auth.
// Returns (possibly TLS-upgraded) client conn plus an audit session context (nil for
// pass-through mode). For CancelRequest the message is forwarded and the function
// returns errCancelForwarded so the caller closes cleanly.
func (h *Handler) handleStartup(ctx context.Context, client net.Conn, backend net.Conn, log *slog.Logger) (net.Conn, *sessionAudit, error) {
	msg, err := readStartupMessage(client)
	if err != nil {
		return client, nil, fmt.Errorf("read startup: %w", err)
	}

	if len(msg) >= 8 {
		code := binary.BigEndian.Uint32(msg[4:8])
		switch code {
		case sslRequestCode:
			if h.clientTLSCfg != nil {
				if _, err := client.Write([]byte{'S'}); err != nil {
					return client, nil, fmt.Errorf("send SSL accept: %w", err)
				}
				tlsConn := tls.Server(client, h.clientTLSCfg)
				if err := tlsConn.Handshake(); err != nil {
					return client, nil, fmt.Errorf("client TLS handshake: %w", err)
				}
				client = tlsConn
				log.Info("client TLS upgraded")
			} else {
				if _, err := client.Write([]byte{'N'}); err != nil {
					return client, nil, fmt.Errorf("send SSL reject: %w", err)
				}
			}
			msg, err = readStartupMessage(client)
			if err != nil {
				return client, nil, fmt.Errorf("read startup after SSL: %w", err)
			}
			// Client may send CancelRequest over the freshly TLS-upgraded conn.
			if len(msg) >= 8 && binary.BigEndian.Uint32(msg[4:8]) == cancelRequestCode {
				if _, err := backend.Write(msg); err != nil {
					return client, nil, fmt.Errorf("forward cancel (post-SSL): %w", err)
				}
				return client, nil, errCancelForwarded
			}
		case gssEncRequestCode:
			if _, err := client.Write([]byte{'N'}); err != nil {
				return client, nil, fmt.Errorf("send GSS reject: %w", err)
			}
			msg, err = readStartupMessage(client)
			if err != nil {
				return client, nil, fmt.Errorf("read startup after GSS reject: %w", err)
			}
		case cancelRequestCode:
			// CancelRequest is fire-and-forget: forward the message and close both sides.
			// The backend does not respond. We never enter auth or relay for this conn.
			if _, err := backend.Write(msg); err != nil {
				return client, nil, fmt.Errorf("forward cancel: %w", err)
			}
			return client, nil, errCancelForwarded
		}
	}

	if h.authClient != nil {
		// Auth re-mapping path: don't forward the original startup; handleAuth
		// rebuilds a backend startup with the mapped user after terminating
		// client auth locally.
		sess, err := h.handleAuth(ctx, client, backend, msg, log)
		if err != nil {
			return client, nil, err
		}
		return client, sess, nil
	}

	if _, err := backend.Write(msg); err != nil {
		return client, nil, fmt.Errorf("forward startup: %w", err)
	}

	if err := h.relayAuth(client, backend, log); err != nil {
		return client, nil, err
	}
	return client, nil, nil
}

// relayAuth relays backend auth messages to client (and client responses) until ReadyForQuery.
// All other intermediate message types are forwarded untouched. The loop is capped at
// maxAuthMessages as defence in depth against a compromised/misbehaving backend.
func (h *Handler) relayAuth(client, backend net.Conn, log *slog.Logger) error {
	for i := 0; i < maxAuthMessages; i++ {
		msg, err := readMessage(backend)
		if err != nil {
			return fmt.Errorf("read auth message: %w", err)
		}
		if _, err := client.Write(msg); err != nil {
			return fmt.Errorf("forward auth message: %w", err)
		}

		msgType := msg[0]
		switch msgType {
		case 'Z': // ReadyForQuery — auth complete
			return nil
		case 'E': // ErrorResponse
			return fmt.Errorf("auth error from server")
		case 'R': // Authentication request
			if len(msg) >= 9 {
				authType := binary.BigEndian.Uint32(msg[5:9])
				switch authType {
				case 0, 12: // AuthenticationOk / AuthenticationSASLFinal → no client response
					continue
				}
			}
			resp, err := readMessage(client)
			if err != nil {
				return fmt.Errorf("read client auth response: %w", err)
			}
			if _, err := backend.Write(resp); err != nil {
				return fmt.Errorf("forward client auth response: %w", err)
			}
		}
	}
	return fmt.Errorf("exceeded max auth messages (%d)", maxAuthMessages)
}

// relayClientMessages reads framed PG messages from client, logs queries
// locally AND ships them to the portal audit endpoint (when configured), then
// forwards to backend. Returns nil on EOF/ErrClosed, underlying error otherwise.
func (h *Handler) relayClientMessages(client, backend net.Conn, log *slog.Logger, sess sessionAudit) error {
	for {
		if h.idleTimeout > 0 {
			_ = client.SetReadDeadline(time.Now().Add(h.idleTimeout))
		}
		msg, err := readMessage(client)
		if err != nil {
			if proxy.IsClosed(err) {
				return nil
			}
			return err
		}

		msgType := msg[0]
		payload := messagePayload(msg)

		switch msgType {
		case 'Q':
			h.recordQuery(log, &sess, "query", trimNull(payload))
		case 'P':
			if query := extractParseQuery(payload); query != "" {
				h.recordQuery(log, &sess, "prepare", []byte(query))
			}
		case 'X':
			if _, err := backend.Write(msg); err != nil {
				return err
			}
			return nil
		}

		if _, err := backend.Write(msg); err != nil {
			return err
		}
	}
}

// recordQuery logs locally and ships to the portal audit endpoint if configured.
func (h *Handler) recordQuery(log *slog.Logger, sess *sessionAudit, event string, query []byte) {
	q := string(query)
	truncated := false
	if len(q) > maxLogQuery {
		q = q[:maxLogQuery]
		truncated = true
	}
	log.Info(event, "query", q, "truncated", truncated)
	if h.auditClient == nil {
		return
	}
	h.auditClient.Submit(audit.Entry{
		Timestamp:     time.Now().UTC(),
		GrantID:       sess.grantID,
		Username:      sess.username,
		ProxyType:     proxyType,
		BackendServer: sess.backendServer,
		Database:      sess.database,
		Query:         q,
		Truncated:     truncated,
		SourceIP:      sess.sourceIP,
	})
}

// readStartupMessage reads a PostgreSQL startup-format message (4-byte length + payload).
func readStartupMessage(r io.Reader) ([]byte, error) {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint32(lenBuf))
	if length < 4 || length > maxStartupLen {
		return nil, fmt.Errorf("invalid startup message length: %d", length)
	}
	msg := make([]byte, length)
	copy(msg, lenBuf)
	if _, err := io.ReadFull(r, msg[4:]); err != nil {
		return nil, err
	}
	return msg, nil
}

// readMessage reads a framed PG message: [1-byte type][4-byte length BE][payload].
func readMessage(r io.Reader) ([]byte, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint32(header[1:5]))
	if length < 4 || length > maxMessageLen {
		return nil, fmt.Errorf("invalid message length: %d", length)
	}
	msg := make([]byte, 1+length)
	copy(msg, header)
	if _, err := io.ReadFull(r, msg[5:]); err != nil {
		return nil, err
	}
	return msg, nil
}

func messagePayload(msg []byte) []byte {
	if len(msg) <= 5 {
		return nil
	}
	return msg[5:]
}

func trimNull(b []byte) []byte {
	if len(b) > 0 && b[len(b)-1] == 0 {
		return b[:len(b)-1]
	}
	return b
}

// extractParseQuery extracts the SQL string from a Parse message payload.
// Format: destination_string\0 query_string\0 int16_param_count param_oids...
func extractParseQuery(payload []byte) string {
	i := 0
	for i < len(payload) && payload[i] != 0 {
		i++
	}
	i++
	if i >= len(payload) {
		return ""
	}
	start := i
	for i < len(payload) && payload[i] != 0 {
		i++
	}
	return string(payload[start:i])
}
