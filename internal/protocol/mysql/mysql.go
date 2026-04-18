package mysql

import (
	"context"
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
	comQuit        = 0x01
	comInitDB      = 0x02
	comQuery       = 0x03
	comStmtPrepare = 0x16
	maxLogQuery    = 4096

	// Defence-in-depth caps on auth-phase loops.
	maxHandshakePackets = 16
	maxFullAuthPackets  = 8

	// caching_sha2_password auth-more-data status bytes
	cachingSha2FastAuthOK  = 0x03 // server tells client: fast auth succeeded; OK packet follows
	cachingSha2FullAuthReq = 0x04 // server tells client: full auth required; client sends pubkey req or password

	proxyType = "mysql"
)

// Handler implements proxy.Handler for the MySQL wire protocol.
type Handler struct {
	logger           *slog.Logger
	authClient       *auth.Client            // nil = pass-through (no auth re-mapping)
	auditClient      *audit.Client           // nil = local-log only, no portal shipping
	revokeClient     proxy.GrantStatusClient // nil = no mid-session revoke polling
	backendAddr      string                  // forwarded to auth.LookupRequest for per-backend policy
	handshakeTimeout time.Duration
	idleTimeout      time.Duration
	// caching_sha2_password full-auth pubkey cache, keyed by backend
	// RemoteAddr. Skips the extra RTT on subsequent connections to the same
	// server. MySQL rotates this key only on restart / explicit reset, so
	// staleness is caught by the next authentication failure and the caller
	// simply restarts — no automatic invalidation.
	pubKeyCache pubkeyLRU
}

// WithRevokeClient enables mid-session revoke polling. Must be called before Serve.
// Passing nil disables the watcher (equivalent to not calling this).
func (h *Handler) WithRevokeClient(c proxy.GrantStatusClient) *Handler {
	h.revokeClient = c
	return h
}

// sessionAudit carries per-connection identity into the relay goroutine so
// each logged/shipped query is tagged with the owning user and grant.
// ExpiresAt + ConnectionTTLSec are consumed by the revoke watcher only; they
// live here to keep handleAuth's return signature stable.
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

// NewHandler builds a MySQL handler with default timeouts.
// Prefer NewFromConfig to honour user-supplied timeouts.
func NewHandler(logger *slog.Logger) *Handler {
	return &Handler{
		logger:           logger.With("proxy", proxyType),
		handshakeTimeout: 15 * time.Second,
		idleTimeout:      5 * time.Minute,
	}
}

// NewFromConfig builds a MySQL handler whose deadlines + auth + audit clients come from cfg.
// Pass authClient=nil to keep pass-through behavior; auditClient=nil disables shipping.
// Zero durations fall back to defaults.
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
		log.Info("disconnect", "duration", time.Since(start).Round(time.Millisecond))
	}()

	// childCtx is cancelled by the revoke watcher (mid-session revocation or
	// hard TTL expiry) and by the deferred cancel below on any exit path.
	// Closing either client or backend conn unblocks both relay goroutines.
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

	// Handshake under deadline.
	if h.handshakeTimeout > 0 {
		_ = client.SetDeadline(time.Now().Add(h.handshakeTimeout))
		_ = backend.SetDeadline(time.Now().Add(h.handshakeTimeout))
	}
	var sess sessionAudit
	sess.sourceIP = proxy.SourceIP(clientAddr)
	sess.backendServer = h.backendAddr

	if h.authClient != nil {
		s, err := h.handleAuth(childCtx, client, backend, log)
		if err != nil {
			log.Error("auth failed", "err", err)
			return
		}
		sess = *s
		log.Info("auth remapping complete")
		// Mid-session revoke watcher. Runs only when a portal is wired for
		// polling AND the auth response carried a grant ID (pass-through auth
		// returns no grant, so there is nothing to revoke against).
		if h.revokeClient != nil && sess.grantID != "" {
			proxy.StartRevokeWatcher(childCtx, cancelChild, proxy.RevokeWatcherConfig{
				GrantID:              sess.grantID,
				ExpiresAt:            sess.expiresAt,
				ConnectionTTLSeconds: sess.connectionTTLSec,
				Client:               h.revokeClient,
				Logger:               log,
			})
		}
	} else {
		if err := h.relayHandshake(client, backend, log); err != nil {
			log.Error("handshake failed", "err", err)
			return
		}
		log.Info("authenticated")
	}
	// Clear handshake deadlines; relay uses its own idle deadline.
	_ = client.SetDeadline(time.Time{})
	_ = backend.SetDeadline(time.Time{})

	// Bidirectional relay: parse client→backend, passthrough backend→client.
	done := make(chan error, 2)
	proxy.SafeGo(log, "mysql client→backend", func() error { return h.relayClientPackets(client, backend, log, sess) }, done)
	proxy.SafeGo(log, "mysql backend→client", func() error { return proxy.Relay(client, backend, nil, h.idleTimeout) }, done)

	// Wait for first direction to finish, then tear down. childCtx captures
	// both parent shutdown and mid-session revocation/TTL via the watcher.
	select {
	case <-done:
	case <-childCtx.Done():
	}
	proxy.HalfClose(client)
	proxy.HalfClose(backend)
	<-done
}

// relayHandshake relays the MySQL auth handshake between server and client,
// including caching_sha2_password fast/full auth sub-flows.
func (h *Handler) relayHandshake(client, backend net.Conn, log *slog.Logger) error {
	// Server → client: initial handshake packet
	pkt, err := readPacket(backend)
	if err != nil {
		return fmt.Errorf("read server handshake: %w", err)
	}
	if err := writePacket(client, pkt); err != nil {
		return fmt.Errorf("forward server handshake: %w", err)
	}

	// Client → server: auth response
	pkt, err = readPacket(client)
	if err != nil {
		return fmt.Errorf("read client auth: %w", err)
	}
	if err := writePacket(backend, pkt); err != nil {
		return fmt.Errorf("forward client auth: %w", err)
	}

	// Server → client: auth result (may involve multiple round-trips for AuthSwitch / caching_sha2_password)
	for i := 0; i < maxHandshakePackets; i++ {
		pkt, err = readPacket(backend)
		if err != nil {
			return fmt.Errorf("read auth result: %w", err)
		}
		if err := writePacket(client, pkt); err != nil {
			return fmt.Errorf("forward auth result: %w", err)
		}

		payload := packetPayload(pkt)
		if len(payload) == 0 {
			return fmt.Errorf("empty auth response")
		}

		switch payload[0] {
		case 0x00: // OK
			return nil
		case 0xFF: // ERR
			return fmt.Errorf("auth error from server")
		case 0xFE: // AuthSwitch / old-auth
			pkt, err = readPacket(client)
			if err != nil {
				return fmt.Errorf("read auth switch response: %w", err)
			}
			if err := writePacket(backend, pkt); err != nil {
				return fmt.Errorf("forward auth switch response: %w", err)
			}
		case 0x01: // AuthMoreData (caching_sha2_password)
			// payload[1] selects sub-flow:
			//   0x03 fast_auth_ok → NO client response; server will send OK next
			//   0x04 full_auth_required → client sends public-key request or encrypted password
			if len(payload) < 2 {
				return fmt.Errorf("malformed AuthMoreData: short payload")
			}
			switch payload[1] {
			case cachingSha2FastAuthOK:
				// Next server packet should be OK (or ERR). Do NOT read from client.
				continue
			case cachingSha2FullAuthReq:
				// One or more client→server messages follow before the final OK/ERR.
				// Relay until we see an OK/ERR from the server again.
				if err := h.relayFullAuth(client, backend); err != nil {
					return err
				}
				// relayFullAuth returned because server sent OK/ERR; handshake done.
				return nil
			default:
				return fmt.Errorf("unknown AuthMoreData status: 0x%02x", payload[1])
			}
		default:
			// Some servers/plugins may send additional intermediate data whose first byte is
			// not one of the above. In the absence of protocol-specific knowledge, forward
			// one client packet and loop; this matches the original POC behaviour.
			pkt, err = readPacket(client)
			if err != nil {
				return fmt.Errorf("read auth continuation: %w", err)
			}
			if err := writePacket(backend, pkt); err != nil {
				return fmt.Errorf("forward auth continuation: %w", err)
			}
		}
	}
	return fmt.Errorf("exceeded max handshake packets (%d)", maxHandshakePackets)
}

// relayFullAuth handles caching_sha2_password full-auth sub-flow:
// client → [perform_full_authentication request / encrypted password]
// server → [public key | OK | ERR]  (may loop once for pubkey exchange)
func (h *Handler) relayFullAuth(client, backend net.Conn) error {
	for i := 0; i < maxFullAuthPackets; i++ {
		// Client sends next packet (pubkey request or password).
		pkt, err := readPacket(client)
		if err != nil {
			return fmt.Errorf("read full-auth client packet: %w", err)
		}
		if err := writePacket(backend, pkt); err != nil {
			return fmt.Errorf("forward full-auth client packet: %w", err)
		}

		// Server response.
		pkt, err = readPacket(backend)
		if err != nil {
			return fmt.Errorf("read full-auth server packet: %w", err)
		}
		if err := writePacket(client, pkt); err != nil {
			return fmt.Errorf("forward full-auth server packet: %w", err)
		}
		payload := packetPayload(pkt)
		if len(payload) == 0 {
			return fmt.Errorf("empty full-auth server response")
		}
		switch payload[0] {
		case 0x00:
			return nil // OK
		case 0xFF:
			return fmt.Errorf("full-auth error from server")
		case 0x01:
			// AuthMoreData (public key). Loop to read next client packet.
			continue
		default:
			// Unknown continuation; loop to stay generic.
			continue
		}
	}
	return fmt.Errorf("exceeded max full-auth packets (%d)", maxFullAuthPackets)
}

// relayClientPackets reads MySQL command packets from client, logs queries locally
// AND ships them to the portal audit endpoint if an audit client is configured,
// then forwards to backend. Returns nil on EOF/ErrClosed, underlying error otherwise.
func (h *Handler) relayClientPackets(client, backend net.Conn, log *slog.Logger, sess sessionAudit) error {
	for {
		if h.idleTimeout > 0 {
			_ = client.SetReadDeadline(time.Now().Add(h.idleTimeout))
		}
		pkt, err := readPacket(client)
		if err != nil {
			if proxy.IsClosed(err) {
				return nil
			}
			return err
		}

		payload := packetPayload(pkt)
		if len(payload) > 0 {
			switch payload[0] {
			case comQuery:
				h.recordQuery(log, &sess, "query", payload[1:])
			case comStmtPrepare:
				h.recordQuery(log, &sess, "prepare", payload[1:])
			case comInitDB:
				// COM_INIT_DB updates the session's default schema — track it
				// so subsequent audit entries carry the current database.
				sess.database = string(payload[1:])
				log.Info("use_db", "database", sess.database)
			case comQuit:
				if err := writePacket(backend, pkt); err != nil {
					return err
				}
				return nil
			}
		}

		if err := writePacket(backend, pkt); err != nil {
			return err
		}
	}
}

// recordQuery emits the local structured log line and submits an audit entry
// to the portal (if auditClient is configured). Truncation is applied once
// and carried through both sinks so they stay consistent.
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

// MySQL packet: [3-byte length LE][1-byte seq][payload]
func readPacket(r io.Reader) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}
	length := int(uint32(header[0]) | uint32(header[1])<<8 | uint32(header[2])<<16)
	pkt := make([]byte, 4+length)
	copy(pkt, header)
	if _, err := io.ReadFull(r, pkt[4:]); err != nil {
		return nil, err
	}
	return pkt, nil
}

func writePacket(w io.Writer, pkt []byte) error {
	_, err := w.Write(pkt)
	return err
}

func packetPayload(pkt []byte) []byte {
	if len(pkt) <= 4 {
		return nil
	}
	return pkt[4:]
}

