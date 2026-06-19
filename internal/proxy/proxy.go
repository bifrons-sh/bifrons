package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/babs/poc-proxies/internal/config"
	"github.com/babs/poc-proxies/internal/ratelimit"
	"github.com/babs/poc-proxies/internal/tlsutil"
)

// Handler is implemented by each protocol package.
type Handler interface {
	HandleConn(ctx context.Context, client net.Conn, dialBackend func(ctx context.Context) (net.Conn, error))
}

// Server is a TCP proxy server.
type Server struct {
	cfg     *config.Config
	handler Handler
	logger  *slog.Logger
	ln      net.Listener
	dial    func(ctx context.Context) (net.Conn, error)
	wg      sync.WaitGroup

	mu    sync.Mutex
	conns map[net.Conn]struct{} // active client conns (backends are closed via CloseOnDone per HandleConn)

	sem chan struct{} // nil when MaxConns = 0 (unlimited)

	// Counters are atomic to avoid coupling them to the connection-tracking
	// mutex: Stats() snapshot readers never block the accept/release hot path.
	accepted, rejected, active atomic.Uint64
	// rateLimited counts accepts refused by the per-IP bucket. Surfaced via
	// /metrics as rate_limited_total{dimension="ip"} on the proxy sidecar.
	rateLimited atomic.Uint64

	// Accept-side per-IP rate limiter (nil when disabled). Applied AFTER
	// Accept returns but BEFORE the handler goroutine spins up, so rejection
	// costs only a sleep+close (bounded by cfg.RateLimitCloseDelay).
	ipBuckets *ratelimit.Buckets

	// closeSlots bounds the number of concurrent sleep-then-close goroutines
	// spawned for rate-limited accepts. Security: without a cap, a spoofed-IP
	// flood would spawn one goroutine + hold one open fd per rejected conn for
	// the whole RateLimitCloseDelay window — a cheap amplification vector. When
	// the budget is exhausted we close immediately instead of lingering.
	closeSlots chan struct{}

	// tracer + pre-built static span attributes. When tracing is disabled
	// (global provider is no-op), Start is effectively free and spanAttrs is
	// never walked by the SDK, so carrying them is cheap.
	tracer    trace.Tracer
	spanAttrs []attribute.KeyValue
}

// Options overrides Server defaults (mainly for PG which must listen plain).
type Options struct {
	ForcePlainListener bool   // ignore cfg.ClientTLSEnabled for listener wrapping (protocol does upgrade itself)
	DBSystem           string // OpenTelemetry `db.system` attribute (mysql|postgresql|mongodb); empty leaves it unset
}

// New creates a proxy server. Call Serve to start accepting.
func New(cfg *config.Config, handler Handler, logger *slog.Logger) (*Server, error) {
	return NewWithOptions(cfg, handler, logger, Options{})
}

// NewWithOptions creates a proxy server with protocol-specific options.
func NewWithOptions(cfg *config.Config, handler Handler, logger *slog.Logger, opts Options) (*Server, error) {
	ln, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return nil, err
	}

	if cfg.ClientTLSEnabled && !opts.ForcePlainListener {
		tlsCfg, err := tlsutil.ListenerTLSConfig(cfg.ClientCertFile, cfg.ClientKeyFile, cfg.ClientCACertFile, cfg.ClientTLSRequired)
		if err != nil {
			ln.Close()
			return nil, err
		}
		ln = tls.NewListener(ln, tlsCfg)
	}

	var backendTLS *tls.Config
	if cfg.BackendTLSEnabled {
		backendTLS, err = tlsutil.DialerTLSConfig(cfg.BackendCACertFile, cfg.BackendCertFile, cfg.BackendKeyFile, cfg.BackendTLSInsecure)
		if err != nil {
			ln.Close()
			return nil, err
		}
	}

	dialTimeout := cfg.BackendDialTimeout
	if dialTimeout <= 0 {
		dialTimeout = 5 * time.Second
	}

	dial := func(ctx context.Context) (net.Conn, error) {
		d := net.Dialer{Timeout: dialTimeout}
		conn, err := d.DialContext(ctx, "tcp", cfg.BackendAddr)
		if err != nil {
			return nil, err
		}
		if backendTLS != nil {
			tlsConn := tls.Client(conn, backendTLS)
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				conn.Close()
				return nil, err
			}
			return tlsConn, nil
		}
		return conn, nil
	}

	s := &Server{
		cfg:     cfg,
		handler: handler,
		logger:  logger,
		ln:      ln,
		dial:    dial,
		conns:   make(map[net.Conn]struct{}),
	}
	if cfg.MaxConns > 0 {
		s.sem = make(chan struct{}, cfg.MaxConns)
	}
	if cfg.AuthRatePerIP > 0 {
		s.ipBuckets = ratelimit.New(ratelimit.PerMinute(cfg.AuthRatePerIP))
		// Bound concurrent linger-close goroutines. 256 is generous for the
		// intended brief-linger behavior on legitimate rate-limit responses
		// while capping the goroutine/fd cost under a flood at a small constant.
		s.closeSlots = make(chan struct{}, 256)
	}

	// Pre-compute span attributes that are static for the process so the hot
	// path does zero parsing/allocation beyond the per-span record itself.
	// When no tracer endpoint is configured, the global tracer is no-op and
	// span.Start short-circuits in ~1 ns with no allocations — hence pulling
	// the tracer up here (versus deferring to per-accept) is safe.
	s.tracer = otel.Tracer("github.com/babs/poc-proxies/internal/proxy")
	if host, port, err := net.SplitHostPort(cfg.BackendAddr); err == nil {
		attrs := make([]attribute.KeyValue, 0, 3)
		attrs = append(attrs, attribute.String("net.peer.name", host))
		if p, perr := strconv.Atoi(port); perr == nil {
			attrs = append(attrs, attribute.Int("net.peer.port", p))
		}
		if opts.DBSystem != "" {
			attrs = append(attrs, attribute.String("db.system", opts.DBSystem))
		}
		s.spanAttrs = attrs
	} else if opts.DBSystem != "" {
		s.spanAttrs = []attribute.KeyValue{attribute.String("db.system", opts.DBSystem)}
	}
	return s, nil
}

// Addr returns the listener's actual address (useful when listening on :0).
func (s *Server) Addr() net.Addr { return s.ln.Addr() }

// Close releases the listener and signals active client connections to terminate.
// Safe to call multiple times.
func (s *Server) Close() error {
	err := s.ln.Close()
	s.mu.Lock()
	for c := range s.conns {
		_ = c.Close()
	}
	s.mu.Unlock()
	return err
}

func (s *Server) trackConn(c net.Conn) {
	s.mu.Lock()
	s.conns[c] = struct{}{}
	s.mu.Unlock()
}

func (s *Server) untrackConn(c net.Conn) {
	s.mu.Lock()
	delete(s.conns, c)
	s.mu.Unlock()
}

// ErrShutdownTimeout is returned by Serve when active connections did not drain within the grace period.
var ErrShutdownTimeout = errors.New("shutdown grace period exceeded")

// Serve accepts connections until ctx is cancelled, then drains active connections.
func (s *Server) Serve(ctx context.Context) error {
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		<-ctx.Done()
		_ = s.Close()
	}()

	// Security: the accept-side per-IP bucket map grows one entry per distinct
	// source IP and never shrinks on its own. Under a spoofed-IP flood that is
	// an unbounded-memory (OOM) vector, so sweep idle buckets on a timer tied
	// to the Serve lifecycle. Cadence ~ the bucket TTL keeps the working set
	// bounded without sweeping so often it churns the lock.
	if s.ipBuckets != nil {
		sweepEvery := ratelimit.PerMinute(s.cfg.AuthRatePerIP).TTL
		if sweepEvery <= 0 {
			sweepEvery = 10 * time.Minute
		}
		ticker := time.NewTicker(sweepEvery)
		go func() {
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					s.ipBuckets.Sweep()
				}
			}
		}()
	}

	var (
		backoff    time.Duration
		maxBackoff = time.Second
	)

	for {
		conn, err := s.ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				break
			}
			if backoff == 0 {
				backoff = 5 * time.Millisecond
			} else {
				backoff *= 2
				if backoff > maxBackoff {
					backoff = maxBackoff
				}
			}
			s.logger.Error("accept error, backing off", "err", err, "backoff", backoff)

			t := time.NewTimer(backoff)
			select {
			case <-ctx.Done():
				t.Stop()
			case <-t.C:
			}
			continue
		}
		backoff = 0

		// Backstop for wedged backends with an idle client: TCP keepalive lets
		// the kernel detect a dead peer and tear the conn down even when the
		// revoke watcher / read deadlines don't fire. Guard the assertion — a
		// TLS listener yields *tls.Conn, not *net.TCPConn, so this is a no-op
		// there (the TLS base conn keepalive is handled by the stdlib dialer).
		if tcp, ok := conn.(*net.TCPConn); ok {
			_ = tcp.SetKeepAlive(true)
			_ = tcp.SetKeepAlivePeriod(60 * time.Second)
		}

		// Accept-side per-IP rate limit — evaluated BEFORE MaxConns so a
		// floodsource doesn't chew through the global cap and starve legit
		// clients. On rejection we hold the conn open for a brief window
		// (bounded by cfg.RateLimitCloseDelay) before RST; instant close
		// invites tight retry loops that amplify the attack.
		if s.ipBuckets != nil {
			ip := SourceIP(conn.RemoteAddr().String())
			if ip != "" && !s.ipBuckets.Allow(ip) {
				s.rateLimited.Add(1)
				s.logger.Warn("connection rate-limited",
					"remote", conn.RemoteAddr().String(),
					"dimension", "ip")
				// Bound the linger goroutine pool: take a close slot if one is
				// free (brief linger, the intended behavior), otherwise close
				// immediately so a flood can't accumulate goroutines + fds.
				select {
				case s.closeSlots <- struct{}{}:
					s.wg.Add(1)
					go func(c net.Conn) {
						defer s.wg.Done()
						defer func() { <-s.closeSlots }()
						s.rateLimitClose(c)
					}(conn)
				default:
					_ = conn.Close()
				}
				continue
			}
		}

		if s.sem != nil {
			select {
			case s.sem <- struct{}{}:
			default:
				s.rejected.Add(1)
				s.logger.Warn("connection rejected: cap reached",
					"remote", conn.RemoteAddr().String(), "cap", s.cfg.MaxConns)
				_ = conn.Close()
				continue
			}
		}

		s.trackConn(conn)
		s.accepted.Add(1)
		s.active.Add(1)

		s.wg.Add(1)
		go func(c net.Conn) {
			defer s.wg.Done()
			defer func() {
				if r := recover(); r != nil {
					s.logger.Error("panic in connection handler",
						"remote", c.RemoteAddr().String(),
						"panic", r,
						"stack", string(debug.Stack()))
				}
				s.untrackConn(c)
				_ = c.Close()
				s.active.Add(^uint64(0)) // atomic decrement
				if s.sem != nil {
					<-s.sem
				}
			}()
			handlerCtx, span := s.tracer.Start(ctx, "proxy.session",
				trace.WithSpanKind(trace.SpanKindServer),
				trace.WithAttributes(s.spanAttrs...),
			)
			s.handler.HandleConn(handlerCtx, c, s.dial)
			span.End()
		}(conn)
	}

	grace := s.cfg.ShutdownGracePeriod
	if grace <= 0 {
		grace = 30 * time.Second
	}
	drained := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(drained)
	}()

	t := time.NewTimer(grace)
	defer t.Stop()
	var serveErr error
	select {
	case <-drained:
	case <-t.C:
		s.logger.Warn("shutdown timeout, forcing close")
		_ = s.Close()
		// Give the forced close a brief window; don't block forever if a handler
		// is wedged inside a goroutine we cannot reach.
		force := time.NewTimer(5 * time.Second)
		defer force.Stop()
		select {
		case <-drained:
		case <-force.C:
			serveErr = ErrShutdownTimeout
		}
	}
	<-shutdownDone
	return serveErr
}

// Stats returns a snapshot of connection counters. Each load is independent,
// so the trio represents a lock-free best-effort view — two successive counts
// may differ by one connection in flight, which is acceptable for /metrics.
func (s *Server) Stats() (accepted, rejected, active uint64) {
	return s.accepted.Load(), s.rejected.Load(), s.active.Load()
}

// RateLimitStats returns (ipRejections, userRejections). User-dimension is
// always zero on the proxy (no username until post-handshake) but the shape
// matches the portal so obs.Server's callback type is shared.
func (s *Server) RateLimitStats() (ip, user uint64) {
	return s.rateLimited.Load(), 0
}

// rateLimitClose drops a freshly-accepted conn after a bounded pause. The
// sleep-then-close pattern lets legit clients see a clean close rather than
// RST-loops; the timer is short (default 100ms) so the goroutine cost is
// bounded in both memory and runtime even under a flood.
func (s *Server) rateLimitClose(c net.Conn) {
	delay := s.cfg.RateLimitCloseDelay
	if delay < 0 {
		delay = 0
	}
	if delay > 0 {
		t := time.NewTimer(delay)
		<-t.C
	}
	_ = c.Close()
}

// Relay copies data from src to dst, calling inspect on each chunk before forwarding.
// inspect may be nil for passthrough. If idleTimeout > 0, a rolling read deadline is applied.
//
// Contract: inspect MUST NOT retain the data slice — the backing buffer is reused on
// the next read. Copy the bytes if you need them beyond the call.
func Relay(dst, src net.Conn, inspect func(data []byte), idleTimeout time.Duration) error {
	buf := make([]byte, 32*1024)
	for {
		if idleTimeout > 0 {
			_ = src.SetReadDeadline(time.Now().Add(idleTimeout))
		}
		n, readErr := src.Read(buf)
		if n > 0 {
			if inspect != nil {
				func() {
					// inspect must never crash the relay, but a swallowed panic
					// hides an inspect-callback bug entirely — log it so it's
					// observable while preserving recover-and-continue behavior.
					defer func() {
						if r := recover(); r != nil {
							slog.Error("panic in relay inspect callback",
								"panic", r, "stack", string(debug.Stack()))
						}
					}()
					inspect(buf[:n])
				}()
			}
			if _, writeErr := dst.Write(buf[:n]); writeErr != nil {
				return writeErr
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) || errors.Is(readErr, net.ErrClosed) {
				return nil
			}
			return readErr
		}
	}
}

// IsClosed reports whether err is a "normal" end-of-connection signal:
// io.EOF, net.ErrClosed, or the pre-Go-1.16 "use of closed network connection"
// string (still emitted by some wrappers). Use this in relay code paths to
// distinguish clean shutdown from real errors.
func IsClosed(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	return strings.Contains(err.Error(), "use of closed network connection")
}

// SourceIP returns the host portion of a `host:port` address, or "" when the
// input cannot be parsed. Used by protocol handlers to populate the portal's
// `source_ip` field in auth lookup requests.
func SourceIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	return host
}

// HalfClose signals EOF to the peer on the write side.
// *net.TCPConn and TLS connections with a TCP base satisfy CloseWrite; anything else
// (net.Pipe in tests, TLS over non-stream conns) falls back to a full Close so the
// opposite-direction relay goroutine unblocks.
func HalfClose(c net.Conn) {
	type closeWriter interface{ CloseWrite() error }
	if cw, ok := c.(closeWriter); ok {
		if err := cw.CloseWrite(); err == nil {
			return
		}
	}
	_ = c.Close()
}

// CloseOnDone closes c when ctx is done, unless the returned stop func is called first.
// Use this to ensure backend conns get closed on shutdown even when the handler is
// blocked on a backend Read with no deadline left.
//
// Typical pattern:
//
//	stop := proxy.CloseOnDone(ctx, backend)
//	defer stop()
//
// The returned stop is idempotent and safe to call multiple times.
func CloseOnDone(ctx context.Context, c io.Closer) func() {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = c.Close()
		case <-done:
		}
	}()
	var once sync.Once
	return func() { once.Do(func() { close(done) }) }
}

// SafeGo runs fn in a new goroutine and sends its error (or a panic-derived error)
// to done. Prevents panics in inner relay goroutines from tearing down the process.
func SafeGo(logger *slog.Logger, tag string, fn func() error, done chan<- error) {
	go func() {
		var err error
		defer func() {
			if r := recover(); r != nil {
				logger.Error("panic in "+tag,
					"panic", r, "stack", string(debug.Stack()))
				err = fmt.Errorf("panic in %s: %v", tag, r)
			}
			done <- err
		}()
		err = fn()
	}()
}
