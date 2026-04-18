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
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/babs/poc-proxies/internal/config"
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
}

// Options overrides Server defaults (mainly for PG which must listen plain).
type Options struct {
	ForcePlainListener bool // ignore cfg.ClientTLSEnabled for listener wrapping (protocol does upgrade itself)
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
			s.handler.HandleConn(ctx, c, s.dial)
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
					defer func() { _ = recover() }() // inspect must never crash the relay
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
