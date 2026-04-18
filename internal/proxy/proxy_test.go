package proxy

import (
	"context"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/babs/poc-proxies/internal/config"
)

func TestSourceIP(t *testing.T) {
	cases := map[string]string{
		"10.0.0.1:12345":         "10.0.0.1",
		"[::1]:5432":             "::1",
		"[2001:db8::1]:443":      "2001:db8::1",
		"garbage":                "",
		"":                       "",
	}
	for in, want := range cases {
		if got := SourceIP(in); got != want {
			t.Errorf("SourceIP(%q)=%q want %q", in, got, want)
		}
	}
}

type blockingHandler struct {
	wg   *sync.WaitGroup
	hold chan struct{}
}

func (b *blockingHandler) HandleConn(ctx context.Context, client net.Conn, dialBackend func(context.Context) (net.Conn, error)) {
	defer b.wg.Done()
	<-b.hold
}

func TestServer_MaxConns(t *testing.T) {
	cfg := &config.Config{
		ListenAddr:          "127.0.0.1:0",
		BackendAddr:         "127.0.0.1:1", // unused
		MaxConns:            2,
		HandshakeTimeout:    time.Second,
		IdleTimeout:         time.Second,
		ShutdownGracePeriod: time.Second,
	}

	var wg sync.WaitGroup
	hold := make(chan struct{})
	h := &blockingHandler{wg: &wg, hold: hold}

	srv, err := New(cfg, h, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan struct{})
	go func() { _ = srv.Serve(ctx); close(serveDone) }()

	addr := srv.Addr().String()

	// Open 3 connections; the 3rd must be rejected (closed immediately by the proxy).
	var conns []net.Conn
	for i := 0; i < 3; i++ {
		wg.Add(1) // pre-claim; decremented either by handler or by our close-path below
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		conns = append(conns, c)
	}

	// Give proxy a moment to accept+classify.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		_, rejected, active := srv.Stats()
		if rejected >= 1 && active == 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	accepted, rejected, active := srv.Stats()
	if rejected == 0 {
		t.Fatalf("expected at least 1 rejection, got accepted=%d rejected=%d active=%d", accepted, rejected, active)
	}
	if active != 2 {
		t.Fatalf("expected 2 active, got %d", active)
	}

	// Unblock handlers and shut down.
	close(hold)
	// The rejected connection did not enter the handler; decrement its pre-claim.
	wg.Done()

	for _, c := range conns {
		_ = c.Close()
	}
	cancel()
	<-serveDone
	wg.Wait()
}

func TestHalfClose_TLSFallsBackToCloseWrite(t *testing.T) {
	// Use a net.Pipe to prove fallback path doesn't panic; pipe is not *net.TCPConn,
	// and not *tls.Conn, so HalfClose falls back to Close(), unblocking the peer's Read.
	a, b := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 16)
		_, _ = b.Read(buf)
	}()
	HalfClose(a)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("HalfClose did not unblock peer Read within 1s")
	}
	_ = b.Close()
}

// echoHandler closes the client conn immediately so Serve's goroutine can end
// its span and we can observe it via the in-memory exporter.
type echoHandler struct{ wg *sync.WaitGroup }

func (h *echoHandler) HandleConn(ctx context.Context, client net.Conn, dialBackend func(context.Context) (net.Conn, error)) {
	defer h.wg.Done()
	_ = client.Close()
}

func TestServer_EmitsProxySessionSpan(t *testing.T) {
	// Install an in-memory span exporter backed by a simple processor — we
	// want synchronous export so the assertion does not race the batcher.
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sdktrace.NewSimpleSpanProcessor(exp)))
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	t.Cleanup(func() {
		_ = tp.Shutdown(context.Background())
		otel.SetTracerProvider(prev)
		// If the previous provider wasn't set, fall back to an explicit noop
		// to avoid bleeding the SDK provider into neighbouring tests.
		if prev == nil {
			otel.SetTracerProvider(noop.NewTracerProvider())
		}
	})

	cfg := &config.Config{
		ListenAddr:          "127.0.0.1:0",
		BackendAddr:         "127.0.0.1:65535",
		HandshakeTimeout:    time.Second,
		IdleTimeout:         time.Second,
		ShutdownGracePeriod: time.Second,
	}
	var wg sync.WaitGroup
	h := &echoHandler{wg: &wg}
	srv, err := NewWithOptions(cfg, h, slog.New(slog.NewJSONHandler(io.Discard, nil)), Options{DBSystem: "mysql"})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan struct{})
	go func() { _ = srv.Serve(ctx); close(serveDone) }()

	addr := srv.Addr().String()
	wg.Add(1)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	wg.Wait() // wait for handler goroutine to return so the span is ended
	_ = c.Close()
	cancel()
	<-serveDone

	spans := exp.GetSpans()
	if len(spans) == 0 {
		t.Fatal("expected at least one span, got 0")
	}
	found := false
	for _, s := range spans {
		if s.Name == "proxy.session" {
			found = true
			var gotDBSystem, gotPeerName bool
			for _, a := range s.Attributes {
				switch string(a.Key) {
				case "db.system":
					if a.Value.AsString() != "mysql" {
						t.Errorf("db.system=%q want mysql", a.Value.AsString())
					}
					gotDBSystem = true
				case "net.peer.name":
					if a.Value.AsString() != "127.0.0.1" {
						t.Errorf("net.peer.name=%q want 127.0.0.1", a.Value.AsString())
					}
					gotPeerName = true
				}
			}
			if !gotDBSystem {
				t.Error("missing db.system attribute")
			}
			if !gotPeerName {
				t.Error("missing net.peer.name attribute")
			}
			break
		}
	}
	if !found {
		t.Fatalf("no proxy.session span in %v", spans)
	}
}

func TestRelay_Passthrough(t *testing.T) {
	src, srcW := net.Pipe()
	dst, dstR := net.Pipe()

	var got atomic.Value
	go func() {
		buf := make([]byte, 1024)
		n, _ := dstR.Read(buf)
		got.Store(string(buf[:n]))
	}()
	go func() {
		_, _ = srcW.Write([]byte("hello"))
		_ = srcW.Close()
	}()

	_ = Relay(dst, src, nil, 500*time.Millisecond)
	_ = dst.Close()
	_ = dstR.Close()

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if v := got.Load(); v != nil && v.(string) == "hello" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("did not see relayed bytes")
}
