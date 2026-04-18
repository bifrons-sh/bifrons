package api

import (
	"context"
	"io"
	"log/slog"
	"net/http/httptest"
	"testing"

	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/babs/poc-proxies/internal/auth"
	"github.com/babs/poc-proxies/portal/internal/config"
	"github.com/babs/poc-proxies/portal/internal/policy"
	"github.com/babs/poc-proxies/portal/internal/store"
)

// TestRouter_EmitsHTTPSpan exercises the otelhttp wrapper baked into
// NewRouter: one request → one server span in the in-memory exporter.
func TestRouter_EmitsHTTPSpan(t *testing.T) {
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sdktrace.NewSimpleSpanProcessor(exp)))
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	t.Cleanup(func() {
		_ = tp.Shutdown(context.Background())
		otel.SetTracerProvider(prev)
		if prev == nil {
			otel.SetTracerProvider(noop.NewTracerProvider())
		}
	})

	cfg := &config.Config{ProxyToken: "t"}
	s := store.NewMemory()
	eng := policy.New(s)
	h := NewRouter(cfg, s, eng, nil, slog.New(slog.NewJSONHandler(io.Discard, nil)))

	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	// Use the running test server so otelhttp treats the request as an inbound
	// server call (matches the production surface).
	body := auth.LookupRequest{Username: "x", ProxyType: "mongo", BackendServer: "127.0.0.1:27017"}
	resp := postJSON(t, srv.URL+"/api/v1/auth", body, map[string]string{"X-Portal-Token": "t"})
	defer resp.Body.Close()

	spans := exp.GetSpans()
	if len(spans) == 0 {
		t.Fatal("expected at least one span from otelhttp wrapper, got 0")
	}
}
