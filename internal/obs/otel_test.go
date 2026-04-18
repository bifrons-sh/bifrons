package obs

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace/noop"
)

// TestInitTracer_EmptyEndpointIsNoop verifies that without an OTLP endpoint,
// the global tracer provider stays at the default no-op — the cheapest hot
// path short of compile-time removal.
func TestInitTracer_EmptyEndpointIsNoop(t *testing.T) {
	// Reset the global to the noop provider so a prior test can't leak state.
	otel.SetTracerProvider(noop.NewTracerProvider())

	shutdown, err := InitTracer(context.Background(), "svc", "")
	if err != nil {
		t.Fatalf("InitTracer: %v", err)
	}
	if shutdown == nil {
		t.Fatal("expected non-nil shutdown (NoopShutdown)")
	}
	if err := shutdown(context.Background()); err != nil {
		t.Fatalf("noop shutdown returned error: %v", err)
	}

	tr := otel.Tracer("test")
	_, span := tr.Start(context.Background(), "op")
	defer span.End()
	// A no-op tracer produces non-recording spans — this is the whole point.
	if span.IsRecording() {
		t.Error("span should not be recording under no-op tracer")
	}
}

// TestInitTracerWithProcessor_RecordsSpan exercises the full pipeline: install
// an in-memory exporter via a simple span processor, then start/end a span and
// confirm it reaches the exporter. Proves the SDK wiring is correct.
func TestInitTracerWithProcessor_RecordsSpan(t *testing.T) {
	exp := tracetest.NewInMemoryExporter()
	sp := sdktrace.NewSimpleSpanProcessor(exp)

	shutdown, err := InitTracerWithProcessor("svc-test", "0.0.0-test", sp)
	if err != nil {
		t.Fatalf("InitTracerWithProcessor: %v", err)
	}
	t.Cleanup(func() {
		_ = shutdown(context.Background())
		// Drop to noop to avoid leaking provider into neighbouring tests.
		otel.SetTracerProvider(noop.NewTracerProvider())
	})

	tr := otel.Tracer("unit")
	_, span := tr.Start(context.Background(), "unit.op")
	span.End()

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}
	if spans[0].Name != "unit.op" {
		t.Errorf("unexpected span name: %q", spans[0].Name)
	}
}
