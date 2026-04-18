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

// TestOtelSampler_Env exercises every OTEL_TRACES_SAMPLER branch including the
// default and the invalid-name fallback. We can't inspect the sampler directly
// (AlwaysSample vs ParentBased wraps it) so we assert on description, which is
// stable across OTel SDK versions.
func TestOtelSampler_Env(t *testing.T) {
	cases := []struct {
		name    string
		sampler string
		arg     string
		want    string
	}{
		{"default", "", "", "ParentBased{root:AlwaysOnSampler"},
		{"always_on", "always_on", "", "AlwaysOnSampler"},
		{"always_off", "always_off", "", "AlwaysOffSampler"},
		{"parent_off", "parentbased_always_off", "", "ParentBased{root:AlwaysOffSampler"},
		{"ratio_0.1", "traceidratio", "0.1", "TraceIDRatioBased{"},
		{"parent_ratio_0.5", "parentbased_traceidratio", "0.5", "ParentBased{root:TraceIDRatioBased"},
		{"bad_name_falls_back", "nonsense", "", "ParentBased{root:AlwaysOnSampler"},
		{"bad_ratio_uses_default", "traceidratio", "not-a-number", "TraceIDRatioBased{"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("OTEL_TRACES_SAMPLER", tc.sampler)
			t.Setenv("OTEL_TRACES_SAMPLER_ARG", tc.arg)
			got := otelSampler().Description()
			if len(got) < len(tc.want) || got[:len(tc.want)] != tc.want {
				t.Errorf("sampler=%q arg=%q: got %q, want prefix %q", tc.sampler, tc.arg, got, tc.want)
			}
		})
	}
}

// TestParseOtelHeaders exercises the env-list parser used by both
// OTEL_EXPORTER_OTLP_HEADERS and OTEL_RESOURCE_ATTRIBUTES.
func TestParseOtelHeaders(t *testing.T) {
	cases := []struct {
		in   string
		want map[string]string
	}{
		{"", nil},
		{"   ", nil},
		{"k=v", map[string]string{"k": "v"}},
		{"a=1,b=2", map[string]string{"a": "1", "b": "2"}},
		{"  a = 1 , b =2  ", map[string]string{"a": "1", "b": "2"}},
		{"=v", nil},                                   // empty key dropped
		{"k", nil},                                    // no = dropped
		{"k=v, bad, c=3", map[string]string{"k": "v", "c": "3"}},
		{"k=a=b", map[string]string{"k": "a=b"}}, // value can contain '='
	}
	for _, tc := range cases {
		got := parseOtelHeaders(tc.in)
		if len(got) != len(tc.want) {
			t.Errorf("parseOtelHeaders(%q) len=%d want %d", tc.in, len(got), len(tc.want))
			continue
		}
		for k, v := range tc.want {
			if got[k] != v {
				t.Errorf("parseOtelHeaders(%q)[%q]=%q want %q", tc.in, k, got[k], v)
			}
		}
	}
}

func TestOtelInsecure_Env(t *testing.T) {
	cases := map[string]bool{
		"":      false,
		"false": false,
		"0":     false,
		"true":  true,
		"1":     true,
		"YES":   true,
	}
	for v, want := range cases {
		t.Setenv("OTEL_EXPORTER_OTLP_INSECURE", v)
		if got := otelInsecure(); got != want {
			t.Errorf("OTEL_EXPORTER_OTLP_INSECURE=%q: got %v, want %v", v, got, want)
		}
	}
}
