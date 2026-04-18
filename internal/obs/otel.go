package obs

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

// NoopShutdown is a Shutdown stand-in when tracing is disabled: it lets callers
// unconditionally `defer shutdown(ctx)` without nil-checking.
var NoopShutdown = func(context.Context) error { return nil }

// InitTracer wires the global OpenTelemetry tracer. When endpoint is empty,
// the global tracer stays at its default no-op so hot-path allocations remain
// on the floor. When set, an OTLP/gRPC exporter ships spans via a batch span
// processor; the returned shutdown flushes that batch.
func InitTracer(ctx context.Context, serviceName, endpoint string) (func(context.Context) error, error) {
	return InitTracerWith(ctx, serviceName, "", endpoint)
}

// InitTracerWith is InitTracer plus an explicit service.version attribute
// (typically the build-time injected main.Version). Honours the standard
// OTel env vars: OTEL_SERVICE_NAME overrides the caller-supplied
// serviceName, OTEL_RESOURCE_ATTRIBUTES adds arbitrary k=v pairs, and
// OTEL_EXPORTER_OTLP_HEADERS attaches gRPC metadata (useful for
// authenticated collectors).
func InitTracerWith(ctx context.Context, serviceName, serviceVersion, endpoint string) (func(context.Context) error, error) {
	// Always install W3C propagators so context extraction from incoming
	// HTTP/gRPC works even when the endpoint is unset: parent/child linkage
	// survives across process boundaries even under the no-op provider.
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{}, propagation.Baggage{},
	))

	if endpoint == "" {
		return NoopShutdown, nil
	}

	if n := strings.TrimSpace(os.Getenv("OTEL_SERVICE_NAME")); n != "" {
		serviceName = n
	}
	res, err := buildResource(serviceName, serviceVersion)
	if err != nil {
		return nil, err
	}

	// TLS by default — flip to plaintext only when OTEL_EXPORTER_OTLP_INSECURE
	// is explicitly truthy. Keeps the secure path the obvious one in prod.
	opts := []otlptracegrpc.Option{otlptracegrpc.WithEndpoint(endpoint)}
	if otelInsecure() {
		opts = append(opts, otlptracegrpc.WithInsecure())
	}
	if hdrs := parseOtelHeaders(os.Getenv("OTEL_EXPORTER_OTLP_HEADERS")); len(hdrs) > 0 {
		opts = append(opts, otlptracegrpc.WithHeaders(hdrs))
	}
	exp, err := otlptracegrpc.New(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("otlp exporter: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(otelSampler()),
	)
	otel.SetTracerProvider(tp)
	return tp.Shutdown, nil
}

// otelInsecure reports whether the OTLP exporter should skip TLS. Honours the
// standard OTEL_EXPORTER_OTLP_INSECURE env var — empty or unset defaults to
// *secure* (TLS required), which is the only safe production posture.
func otelInsecure() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_INSECURE")))
	return v == "1" || v == "true" || v == "yes"
}

// otelSampler reads OTEL_TRACES_SAMPLER / _ARG per the OTel spec and falls back
// to parent-based-AlwaysSample when unset (matches pre-rollout behaviour).
// Supported names:
//   - always_on / always_off
//   - parentbased_always_on / parentbased_always_off (default: parentbased_always_on)
//   - traceidratio / parentbased_traceidratio (ratio arg in OTEL_TRACES_SAMPLER_ARG)
//
// Unknown names fall back to parent-based-AlwaysSample with a stderr warning —
// we never silently break tracing.
func otelSampler() sdktrace.Sampler {
	name := strings.ToLower(strings.TrimSpace(os.Getenv("OTEL_TRACES_SAMPLER")))
	arg := strings.TrimSpace(os.Getenv("OTEL_TRACES_SAMPLER_ARG"))
	switch name {
	case "", "parentbased_always_on":
		return sdktrace.ParentBased(sdktrace.AlwaysSample())
	case "always_on":
		return sdktrace.AlwaysSample()
	case "always_off":
		return sdktrace.NeverSample()
	case "parentbased_always_off":
		return sdktrace.ParentBased(sdktrace.NeverSample())
	case "traceidratio":
		return sdktrace.TraceIDRatioBased(parseRatio(arg, 1.0))
	case "parentbased_traceidratio":
		return sdktrace.ParentBased(sdktrace.TraceIDRatioBased(parseRatio(arg, 1.0)))
	default:
		fmt.Fprintf(os.Stderr, "obs: unknown OTEL_TRACES_SAMPLER=%q, falling back to parentbased_always_on\n", name)
		return sdktrace.ParentBased(sdktrace.AlwaysSample())
	}
}

func parseRatio(s string, fallback float64) float64 {
	if s == "" {
		return fallback
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || f < 0 || f > 1 {
		fmt.Fprintf(os.Stderr, "obs: invalid OTEL_TRACES_SAMPLER_ARG=%q, using %g\n", s, fallback)
		return fallback
	}
	return f
}

// InitTracerWithProcessor is an ops/test hook: it installs the given span
// processor (e.g. a simple in-memory processor) and skips the OTLP exporter.
// Useful for exercising instrumentation without a collector.
func InitTracerWithProcessor(serviceName, serviceVersion string, sp sdktrace.SpanProcessor) (func(context.Context) error, error) {
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{}, propagation.Baggage{},
	))
	res, err := buildResource(serviceName, serviceVersion)
	if err != nil {
		return nil, err
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSpanProcessor(sp),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tp)
	return tp.Shutdown, nil
}

func buildResource(serviceName, serviceVersion string) (*resource.Resource, error) {
	attrs := make([]attribute.KeyValue, 0, 4)
	if serviceName != "" {
		attrs = append(attrs, semconv.ServiceName(serviceName))
	}
	if serviceVersion != "" {
		attrs = append(attrs, semconv.ServiceVersion(serviceVersion))
	}
	// OTEL_RESOURCE_ATTRIBUTES is a comma-separated list of k=v pairs per the
	// OTel spec; appended verbatim so operators can tag deployment/region
	// without code changes.
	for k, v := range parseOtelHeaders(os.Getenv("OTEL_RESOURCE_ATTRIBUTES")) {
		attrs = append(attrs, attribute.String(k, v))
	}
	res, err := resource.Merge(resource.Default(), resource.NewSchemaless(attrs...))
	if err != nil {
		return nil, fmt.Errorf("build resource: %w", err)
	}
	return res, nil
}

// parseOtelHeaders splits a comma-separated "k1=v1,k2=v2" list as used by the
// OTel env-var spec for both headers and resource attributes. Values are
// percent-decoded so operators can embed commas, '=', spaces, etc.; keys
// with empty names or values with bad percent-encoding are dropped so a
// typo in an env var never crashes boot.
func parseOtelHeaders(s string) map[string]string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	out := map[string]string{}
	for _, part := range strings.Split(s, ",") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		k := strings.TrimSpace(kv[0])
		v := strings.TrimSpace(kv[1])
		if k == "" {
			continue
		}
		if decoded, err := url.QueryUnescape(v); err == nil {
			v = decoded
		}
		out[k] = v
	}
	return out
}
