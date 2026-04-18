package obs

import (
	"context"
	"fmt"

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
// (typically the build-time injected main.Version).
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

	res, err := buildResource(serviceName, serviceVersion)
	if err != nil {
		return nil, err
	}

	exp, err := otlptracegrpc.New(ctx,
		otlptracegrpc.WithEndpoint(endpoint),
		otlptracegrpc.WithInsecure(),
	)
	if err != nil {
		return nil, fmt.Errorf("otlp exporter: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tp)
	return tp.Shutdown, nil
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
	attrs := make([]attribute.KeyValue, 0, 2)
	if serviceName != "" {
		attrs = append(attrs, semconv.ServiceName(serviceName))
	}
	if serviceVersion != "" {
		attrs = append(attrs, semconv.ServiceVersion(serviceVersion))
	}
	res, err := resource.Merge(resource.Default(), resource.NewSchemaless(attrs...))
	if err != nil {
		return nil, fmt.Errorf("build resource: %w", err)
	}
	return res, nil
}
