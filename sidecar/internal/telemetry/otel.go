// Package telemetry handles async OpenTelemetry span emission and structured
// audit logging. Spans are emitted after each enforcement decision and never
// block the enforcement path. If the OTel sink is unavailable, enforcement
// continues unaffected.
package telemetry

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

// OTelConfig controls tracer initialisation. An empty Endpoint installs the
// noop tracer.
type OTelConfig struct {
	Endpoint    string
	ServiceName string
	SampleRatio float64
	Insecure    bool
}

// ShutdownFunc flushes and releases tracer resources.
type ShutdownFunc func(context.Context) error

func noopShutdown(context.Context) error { return nil }

// Init installs a tracer provider and returns the tracer plus a shutdown
// function. A nil or empty endpoint returns a noop tracer; exporter failures
// also fall back to noop so the enforcement path is never blocked by
// telemetry setup.
func Init(ctx context.Context, cfg *OTelConfig) (trace.Tracer, ShutdownFunc, error) {
	if cfg == nil || strings.TrimSpace(cfg.Endpoint) == "" {
		return noopTracer(), noopShutdown, nil
	}

	endpoint, err := normaliseEndpoint(cfg.Endpoint)
	if err != nil {
		return noopTracer(), noopShutdown, fmt.Errorf("telemetry: bad endpoint %q: %w", cfg.Endpoint, err)
	}

	serviceName := cfg.ServiceName
	if serviceName == "" {
		serviceName = "acf-sidecar"
	}

	opts := []otlptracehttp.Option{otlptracehttp.WithEndpoint(endpoint)}
	if cfg.Insecure {
		opts = append(opts, otlptracehttp.WithInsecure())
	}

	exp, err := otlptrace.New(ctx, otlptracehttp.NewClient(opts...))
	if err != nil {
		return noopTracer(), noopShutdown, fmt.Errorf("telemetry: otlp exporter init: %w", err)
	}

	res, err := resource.New(ctx, resource.WithAttributes(semconv.ServiceName(serviceName)))
	if err != nil {
		res = resource.Default()
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp, sdktrace.WithBatchTimeout(2*time.Second)),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(clampRatio(cfg.SampleRatio)))),
	)

	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	return tp.Tracer(serviceName), tp.Shutdown, nil
}

func noopTracer() trace.Tracer {
	return noop.NewTracerProvider().Tracer("acf-sidecar")
}

// NoopTracer returns a tracer that emits nothing. Pipeline.NewWithOptions
// uses it as the default when Options.Tracer is nil.
func NoopTracer() trace.Tracer { return noopTracer() }

func clampRatio(r float64) float64 {
	if r <= 0 {
		return 0
	}
	if r >= 1 {
		return 1
	}
	return r
}

func normaliseEndpoint(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", fmt.Errorf("empty endpoint")
	}
	if !strings.Contains(s, "://") {
		return s, nil
	}
	u, err := url.Parse(s)
	if err != nil {
		return "", err
	}
	if u.Host == "" {
		return "", fmt.Errorf("endpoint has no host")
	}
	return u.Host, nil
}
