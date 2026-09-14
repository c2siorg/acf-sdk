package telemetry

import (
	"context"
	"testing"
	"time"
)

func TestInit_NilConfigReturnsNoop(t *testing.T) {
	tracer, shutdown, err := Init(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if tracer == nil {
		t.Fatal("nil tracer returned")
	}
	if err := shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
}

func TestInit_EmptyEndpointReturnsNoop(t *testing.T) {
	tracer, shutdown, err := Init(context.Background(), &OTelConfig{Endpoint: "   "})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if tracer == nil {
		t.Fatal("nil tracer returned")
	}

	_, span := tracer.Start(context.Background(), "probe")
	if span.SpanContext().IsValid() {
		t.Error("noop tracer should produce an invalid span context")
	}
	span.End()

	if err := shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
}

func TestInit_DeadEndpointDoesNotPanic(t *testing.T) {
	tracer, shutdown, err := Init(context.Background(), &OTelConfig{
		Endpoint:    "127.0.0.1:1",
		ServiceName: "acf-sidecar-test",
		SampleRatio: 1.0,
		Insecure:    true,
	})
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	if tracer == nil {
		t.Fatal("nil tracer")
	}

	_, span := tracer.Start(context.Background(), "probe")
	span.End()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = shutdown(ctx)
}

func TestNormaliseEndpoint(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"localhost:4318", "localhost:4318", true},
		{"http://localhost:4318", "localhost:4318", true},
		{"https://otel.example.com:4318/v1/traces", "otel.example.com:4318", true},
		{"  http://host:4318  ", "host:4318", true},
		{"", "", false},
	}
	for _, c := range cases {
		got, err := normaliseEndpoint(c.in)
		if c.ok && err != nil {
			t.Errorf("normalise(%q): unexpected err %v", c.in, err)
			continue
		}
		if !c.ok && err == nil {
			t.Errorf("normalise(%q): expected err, got %q", c.in, got)
			continue
		}
		if got != c.want {
			t.Errorf("normalise(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestClampRatio(t *testing.T) {
	cases := []struct {
		in, want float64
	}{
		{-0.5, 0},
		{0, 0},
		{0.25, 0.25},
		{1, 1},
		{1.5, 1},
	}
	for _, c := range cases {
		if got := clampRatio(c.in); got != c.want {
			t.Errorf("clampRatio(%v) = %v, want %v", c.in, got, c.want)
		}
	}
}
