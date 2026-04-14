package transport

import (
	"context"
	"testing"
	"time"
)

// TestDrainWaitsForServe confirms Drain blocks until the accept loop has
// finished before it waits on handlers. If Drain returned before Serve
// exited, a connection accepted in that window could register a handler
// after handlers.Wait() had already returned, leaving the handler running
// while the telemetry stack was torn down.
func TestDrainWaitsForServe(t *testing.T) {
	ln, _, _ := newTestListener(t)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := ln.Drain(ctx)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("Drain returned nil while Serve was still running; expected ctx deadline")
	}
	if elapsed < 40*time.Millisecond {
		t.Errorf("Drain returned too quickly (%v); expected to block until ctx deadline", elapsed)
	}

	ln.Stop()
	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()
	if err := ln.Drain(ctx2); err != nil {
		t.Errorf("post-Stop Drain: %v", err)
	}
}

// TestStopClosesConns covers the case where a client connects and then
// hangs mid-request. Without Stop closing accepted connections the
// handler's blocking Read would hold the WaitGroup forever and Drain
// would hit its deadline even though the listener is "shut down".
func TestStopClosesConns(t *testing.T) {
	ln, _, address := newTestListener(t)

	conn := dial(t, address)
	defer conn.Close()

	// Let Serve spawn the handler and let handleConn reach the blocking
	// DecodeRequest call.
	time.Sleep(50 * time.Millisecond)

	ln.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := ln.Drain(ctx); err != nil {
		t.Fatalf("Drain did not complete after Stop closed stalled client: %v", err)
	}
}
