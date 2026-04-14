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

	// Serve is still running. Drain must block on serveDone and hit the
	// context deadline rather than returning immediately off an empty
	// handler WaitGroup.
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

	// Now stop the listener and confirm Drain unblocks cleanly with a
	// generous deadline.
	ln.Stop()
	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()
	if err := ln.Drain(ctx2); err != nil {
		t.Errorf("post-Stop Drain: %v", err)
	}
}
