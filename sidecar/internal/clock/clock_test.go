package clock

import (
	"testing"
	"time"
)

func TestNow_IsMonotonic(t *testing.T) {
	prev := Now()
	for i := 0; i < 100_000; i++ {
		now := Now()
		if now < prev {
			t.Fatalf("clock went backwards: %v then %v", prev, now)
		}
		prev = now
	}
}

func TestNow_TracksWallTime(t *testing.T) {
	start := Now()
	time.Sleep(20 * time.Millisecond)
	if d := Since(start); d < 15*time.Millisecond || d > time.Second {
		t.Errorf("20ms sleep measured as %v", d)
	}
}

func TestNow_ResolvesMicrosecondWork(t *testing.T) {
	// A loop of a few microseconds must not read as zero. With the runtime's
	// coarse Windows clock almost every iteration did.
	zero := 0
	for i := 0; i < 200; i++ {
		start := Now()
		x := 0
		for j := 0; j < 20_000; j++ {
			x += j
		}
		_ = x
		if Since(start) == 0 {
			zero++
		}
	}
	if zero > 20 {
		t.Errorf("%d/200 microsecond loops measured as zero", zero)
	}
}
