// Package clock is a high-resolution monotonic clock for per-request timing.
//
// On Windows the Go runtime's monotonic clock advances with the system timer
// interrupt, measured at 0.3–0.7 ms steps on the development machine. Sidecar
// request steps take microseconds, so time.Since reads most of them as zero.
// Now reads QueryPerformanceCounter on Windows instead (100 ns resolution,
// about 60 ns per call) and the runtime clock everywhere else.
package clock

import "time"

// Since returns the time elapsed since start, where start came from Now.
func Since(start time.Duration) time.Duration { return Now() - start }
