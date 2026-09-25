//go:build !windows

package clock

import "time"

var origin = time.Now()

// Now returns monotonic time since an arbitrary origin. Only differences
// between two Now values are meaningful.
func Now() time.Duration { return time.Since(origin) }
