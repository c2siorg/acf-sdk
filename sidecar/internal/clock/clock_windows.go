//go:build windows

package clock

import (
	"syscall"
	"time"
	"unsafe"
)

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	qpc      = kernel32.NewProc("QueryPerformanceCounter")
	freq     = queryFrequency()
)

func queryFrequency() int64 {
	var f int64
	if r, _, err := kernel32.NewProc("QueryPerformanceFrequency").Call(uintptr(unsafe.Pointer(&f))); r == 0 {
		panic("clock: QueryPerformanceFrequency failed: " + err.Error())
	}
	return f
}

// Now returns monotonic time since an arbitrary origin. Only differences
// between two Now values are meaningful.
func Now() time.Duration {
	var c int64
	qpc.Call(uintptr(unsafe.Pointer(&c))) //nolint:errcheck // cannot fail on XP and later
	// Whole seconds and the remainder separately, so ticks*1e9 cannot overflow.
	return time.Duration(c/freq)*time.Second + time.Duration(c%freq)*time.Second/time.Duration(freq)
}
