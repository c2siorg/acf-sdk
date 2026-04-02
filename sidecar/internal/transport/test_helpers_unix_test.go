//go:build !windows

package transport

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// testAddress returns a platform-appropriate temporary IPC address.
// On Linux/macOS this is a UDS socket file. Uses a short path to stay
// within macOS's 104-byte UDS path limit.
func testAddress(t *testing.T) string {
	t.Helper()
	// Create a short socket path in /tmp to avoid exceeding macOS UDS path limit (104 bytes)
	dir := filepath.Join("/tmp", fmt.Sprintf("acf_%d", os.Getpid()))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(dir)
	})
	return filepath.Join(dir, "test.sock")
}
