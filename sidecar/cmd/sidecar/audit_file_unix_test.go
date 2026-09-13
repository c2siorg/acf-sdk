//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestCanonicalizeDarwinAuditPath(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Darwin-only path aliases")
	}

	tests := []struct {
		name string
		path string
		want string
	}{
		{name: "tmp", path: "/tmp/acf/audit.jsonl", want: "/private/tmp/acf/audit.jsonl"},
		{name: "var", path: "/var/log/acf/audit.log", want: "/private/var/log/acf/audit.log"},
		{name: "tmp prefix boundary", path: "/tmp-old/acf/audit.jsonl", want: "/tmp-old/acf/audit.jsonl"},
		{name: "private path", path: "/private/var/log/acf/audit.log", want: "/private/var/log/acf/audit.log"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := canonicalizeDarwinAuditPath(test.path); got != test.want {
				t.Fatalf("canonicalizeDarwinAuditPath(%q) = %q, want %q", test.path, got, test.want)
			}
		})
	}
}

func TestOpenAuditFileUsesDarwinRootAliases(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Darwin-only path aliases")
	}

	dir := t.TempDir()
	if !strings.HasPrefix(dir, "/var/") {
		t.Skip("temporary directory is not under /var")
	}
	path := filepath.Join("/var", strings.TrimPrefix(dir, "/var"), "nested", "audit.jsonl")
	file, err := openAuditFile(path)
	if err != nil {
		t.Fatalf("openAuditFile: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close audit file: %v", err)
	}

	directoryInfo, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("stat audit directory: %v", err)
	}
	if got := directoryInfo.Mode().Perm(); got&0o077 != 0 {
		t.Errorf("audit directory permissions expose group or other access: %04o", got)
	}

	fileInfo, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat audit file: %v", err)
	}
	if got := fileInfo.Mode().Perm(); got&0o077 != 0 {
		t.Errorf("audit file permissions expose group or other access: %04o", got)
	}
}

func TestOpenAuditFileRejectsUntrustedSymlinkedParent(t *testing.T) {
	dir := t.TempDir()
	realParent := filepath.Join(dir, "real-parent")
	linkedParent := filepath.Join(dir, "linked-parent")
	if err := os.Mkdir(realParent, 0o700); err != nil {
		t.Fatalf("create parent: %v", err)
	}
	if err := os.Symlink(realParent, linkedParent); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	path := filepath.Join(linkedParent, "audit.jsonl")
	if _, err := openAuditFile(path); err == nil {
		t.Fatal("openAuditFile accepted a symlinked parent")
	} else if strings.Contains(err.Error(), path) {
		t.Fatalf("audit error exposed configured path: %v", err)
	}
	if _, err := os.Stat(filepath.Join(realParent, "audit.jsonl")); !os.IsNotExist(err) {
		t.Fatalf("audit file was created through symlinked parent: %v", err)
	}
}

func TestOpenAuditFileRejectsExistingFIFOWithoutBlocking(t *testing.T) {
	path := filepath.Join(realAuditTempDir(t), "audit.fifo")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Skipf("FIFO unavailable: %v", err)
	}

	result := make(chan error, 1)
	go func() {
		_, err := openAuditFile(path)
		result <- err
	}()

	select {
	case err := <-result:
		if err == nil {
			t.Fatal("openAuditFile accepted an existing FIFO")
		}
		if strings.Contains(err.Error(), path) {
			t.Fatalf("audit error exposed configured path: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("openAuditFile blocked on an existing FIFO")
	}
}

func TestOpenAuditFileRejectsUnsafeExistingFileMode(t *testing.T) {
	path := filepath.Join(realAuditTempDir(t), "audit.jsonl")
	if err := os.WriteFile(path, []byte("existing\n"), 0o660); err != nil {
		t.Fatalf("create audit file: %v", err)
	}
	if err := os.Chmod(path, 0o660); err != nil {
		t.Fatalf("set audit file permissions: %v", err)
	}

	if _, err := openAuditFile(path); err == nil {
		t.Fatal("openAuditFile accepted an existing group-writable file")
	} else if strings.Contains(err.Error(), path) {
		t.Fatalf("audit error exposed configured path: %v", err)
	}
}

func TestOpenAuditFileRejectsExistingFileWithUntrustedOwner(t *testing.T) {
	if unix.Geteuid() != 0 {
		t.Skip("changing ownership requires root")
	}

	path := filepath.Join(realAuditTempDir(t), "audit.jsonl")
	if err := os.WriteFile(path, []byte("existing\n"), 0o600); err != nil {
		t.Fatalf("create audit file: %v", err)
	}
	if err := os.Chown(path, 65534, -1); err != nil {
		t.Skipf("changing ownership unavailable: %v", err)
	}

	if _, err := openAuditFile(path); err == nil {
		t.Fatal("openAuditFile accepted an existing file with an untrusted owner")
	} else if strings.Contains(err.Error(), path) {
		t.Fatalf("audit error exposed configured path: %v", err)
	}
}

func TestOpenAuditFileRejectsUnsafeExistingParentMode(t *testing.T) {
	root := realAuditTempDir(t)
	parent := filepath.Join(root, "unsafe-parent")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatalf("create parent directory: %v", err)
	}
	if err := os.Chmod(parent, 0o777); err != nil {
		t.Fatalf("set parent permissions: %v", err)
	}

	path := filepath.Join(parent, "audit.jsonl")
	if _, err := openAuditFile(path); err == nil {
		t.Fatal("openAuditFile accepted a group-writable parent directory")
	} else if strings.Contains(err.Error(), path) {
		t.Fatalf("audit error exposed configured path: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("audit file was created below an unsafe parent: %v", err)
	}
}

func TestOpenAuditFileAllowsStickyTemporaryParent(t *testing.T) {
	parent := filepath.Join(realAuditTempDir(t), "sticky-parent")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatalf("create parent directory: %v", err)
	}
	if err := os.Chmod(parent, os.ModeSticky|0o777); err != nil {
		t.Fatalf("set sticky parent permissions: %v", err)
	}

	file, err := openAuditFile(filepath.Join(parent, "audit.jsonl"))
	if err != nil {
		t.Fatalf("openAuditFile rejected sticky temporary parent: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close audit file: %v", err)
	}
}
