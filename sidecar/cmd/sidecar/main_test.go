package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestOpenAuditWriterUsesPrivatePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not expose Unix permission bits")
	}

	dir := filepath.Join(t.TempDir(), "audit")
	path := filepath.Join(dir, "decisions.jsonl")
	_, closeWriter, err := openAuditWriter(path)
	if err != nil {
		t.Fatalf("openAuditWriter: %v", err)
	}
	if err := closeWriter(); err != nil {
		t.Fatalf("close audit writer: %v", err)
	}

	for name, target := range map[string]string{"directory": dir, "file": path} {
		info, err := os.Stat(target)
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		if got := info.Mode().Perm(); got&0o077 != 0 {
			t.Errorf("%s permissions expose group or other access: %04o", name, got)
		}
	}
}

func TestOpenAuditWriterTightensExistingFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not expose Unix permission bits")
	}

	path := filepath.Join(t.TempDir(), "decisions.jsonl")
	if err := os.WriteFile(path, []byte("existing\n"), 0o644); err != nil {
		t.Fatalf("create audit file: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("set initial permissions: %v", err)
	}

	_, closeWriter, err := openAuditWriter(path)
	if err != nil {
		t.Fatalf("openAuditWriter: %v", err)
	}
	if err := closeWriter(); err != nil {
		t.Fatalf("close audit writer: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat audit file: %v", err)
	}
	if got := info.Mode().Perm(); got&0o077 != 0 {
		t.Errorf("existing file still exposes group or other access: %04o", got)
	}
}
