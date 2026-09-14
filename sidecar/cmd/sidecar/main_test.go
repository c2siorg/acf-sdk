package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestOpenAuditWriterUsesPrivatePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not expose Unix permission bits")
	}

	dir := filepath.Join(realAuditTempDir(t), "audit")
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

	path := filepath.Join(realAuditTempDir(t), "decisions.jsonl")
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

func TestOpenAuditWriterRejectsSymlink(t *testing.T) {
	dir := realAuditTempDir(t)
	target := filepath.Join(dir, "target.jsonl")
	path := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(target, []byte("keep\n"), 0o600); err != nil {
		t.Fatalf("create target: %v", err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	if _, _, err := openAuditWriter(path); err == nil {
		t.Fatal("openAuditWriter accepted a symlink")
	} else if strings.Contains(err.Error(), path) {
		t.Fatalf("audit error exposed configured path: %v", err)
	}
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read target: %v", err)
	}
	if string(data) != "keep\n" {
		t.Fatalf("target changed: %q", data)
	}
}

func TestOpenAuditWriterRejectsSymlinkedParent(t *testing.T) {
	dir := realAuditTempDir(t)
	realParent := filepath.Join(dir, "real-parent")
	linkedParent := filepath.Join(dir, "linked-parent")
	if err := os.Mkdir(realParent, 0o700); err != nil {
		t.Fatalf("create parent: %v", err)
	}
	if err := os.Symlink(realParent, linkedParent); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	path := filepath.Join(linkedParent, "audit.jsonl")
	if _, _, err := openAuditWriter(path); err == nil {
		t.Fatal("openAuditWriter accepted a symlinked parent")
	} else if strings.Contains(err.Error(), path) {
		t.Fatalf("audit error exposed configured path: %v", err)
	}
	if _, err := os.Stat(filepath.Join(realParent, "audit.jsonl")); !os.IsNotExist(err) {
		t.Fatalf("audit file was created through symlinked parent: %v", err)
	}
}

func realAuditTempDir(t *testing.T) string {
	t.Helper()

	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolve temporary directory: %v", err)
	}
	return root
}
