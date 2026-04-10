package config

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultConfigPathFindsProjectRoot(t *testing.T) {
	root := makeProjectRoot(t)
	startDir := filepath.Join(root, "sidecar", "cmd", "sidecar")
	if err := os.MkdirAll(startDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	got := DefaultConfigPath(startDir)
	want := filepath.Join(root, "config", "sidecar.yaml")
	if got != want {
		t.Fatalf("DefaultConfigPath: got %q, want %q", got, want)
	}
}

func TestResolvePolicyDirUsesConfigLocation(t *testing.T) {
	root := makeProjectRoot(t)
	configPath := filepath.Join(root, "config", "sidecar.yaml")
	if err := os.WriteFile(configPath, []byte("policy_dir: ../policies/v1\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	got := ResolvePolicyDir("../policies/v1", configPath, filepath.Join(root, "sidecar"))
	want := filepath.Join(root, "policies", "v1")
	if got != want {
		t.Fatalf("ResolvePolicyDir(config): got %q, want %q", got, want)
	}
}

func TestResolvePolicyDirUsesProjectRootWhenConfigMissing(t *testing.T) {
	root := makeProjectRoot(t)
	startDir := filepath.Join(root, "sidecar")
	if err := os.MkdirAll(startDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	got := ResolvePolicyDir("./policies/v1", filepath.Join(root, "config", "sidecar.yaml"), startDir)
	want := filepath.Join(root, "policies", "v1")
	if got != want {
		t.Fatalf("ResolvePolicyDir(default): got %q, want %q", got, want)
	}
}

func TestLoadResolvesRelativePolicyDirAgainstConfigFile(t *testing.T) {
	root := makeProjectRoot(t)
	configPath := filepath.Join(root, "config", "sidecar.yaml")
	if err := os.WriteFile(configPath, []byte("policy_dir: ../policies/v1\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	want := filepath.Join(root, "policies", "v1")
	if cfg.PolicyDir != want {
		t.Fatalf("PolicyDir: got %q, want %q", cfg.PolicyDir, want)
	}
}

func TestLoadOrDefaultLogsWhenConfigMissing(t *testing.T) {
	root := makeProjectRoot(t)
	missingPath := filepath.Join(root, "config", "sidecar.yaml")

	var buf bytes.Buffer
	prevWriter := log.Writer()
	prevFlags := log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	defer log.SetOutput(prevWriter)
	defer log.SetFlags(prevFlags)

	cfg, err := LoadOrDefault(missingPath)
	if err != nil {
		t.Fatalf("LoadOrDefault: %v", err)
	}
	if cfg == nil {
		t.Fatal("LoadOrDefault returned nil config")
	}

	msg := buf.String()
	if !strings.Contains(msg, "using built-in defaults") {
		t.Fatalf("expected fallback log, got %q", msg)
	}
}

func makeProjectRoot(t *testing.T) string {
	t.Helper()

	root := t.TempDir()
	for _, dir := range []string{
		filepath.Join(root, "config"),
		filepath.Join(root, "sidecar"),
		filepath.Join(root, "policies", "v1"),
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("MkdirAll(%q): %v", dir, err)
		}
	}

	if err := os.WriteFile(filepath.Join(root, "config", "sidecar.example.yaml"), []byte(""), 0o644); err != nil {
		t.Fatalf("WriteFile(sidecar.example.yaml): %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "sidecar", "go.mod"), []byte("module example.com/test\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(go.mod): %v", err)
	}
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatalf("Mkdir(.git): %v", err)
	}

	return root
}
