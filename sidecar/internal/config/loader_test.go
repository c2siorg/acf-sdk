package config

import (
	"os"
	"path/filepath"
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

	return root
}
