package config

import (
	"bytes"
	"encoding/json"
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

func TestLoadResolvesRelativePolicyDirViaConfigSymlink(t *testing.T) {
	root := t.TempDir()
	realConfigDir := filepath.Join(root, "real-config")
	linkedConfigDir := filepath.Join(root, "config")
	policyDir := filepath.Join(root, "policies", "v1")

	for _, dir := range []string{realConfigDir, policyDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("MkdirAll(%q): %v", dir, err)
		}
	}

	if err := os.Symlink(realConfigDir, linkedConfigDir); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	configPath := filepath.Join(linkedConfigDir, "sidecar.yaml")
	if err := os.WriteFile(filepath.Join(realConfigDir, "sidecar.yaml"), []byte("policy_dir: ../policies/v1\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	want := filepath.Join(root, "policies", "v1")
	if cfg.PolicyDir != want {
		t.Fatalf("PolicyDir via symlink: got %q, want %q", cfg.PolicyDir, want)
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

	if err := os.WriteFile(filepath.Join(root, "sidecar", "go.mod"), []byte("module example.com/test\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(go.mod): %v", err)
	}
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatalf("Mkdir(.git): %v", err)
	}

	return root
}

func TestLoadPatterns_StructuredFormat(t *testing.T) {
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	os.MkdirAll(dataDir, 0o755)

	structured := map[string]any{
		"_version": "2.0.0",
		"patterns": []map[string]string{
			{"id": "jp-001", "category": "instruction_override", "pattern": "ignore previous instructions", "severity": "high", "owasp_llm": "LLM01"},
			{"id": "jp-002", "category": "role_escalation", "pattern": "you are now DAN", "severity": "high", "owasp_llm": "LLM01"},
		},
	}
	data, _ := json.Marshal(structured)
	os.WriteFile(filepath.Join(dataDir, "jailbreak_patterns.json"), data, 0o644)

	p, err := LoadPatterns(dir)
	if err != nil {
		t.Fatalf("LoadPatterns failed: %v", err)
	}
	if len(p.Patterns) != 2 {
		t.Fatalf("expected 2 patterns, got %d", len(p.Patterns))
	}
	if p.Patterns[0] != "ignore previous instructions" {
		t.Errorf("expected first pattern 'ignore previous instructions', got %q", p.Patterns[0])
	}
	if p.Patterns[1] != "you are now DAN" {
		t.Errorf("expected second pattern 'you are now DAN', got %q", p.Patterns[1])
	}
}

func TestLoadPatterns_FlatStringFormat(t *testing.T) {
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	os.MkdirAll(dataDir, 0o755)

	flat := map[string]any{
		"_version": "1.0.0",
		"patterns": []string{"ignore all", "jailbreak", "dan mode"},
	}
	data, _ := json.Marshal(flat)
	os.WriteFile(filepath.Join(dataDir, "jailbreak_patterns.json"), data, 0o644)

	p, err := LoadPatterns(dir)
	if err != nil {
		t.Fatalf("LoadPatterns failed: %v", err)
	}
	if len(p.Patterns) != 3 {
		t.Fatalf("expected 3 patterns, got %d", len(p.Patterns))
	}
	if p.Patterns[0] != "ignore all" {
		t.Errorf("expected 'ignore all', got %q", p.Patterns[0])
	}
}

func TestLoadPatterns_MissingFile(t *testing.T) {
	_, err := LoadPatterns(t.TempDir())
	if err == nil {
		t.Error("expected error for missing patterns file")
	}
}

func TestLoadPatterns_EmptyPatternsWarns(t *testing.T) {
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	os.MkdirAll(dataDir, 0o755)
	os.WriteFile(filepath.Join(dataDir, "jailbreak_patterns.json"), []byte(`{"_version":"2.1.0","patterns":[]}`), 0o644)

	var buf bytes.Buffer
	prevWriter := log.Writer()
	prevFlags := log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	defer log.SetOutput(prevWriter)
	defer log.SetFlags(prevFlags)

	p, err := LoadPatterns(dir)
	if err != nil {
		t.Fatalf("LoadPatterns: %v", err)
	}
	if len(p.Patterns) != 0 {
		t.Fatalf("expected 0 patterns, got %d", len(p.Patterns))
	}
	if !strings.Contains(buf.String(), "no usable jailbreak patterns") {
		t.Fatalf("expected empty-pattern warning, got %q", buf.String())
	}
}
