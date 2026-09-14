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

func TestLoadTelemetryConfig(t *testing.T) {
	root := makeProjectRoot(t)
	configPath := filepath.Join(root, "config", "sidecar.yaml")
	raw := `telemetry:
  otel_endpoint: http://collector:4318
  service_name: acf-test
  sample_ratio: 0.25
  insecure: true
  audit_path: /tmp/acf-audit.jsonl
  audit_buffer: 256
  policy_version: test-v1
`
	if err := os.WriteFile(configPath, []byte(raw), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	got := cfg.Telemetry
	if got.OTelEndpoint != "http://collector:4318" || got.ServiceName != "acf-test" ||
		got.SampleRatio != 0.25 || !got.Insecure || got.AuditPath != "/tmp/acf-audit.jsonl" ||
		got.AuditBuffer != 256 || got.PolicyVersion != "test-v1" {
		t.Fatalf("Telemetry: got %+v", got)
	}
}

func TestLoadResolvesRelativeAuditPathAgainstConfigFile(t *testing.T) {
	root := makeProjectRoot(t)
	configPath := filepath.Join(root, "config", "sidecar.yaml")
	if err := os.WriteFile(configPath, []byte("telemetry:\n  audit_path: audit/decisions.jsonl\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	canonicalConfigDir, err := filepath.EvalSymlinks(filepath.Dir(configPath))
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	want := filepath.Join(canonicalConfigDir, "audit", "decisions.jsonl")
	if cfg.Telemetry.AuditPath != want {
		t.Fatalf("AuditPath: got %q, want %q", cfg.Telemetry.AuditPath, want)
	}
}

func TestLoadResolvesRelativeAuditPathViaConfigSymlink(t *testing.T) {
	root := t.TempDir()
	realConfigDir := filepath.Join(root, "real-config")
	linkedConfigDir := filepath.Join(root, "config")
	if err := os.MkdirAll(realConfigDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(%q): %v", realConfigDir, err)
	}
	if err := os.Symlink(realConfigDir, linkedConfigDir); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	configPath := filepath.Join(linkedConfigDir, "sidecar.yaml")
	if err := os.WriteFile(filepath.Join(realConfigDir, "sidecar.yaml"), []byte("telemetry:\n  audit_path: audit/decisions.jsonl\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	canonicalConfigDir, err := filepath.EvalSymlinks(realConfigDir)
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	want := filepath.Join(canonicalConfigDir, "audit", "decisions.jsonl")
	if cfg.Telemetry.AuditPath != want {
		t.Fatalf("AuditPath via symlink: got %q, want %q", cfg.Telemetry.AuditPath, want)
	}
}

func TestLoadDoesNotCanonicalizeRelativeAuditPath(t *testing.T) {
	root := t.TempDir()
	configDir := filepath.Join(root, "config")
	auditTargetDir := filepath.Join(root, "audit-target")
	for _, dir := range []string{configDir, auditTargetDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("MkdirAll(%q): %v", dir, err)
		}
	}

	auditLink := filepath.Join(configDir, "audit-link")
	if err := os.Symlink(auditTargetDir, auditLink); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	configPath := filepath.Join(configDir, "sidecar.yaml")
	if err := os.WriteFile(configPath, []byte("telemetry:\n  audit_path: audit-link/decisions.jsonl\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	canonicalConfigDir, err := filepath.EvalSymlinks(configDir)
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	want := filepath.Join(canonicalConfigDir, "audit-link", "decisions.jsonl")
	if cfg.Telemetry.AuditPath != want {
		t.Fatalf("AuditPath: got %q, want %q", cfg.Telemetry.AuditPath, want)
	}
}

func TestResolveAuditPathReportsConfigDirectoryError(t *testing.T) {
	baseDir := filepath.Join(t.TempDir(), "missing")
	_, err := resolveAuditPath(baseDir, "audit/decisions.jsonl")
	if err == nil {
		t.Fatal("resolveAuditPath returned nil error")
	}
	if !strings.Contains(err.Error(), "cannot canonicalize config directory") {
		t.Fatalf("resolveAuditPath error: got %q", err)
	}
}

func TestLoadPreservesStdoutAuditPaths(t *testing.T) {
	for _, path := range []string{"", "-"} {
		t.Run(path, func(t *testing.T) {
			configPath := filepath.Join(t.TempDir(), "sidecar.yaml")
			raw := "telemetry:\n  audit_path: \"" + path + "\"\n"
			if err := os.WriteFile(configPath, []byte(raw), 0o644); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}

			cfg, err := Load(configPath)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if cfg.Telemetry.AuditPath != path {
				t.Fatalf("AuditPath: got %q, want %q", cfg.Telemetry.AuditPath, path)
			}
		})
	}
}

func TestLoadRejectsInvalidTelemetrySampleRatio(t *testing.T) {
	tests := map[string]string{
		"negative":          "-0.1",
		"above 1":           "1.1",
		"not a number":      ".nan",
		"positive infinity": ".inf",
		"negative infinity": "-.inf",
	}

	for name, value := range tests {
		t.Run(name, func(t *testing.T) {
			configPath := filepath.Join(t.TempDir(), "sidecar.yaml")
			raw := "telemetry:\n  sample_ratio: " + value + "\n"
			if err := os.WriteFile(configPath, []byte(raw), 0o644); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}

			_, err := Load(configPath)
			if err == nil || !strings.Contains(err.Error(), "telemetry.sample_ratio") {
				t.Fatalf("Load(sample_ratio=%s): got %v, want validation error", value, err)
			}
		})
	}
}

func TestLoadRejectsInvalidEnforcementNumbers(t *testing.T) {
	tests := []struct {
		name  string
		raw   string
		field string
	}{
		{
			name:  "block_score negative",
			raw:   "thresholds:\n  block_score: -0.1\n",
			field: "thresholds.block_score",
		},
		{
			name:  "block_score above 1",
			raw:   "thresholds:\n  block_score: 1.1\n",
			field: "thresholds.block_score",
		},
		{
			name:  "block_score NaN",
			raw:   "thresholds:\n  block_score: .nan\n",
			field: "thresholds.block_score",
		},
		{
			name:  "block_score positive infinity",
			raw:   "thresholds:\n  block_score: .inf\n",
			field: "thresholds.block_score",
		},
		{
			name:  "block_score negative infinity",
			raw:   "thresholds:\n  block_score: -.inf\n",
			field: "thresholds.block_score",
		},
		{
			name:  "sanitise_score negative",
			raw:   "thresholds:\n  sanitise_score: -0.1\n",
			field: "thresholds.sanitise_score",
		},
		{
			name:  "sanitise_score above 1",
			raw:   "thresholds:\n  sanitise_score: 1.1\n",
			field: "thresholds.sanitise_score",
		},
		{
			name:  "sanitise_score NaN",
			raw:   "thresholds:\n  sanitise_score: .nan\n",
			field: "thresholds.sanitise_score",
		},
		{
			name:  "sanitise_score positive infinity",
			raw:   "thresholds:\n  sanitise_score: .inf\n",
			field: "thresholds.sanitise_score",
		},
		{
			name:  "sanitise_score negative infinity",
			raw:   "thresholds:\n  sanitise_score: -.inf\n",
			field: "thresholds.sanitise_score",
		},
		{
			name:  "trust_weights negative",
			raw:   "trust_weights:\n  source: -0.1\n",
			field: "trust_weights.source",
		},
		{
			name:  "trust_weights above 1",
			raw:   "trust_weights:\n  source: 1.1\n",
			field: "trust_weights.source",
		},
		{
			name:  "trust_weights NaN",
			raw:   "trust_weights:\n  source: .nan\n",
			field: "trust_weights.source",
		},
		{
			name:  "trust_weights positive infinity",
			raw:   "trust_weights:\n  source: .inf\n",
			field: "trust_weights.source",
		},
		{
			name:  "trust_weights negative infinity",
			raw:   "trust_weights:\n  source: -.inf\n",
			field: "trust_weights.source",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configPath := filepath.Join(t.TempDir(), "sidecar.yaml")
			if err := os.WriteFile(configPath, []byte(tt.raw), 0o644); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}

			_, err := Load(configPath)
			if err == nil || !strings.Contains(err.Error(), tt.field) {
				t.Fatalf("Load(%s): got %v, want validation error for %s", tt.name, err, tt.field)
			}
		})
	}
}

func TestLoadAcceptsEnforcementBoundaryValues(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		block    float64
		sanitise float64
		trust    float64
		sample   float64
	}{
		{
			name: "lower boundaries",
			raw: `thresholds:
  block_score: 0
  sanitise_score: 0
trust_weights:
  source: 0
telemetry:
  sample_ratio: 0
`,
			block:    0,
			sanitise: 0,
			trust:    0,
			sample:   0,
		},
		{
			name: "upper boundaries",
			raw: `thresholds:
  block_score: 1
  sanitise_score: 1
trust_weights:
  source: 1
telemetry:
  sample_ratio: 1
`,
			block:    1,
			sanitise: 1,
			trust:    1,
			sample:   1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configPath := filepath.Join(t.TempDir(), "sidecar.yaml")
			if err := os.WriteFile(configPath, []byte(tt.raw), 0o644); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}

			cfg, err := Load(configPath)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if cfg.Thresholds.BlockScore != tt.block || cfg.Thresholds.SanitiseScore != tt.sanitise ||
				cfg.TrustWeights["source"] != tt.trust || cfg.Telemetry.SampleRatio != tt.sample {
				t.Fatalf("enforcement boundaries: got thresholds=%+v trust=%v sample=%v", cfg.Thresholds, cfg.TrustWeights["source"], cfg.Telemetry.SampleRatio)
			}
		})
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
	if len(p.Entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(p.Entries))
	}
	if p.Entries[0].ID != "jp-001" || p.Entries[0].Category != "instruction_override" {
		t.Errorf("expected entry jp-001/instruction_override, got %s/%s", p.Entries[0].ID, p.Entries[0].Category)
	}
	if p.Entries[1].Category != "role_escalation" {
		t.Errorf("expected entry category role_escalation, got %q", p.Entries[1].Category)
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
	if len(p.Entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(p.Entries))
	}
	if p.Entries[0].Pattern != "ignore all" || p.Entries[0].Category != "" {
		t.Errorf("flat entries should carry pattern only, got %+v", p.Entries[0])
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
