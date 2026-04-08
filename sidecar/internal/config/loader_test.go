package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

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
