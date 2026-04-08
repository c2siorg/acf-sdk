// Package config loads and validates sidecar configuration from a YAML file.
// The config is read once at startup; hot-reload of policy data files is
// handled separately by the policy engine in Phase 3.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"

	"gopkg.in/yaml.v3"
)

// Config is the top-level sidecar configuration.
type Config struct {
	// SocketPath is the IPC address (UDS path or Windows named pipe).
	// Overridden by ACF_SOCKET_PATH environment variable.
	SocketPath string `yaml:"socket_path"`

	// PolicyDir is the directory containing Rego files and data/.
	PolicyDir string `yaml:"policy_dir"`

	// LogLevel controls log verbosity: debug | info | warn | error.
	LogLevel string `yaml:"log_level"`

	// Pipeline controls pipeline behaviour.
	Pipeline PipelineConfig `yaml:"pipeline"`

	// Thresholds defines score cutoffs for BLOCK and SANITISE decisions.
	Thresholds ThresholdConfig `yaml:"thresholds"`

	// TrustWeights maps provenance labels to a multiplier applied to the raw score.
	TrustWeights map[string]float64 `yaml:"trust_weights"`

	// ToolAllowlist is the set of permitted tool names for on_tool_call.
	// Empty means all tools are permitted.
	ToolAllowlist []string `yaml:"tool_allowlist"`

	// MemoryKeyAllowlist is the set of permitted memory keys for on_memory.
	// Empty means all keys are permitted.
	MemoryKeyAllowlist []string `yaml:"memory_key_allowlist"`

	// SignalWeights maps signal names to their contribution to the risk score.
	SignalWeights map[string]float64 `yaml:"signal_weights"`
}

// PipelineConfig controls pipeline execution behaviour.
type PipelineConfig struct {
	// StrictMode enables short-circuit on the first hard block signal.
	// When false, all stages run regardless and the full signal set is collected.
	// Default: true.
	StrictMode bool `yaml:"strict_mode"`
}

// ThresholdConfig defines score cutoffs for pipeline decisions.
type ThresholdConfig struct {
	// BlockScore: score >= this value → BLOCK (before OPA in Phase 3).
	BlockScore float64 `yaml:"block_score"`
	// SanitiseScore: score >= this value → SANITISE (used by OPA in Phase 3).
	SanitiseScore float64 `yaml:"sanitise_score"`
}

// Load reads and parses the YAML config file at path.
// Returns an error if the file is missing, unparseable, or fails validation.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: cannot read %s: %w", path, err)
	}

	cfg := defaults()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("config: cannot parse %s: %w", path, err)
	}

	if err := validate(cfg); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}

	return cfg, nil
}

// LoadOrDefault attempts to load from path. If the file does not exist,
// it returns a default config without error. Any other read error is fatal.
func LoadOrDefault(path string) (*Config, error) {
	cfg, err := Load(path)
	if errors.Is(err, os.ErrNotExist) {
		return defaults(), nil
	}
	return cfg, err
}

// ToolAllowed reports whether name is in the tool allowlist.
// Returns true if the allowlist is empty (allow all).
func (c *Config) ToolAllowed(name string) bool {
	if len(c.ToolAllowlist) == 0 {
		return true
	}
	for _, t := range c.ToolAllowlist {
		if t == name {
			return true
		}
	}
	return false
}

// MemoryKeyAllowed reports whether key is in the memory key allowlist.
// Returns true if the allowlist is empty (allow all).
func (c *Config) MemoryKeyAllowed(key string) bool {
	if len(c.MemoryKeyAllowlist) == 0 {
		return true
	}
	for _, k := range c.MemoryKeyAllowlist {
		if k == key {
			return true
		}
	}
	return false
}

// ProvenanceWeight returns the trust multiplier for the given provenance label.
// Returns 1.0 if the label is not in the map.
func (c *Config) ProvenanceWeight(provenance string) float64 {
	if w, ok := c.TrustWeights[provenance]; ok {
		return w
	}
	return 1.0
}

// defaults returns a Config with safe default values.
func defaults() *Config {
	return &Config{
		SocketPath: "",
		PolicyDir:  "./policies/v1",
		LogLevel:   "info",
		Pipeline: PipelineConfig{
			StrictMode: true,
		},
		Thresholds: ThresholdConfig{
			BlockScore:    0.85,
			SanitiseScore: 0.50,
		},
		TrustWeights: map[string]float64{
			"user":        1.0,
			"user_input":  1.0,
			"tool_output": 0.8,
			"rag_chunk":   0.7,
			"rag":         0.7,
			"memory_read": 0.6,
			"memory":      0.6,
		},
		SignalWeights: map[string]float64{
			"jailbreak_pattern":    0.9,
			"instruction_override": 0.85,
			"role_escalation":      0.8,
			"shell_metachar":       0.75,
			"path_traversal":       0.75,
			"embedded_instruction": 0.65,
			"structural_anomaly":   0.40,
			"hmac_invalid":         1.0,
		},
		ToolAllowlist:      []string{},
		MemoryKeyAllowlist: []string{},
	}
}

func validate(c *Config) error {
	if c.Thresholds.BlockScore < 0 || c.Thresholds.BlockScore > 1 {
		return errors.New("thresholds.block_score must be between 0.0 and 1.0")
	}
	if c.Thresholds.SanitiseScore < 0 || c.Thresholds.SanitiseScore > 1 {
		return errors.New("thresholds.sanitise_score must be between 0.0 and 1.0")
	}
	if c.Thresholds.SanitiseScore > c.Thresholds.BlockScore {
		return errors.New("thresholds.sanitise_score must be <= thresholds.block_score")
	}
	return nil
}

// Patterns holds the parsed jailbreak patterns for the scanner.
type Patterns struct {
	Version  string
	Patterns []string
}

// LoadPatterns reads and parses jailbreak_patterns.json from policyDir.
// Supports both structured entries (objects with a "pattern" field) and
// flat string arrays for backward compatibility.
func LoadPatterns(policyDir string) (*Patterns, error) {
	path := policyDir + "/data/jailbreak_patterns.json"
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: cannot read patterns file %s: %w", path, err)
	}

	var raw struct {
		Version  string            `json:"_version"`
		Patterns []json.RawMessage `json:"patterns"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("config: cannot parse patterns file: %w", err)
	}

	strs := make([]string, 0, len(raw.Patterns))
	skipped := 0
	for i, p := range raw.Patterns {
		// Try structured entry first ({"pattern": "...", ...})
		var entry struct {
			Pattern string `json:"pattern"`
		}
		if err := json.Unmarshal(p, &entry); err == nil && entry.Pattern != "" {
			strs = append(strs, entry.Pattern)
			continue
		}
		// Fall back to plain string
		var s string
		if err := json.Unmarshal(p, &s); err == nil && s != "" {
			strs = append(strs, s)
			continue
		}
		log.Printf("config: warning: skipping unparseable pattern at index %d in %s", i, path)
		skipped++
	}

	if skipped > 0 {
		log.Printf("config: warning: %d of %d pattern entries could not be parsed", skipped, len(raw.Patterns))
	}

	return &Patterns{Version: raw.Version, Patterns: strs}, nil
}
