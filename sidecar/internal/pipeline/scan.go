// scan.go — Stage 3 of the pipeline.
// Runs on rc.CanonicalText produced by the normalise stage:
//   - Aho-Corasick multi-pattern lexical scan against jailbreak_patterns.json
//   - Tool allowlist check (on_tool_call)
//   - Memory key allowlist check (on_memory)
//
// Emits named signals into rc.Signals. Hard-blocks only when a pattern match
// produces a signal whose weight reaches the block threshold — that is left to
// the aggregate stage. Scan itself never returns hardBlock=true; it is a pure
// signal emitter. The aggregate stage decides if the combined score is blocking.
package pipeline

import (
	"strings"

	"github.com/cloudflare/ahocorasick"

	"github.com/acf-sdk/sidecar/internal/config"
	"github.com/acf-sdk/sidecar/pkg/riskcontext"
)

// shellMetachars are characters that allow command chaining or injection in shells.
var shellMetachars = []string{";", "&&", "||", "|", "`", "$(", "${", " & ", ">", "<"}

// pathTraversalPatterns are sequences used to escape a directory boundary.
var pathTraversalPatterns = []string{"../", "..\\", "/..", "\\.."}

// ScanStage runs lexical pattern matching and allowlist checks.
type ScanStage struct {
	cfg      *config.Config
	matcher  *ahocorasick.Matcher
	patterns []string // parallel to matcher dictionary
}

// NewScanStage constructs a ScanStage. patterns is the list of strings loaded
// from jailbreak_patterns.json. An empty pattern list means lexical scan is a
// no-op (no signals emitted from pattern matching).
func NewScanStage(cfg *config.Config, patterns []string) *ScanStage {
	s := &ScanStage{cfg: cfg, patterns: patterns}
	if len(patterns) > 0 {
		dict := make([][]byte, len(patterns))
		for i, p := range patterns {
			dict[i] = []byte(strings.ToLower(p))
		}
		s.matcher = ahocorasick.NewMatcher(dict)
	}
	return s
}

func (s *ScanStage) Name() string { return "scan" }

// Run scans rc.CanonicalText and appends signals to rc.Signals.
// Always returns hardBlock=false — signal weighting and block decisions
// are the aggregate stage's responsibility.
func (s *ScanStage) Run(rc *riskcontext.RiskContext) (hardBlock bool) {
	text := strings.ToLower(rc.CanonicalText)

	// 1. Aho-Corasick lexical scan.
	if s.matcher != nil && len(text) > 0 {
		hits := s.matcher.Match([]byte(text))
		if len(hits) > 0 {
			rc.Signals = append(rc.Signals, riskcontext.Signal{Category: "jailbreak_pattern"})
		}
	}

	// 2. Hook-specific allowlist and integrity checks.
	switch rc.HookType {
	case "on_tool_call":
		s.checkToolAllowlist(rc)
		s.checkToolDangerousParams(rc)
	case "on_memory":
		s.checkMemoryAllowlist(rc)
	}

	return false
}

// checkToolAllowlist emits a signal if the tool name is not in the allowlist.
func (s *ScanStage) checkToolAllowlist(rc *riskcontext.RiskContext) {
	toolName := ""
	if m, ok := rc.Payload.(map[string]any); ok {
		if n, ok := m["name"].(string); ok {
			toolName = n
		}
	}
	if toolName != "" && !s.cfg.ToolAllowed(toolName) {
		rc.Signals = append(rc.Signals, riskcontext.Signal{Category: "tool:not_allowed"})
	}
}

// checkToolDangerousParams scans all string values in the tool params for shell
// metacharacters and path traversal sequences, emitting signals independently.
func (s *ScanStage) checkToolDangerousParams(rc *riskcontext.RiskContext) {
	m, ok := rc.Payload.(map[string]any)
	if !ok {
		return
	}
	params, ok := m["params"].(map[string]any)
	if !ok {
		return
	}

	combined := flattenStrings(params)
	lower := strings.ToLower(combined)

	for _, seq := range shellMetachars {
		if strings.Contains(lower, seq) {
			rc.Signals = append(rc.Signals, riskcontext.Signal{Category: "shell_metacharacter"})
			break
		}
	}

	for _, seq := range pathTraversalPatterns {
		if strings.Contains(lower, seq) {
			rc.Signals = append(rc.Signals, riskcontext.Signal{Category: "path_traversal"})
			break
		}
	}
}

// flattenStrings recursively collects all string leaf values from a map.
func flattenStrings(m map[string]any) string {
	var parts []string
	for _, v := range m {
		switch val := v.(type) {
		case string:
			parts = append(parts, val)
		case map[string]any:
			parts = append(parts, flattenStrings(val))
		}
	}
	return strings.Join(parts, " ")
}

// checkMemoryAllowlist emits a signal if the memory key is not in the allowlist.
func (s *ScanStage) checkMemoryAllowlist(rc *riskcontext.RiskContext) {
	key := ""
	if m, ok := rc.Payload.(map[string]any); ok {
		if k, ok := m["key"].(string); ok {
			key = k
		}
	}
	if key != "" && !s.cfg.MemoryKeyAllowed(key) {
		rc.Signals = append(rc.Signals, riskcontext.Signal{Category: "memory:key_not_allowed"})
	}
}
