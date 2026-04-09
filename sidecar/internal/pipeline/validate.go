// validate.go — Stage 1 of the pipeline.
// Validates the schema of the inbound RiskContext. The transport layer already
// verified the HMAC and nonce; validate checks the JSON payload fields are
// semantically valid before passing to normalise.
//
// Hard blocks on:
//   - unknown or missing hook_type
//   - empty provenance
//   - nil payload
//   - malformed on_tool_call payloads (must include a non-empty name)
//   - malformed on_memory payloads (must include a non-empty key and read/write op)
package pipeline

import (
	"strings"

	"github.com/acf-sdk/sidecar/pkg/riskcontext"
)

// validHookTypes is the set of hook types the pipeline accepts.
var validHookTypes = map[string]bool{
	"on_prompt":    true,
	"on_context":   true,
	"on_tool_call": true,
	"on_memory":    true,
}

// ValidateStage checks the schema of the inbound RiskContext.
type ValidateStage struct{}

func (v *ValidateStage) Name() string { return "validate" }

// Run validates rc and emits a hard block signal if any required field is
// missing or invalid. The stage does not mutate rc on success.
func (v *ValidateStage) Run(rc *riskcontext.RiskContext) (hardBlock bool) {
	if !validHookTypes[rc.HookType] {
		rc.Signals = append(rc.Signals, "validate:invalid_hook_type")
		return true
	}
	if rc.Provenance == "" {
		rc.Signals = append(rc.Signals, "validate:missing_provenance")
		return true
	}
	if rc.Payload == nil {
		rc.Signals = append(rc.Signals, "validate:nil_payload")
		return true
	}

	switch rc.HookType {
	case "on_tool_call":
		if !validToolPayload(rc.Payload) {
			rc.Signals = append(rc.Signals, "validate:tool_payload_malformed")
			return true
		}
	case "on_memory":
		if signal, ok := validateMemoryPayload(rc.Payload); ok {
			rc.Signals = append(rc.Signals, signal)
			return true
		}
	}

	return false
}

// NewValidateStage constructs a ValidateStage.
func NewValidateStage() *ValidateStage {
	return &ValidateStage{}
}

func validToolPayload(payload any) bool {
	m, ok := payload.(map[string]any)
	if !ok {
		return false
	}

	name, ok := m["name"].(string)
	return ok && strings.TrimSpace(name) != ""
}

func validateMemoryPayload(payload any) (string, bool) {
	m, ok := payload.(map[string]any)
	if !ok {
		return "validate:memory_payload_malformed", true
	}

	key, ok := m["key"].(string)
	if !ok || strings.TrimSpace(key) == "" {
		return "validate:memory_missing_key", true
	}

	op, ok := m["op"].(string)
	if !ok {
		return "validate:memory_invalid_op", true
	}

	switch strings.TrimSpace(op) {
	case "read", "write":
		return "", false
	default:
		return "validate:memory_invalid_op", true
	}
}
