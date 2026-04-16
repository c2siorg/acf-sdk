// validate.go — Stage 1 of the pipeline.
// Validates the schema of the inbound RiskContext. The transport layer already
// verified the HMAC and nonce; validate checks the JSON payload fields are
// semantically valid before passing to normalise.
//
// Hard blocks on:
//   - unknown or missing hook_type
//   - empty provenance
//   - nil payload
package pipeline

import (
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
		rc.Signals = append(rc.Signals, riskcontext.Signal{Category: "validate:invalid_hook_type"})
		return true
	}
	if rc.Provenance == "" {
		rc.Signals = append(rc.Signals, riskcontext.Signal{Category: "validate:missing_provenance"})
		return true
	}
	if rc.Payload == nil {
		rc.Signals = append(rc.Signals, riskcontext.Signal{Category: "validate:nil_payload"})
		return true
	}
	return false
}

// NewValidateStage constructs a ValidateStage.
func NewValidateStage() *ValidateStage {
	return &ValidateStage{}
}
