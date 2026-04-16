package pipeline

import (
	"testing"

	"github.com/acf-sdk/sidecar/pkg/riskcontext"
)

func validRC() *riskcontext.RiskContext {
	return &riskcontext.RiskContext{
		HookType:   "on_prompt",
		Provenance: "user",
		Payload:    "hello world",
	}
}

func TestValidate_ValidContext(t *testing.T) {
	v := NewValidateStage()
	rc := validRC()
	if hardBlock := v.Run(rc); hardBlock {
		t.Errorf("expected no hard block for valid context, got signals=%v", rc.Signals)
	}
}

func TestValidate_InvalidHookType(t *testing.T) {
	v := NewValidateStage()
	rc := validRC()
	rc.HookType = "on_unknown"
	if hardBlock := v.Run(rc); !hardBlock {
		t.Error("expected hard block for invalid hook_type")
	}
	if len(rc.Signals) == 0 {
		t.Error("expected signal to be emitted")
	}
}

func TestValidate_EmptyHookType(t *testing.T) {
	v := NewValidateStage()
	rc := validRC()
	rc.HookType = ""
	if hardBlock := v.Run(rc); !hardBlock {
		t.Error("expected hard block for empty hook_type")
	}
}

func TestValidate_MissingProvenance(t *testing.T) {
	v := NewValidateStage()
	rc := validRC()
	rc.Provenance = ""
	if hardBlock := v.Run(rc); !hardBlock {
		t.Error("expected hard block for empty provenance")
	}
	found := false
	for _, s := range rc.Signals {
		if s.Category == "validate:missing_provenance" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected validate:missing_provenance signal, got %v", rc.Signals)
	}
}

func TestValidate_NilPayload(t *testing.T) {
	v := NewValidateStage()
	rc := validRC()
	rc.Payload = nil
	if hardBlock := v.Run(rc); !hardBlock {
		t.Error("expected hard block for nil payload")
	}
}

func TestValidate_AllHookTypes(t *testing.T) {
	hooks := []string{"on_prompt", "on_context", "on_tool_call", "on_memory"}
	v := NewValidateStage()
	for _, h := range hooks {
		rc := validRC()
		rc.HookType = h
		if hardBlock := v.Run(rc); hardBlock {
			t.Errorf("hook_type %q should be valid but got hard block", h)
		}
	}
}
