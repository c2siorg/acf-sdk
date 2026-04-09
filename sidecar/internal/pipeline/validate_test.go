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
		if s == "validate:missing_provenance" {
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
		switch h {
		case "on_tool_call":
			rc.Payload = map[string]any{"name": "search", "params": map[string]any{"query": "weather"}}
		case "on_memory":
			rc.Payload = map[string]any{"key": "session", "value": "hello", "op": "write"}
		}
		if hardBlock := v.Run(rc); hardBlock {
			t.Errorf("hook_type %q should be valid but got hard block", h)
		}
	}
}

func TestValidate_PromptAndContextRemainTolerant(t *testing.T) {
	v := NewValidateStage()

	cases := []struct {
		name string
		rc   *riskcontext.RiskContext
	}{
		{
			name: "prompt object payload allowed",
			rc: &riskcontext.RiskContext{
				HookType:   "on_prompt",
				Provenance: "user",
				Payload: map[string]any{
					"text":   "hello",
					"nested": map[string]any{"count": 1},
				},
			},
		},
		{
			name: "context slice payload allowed",
			rc: &riskcontext.RiskContext{
				HookType:   "on_context",
				Provenance: "rag",
				Payload: []any{
					"chunk 1",
					map[string]any{"source": "doc", "page": 3},
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if hardBlock := v.Run(tc.rc); hardBlock {
				t.Fatalf("expected tolerant validation for %s, got signals=%v", tc.rc.HookType, tc.rc.Signals)
			}
		})
	}
}

func TestValidate_ToolPayloadMalformed(t *testing.T) {
	v := NewValidateStage()
	rc := validRC()
	rc.HookType = "on_tool_call"
	rc.Payload = "shell"

	if hardBlock := v.Run(rc); !hardBlock {
		t.Fatal("expected hard block for malformed tool payload")
	}
	if rc.Signals[len(rc.Signals)-1] != "validate:tool_payload_malformed" {
		t.Fatalf("expected validate:tool_payload_malformed, got %v", rc.Signals)
	}
}

func TestValidate_ToolPayloadMissingName(t *testing.T) {
	v := NewValidateStage()
	rc := validRC()
	rc.HookType = "on_tool_call"
	rc.Payload = map[string]any{"params": map[string]any{"cmd": "ls"}}

	if hardBlock := v.Run(rc); !hardBlock {
		t.Fatal("expected hard block for tool payload without a name")
	}
	if rc.Signals[len(rc.Signals)-1] != "validate:tool_payload_malformed" {
		t.Fatalf("expected validate:tool_payload_malformed, got %v", rc.Signals)
	}
}

func TestValidate_MemoryPayloadMalformed(t *testing.T) {
	v := NewValidateStage()
	rc := validRC()
	rc.HookType = "on_memory"
	rc.Payload = "secret"

	if hardBlock := v.Run(rc); !hardBlock {
		t.Fatal("expected hard block for malformed memory payload")
	}
	if rc.Signals[len(rc.Signals)-1] != "validate:memory_payload_malformed" {
		t.Fatalf("expected validate:memory_payload_malformed, got %v", rc.Signals)
	}
}

func TestValidate_MemoryMissingKey(t *testing.T) {
	v := NewValidateStage()
	rc := validRC()
	rc.HookType = "on_memory"
	rc.Payload = map[string]any{"value": "secret", "op": "write"}

	if hardBlock := v.Run(rc); !hardBlock {
		t.Fatal("expected hard block for missing memory key")
	}
	if rc.Signals[len(rc.Signals)-1] != "validate:memory_missing_key" {
		t.Fatalf("expected validate:memory_missing_key, got %v", rc.Signals)
	}
}

func TestValidate_MemoryInvalidOp(t *testing.T) {
	v := NewValidateStage()
	rc := validRC()
	rc.HookType = "on_memory"
	rc.Payload = map[string]any{"key": "session", "value": "secret", "op": "delete"}

	if hardBlock := v.Run(rc); !hardBlock {
		t.Fatal("expected hard block for invalid memory op")
	}
	if rc.Signals[len(rc.Signals)-1] != "validate:memory_invalid_op" {
		t.Fatalf("expected validate:memory_invalid_op, got %v", rc.Signals)
	}
}

func TestValidate_MemoryReadWriteAllowed(t *testing.T) {
	ops := []string{"read", "write"}
	v := NewValidateStage()

	for _, op := range ops {
		rc := validRC()
		rc.HookType = "on_memory"
		rc.Payload = map[string]any{"key": "session", "value": "secret", "op": op}

		if hardBlock := v.Run(rc); hardBlock {
			t.Errorf("memory op %q should be valid but got signals=%v", op, rc.Signals)
		}
	}
}
