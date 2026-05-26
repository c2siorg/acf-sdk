package pipeline

import (
	"strings"
	"testing"

	"github.com/acf-sdk/sidecar/pkg/riskcontext"
)

func TestNormalise_PlainString(t *testing.T) {
	n := NewNormaliseStage()
	rc := &riskcontext.RiskContext{Payload: "hello world"}
	n.Run(rc)
	if rc.CanonicalText == "" {
		t.Error("expected CanonicalText to be populated")
	}
}

func TestNormalise_NeverHardBlocks(t *testing.T) {
	n := NewNormaliseStage()
	rc := &riskcontext.RiskContext{Payload: "anything"}
	if hardBlock := n.Run(rc); hardBlock {
		t.Error("normalise should never return hardBlock=true")
	}
}

func TestNormalise_URLDecode(t *testing.T) {
	n := NewNormaliseStage()
	rc := &riskcontext.RiskContext{Payload: "ignore%20me"}
	n.Run(rc)
	if !strings.Contains(rc.CanonicalText, "ignore me") {
		t.Errorf("expected URL-decoded text, got %q", rc.CanonicalText)
	}
}

func TestNormalise_RecursiveURLDecode(t *testing.T) {
	n := NewNormaliseStage()
	// Double-encoded: %2520 → %20 → space
	rc := &riskcontext.RiskContext{Payload: "hello%2520world"}
	n.Run(rc)
	if !strings.Contains(rc.CanonicalText, "hello world") {
		t.Errorf("expected recursively URL-decoded text, got %q", rc.CanonicalText)
	}
}

func TestNormalise_ZeroWidthStripped(t *testing.T) {
	n := NewNormaliseStage()
	// Insert zero-width space between characters
	rc := &riskcontext.RiskContext{Payload: "hel\u200blo"}
	n.Run(rc)
	if strings.ContainsRune(rc.CanonicalText, '\u200b') {
		t.Errorf("expected zero-width char stripped, got %q", rc.CanonicalText)
	}
	if !strings.Contains(rc.CanonicalText, "hello") {
		t.Errorf("expected 'hello' after zero-width strip, got %q", rc.CanonicalText)
	}
}

func TestNormalise_Leetspeak(t *testing.T) {
	n := NewNormaliseStage()
	rc := &riskcontext.RiskContext{Payload: "h3ll0"}
	n.Run(rc)
	if !strings.Contains(rc.CanonicalText, "hello") {
		t.Errorf("expected leetspeak cleaned to 'hello', got %q", rc.CanonicalText)
	}
}

func TestNormalise_OriginalPayloadUnchanged(t *testing.T) {
	n := NewNormaliseStage()
	original := "h3ll0%20w0rld"
	rc := &riskcontext.RiskContext{Payload: original}
	n.Run(rc)
	if rc.Payload.(string) != original {
		t.Errorf("expected Payload unchanged, got %q", rc.Payload)
	}
}

func TestNormalise_MapPayloadDeterministic(t *testing.T) {
	n := NewNormaliseStage()
	payload := map[string]any{
		"name": "shell",
		"args": "rm -rf /",
	}
	// Run 10 times — CanonicalText must be identical every time.
	var first string
	for i := 0; i < 10; i++ {
		rc := &riskcontext.RiskContext{Payload: payload}
		n.Run(rc)
		if i == 0 {
			first = rc.CanonicalText
			continue
		}
		if rc.CanonicalText != first {
			t.Errorf("non-deterministic CanonicalText: run 0 got %q, run %d got %q", first, i, rc.CanonicalText)
		}
	}
}

func TestNormalise_MapPayloadSortedKeyOrder(t *testing.T) {
	n := NewNormaliseStage()
	rc := &riskcontext.RiskContext{
		Payload: map[string]any{
			"name": "shell",
			"args": "rm -rf /",
		},
	}
	n.Run(rc)
	// keys sorted: "args" < "name" → values joined in that order
	want := "rm -rf / shell"
	if rc.CanonicalText != want {
		t.Errorf("expected %q, got %q", want, rc.CanonicalText)
	}
}

func TestNormalise_MapPayload(t *testing.T) {
	n := NewNormaliseStage()
	rc := &riskcontext.RiskContext{
		Payload: map[string]any{
			"name": "search",
			"args": "find me",
		},
	}
	n.Run(rc)
	if rc.CanonicalText == "" {
		t.Error("expected CanonicalText populated from map payload")
	}
}
