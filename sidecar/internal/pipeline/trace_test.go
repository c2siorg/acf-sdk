package pipeline

import (
	"testing"

	"github.com/acf-sdk/sidecar/internal/config"
	"github.com/acf-sdk/sidecar/pkg/decision"
	"github.com/acf-sdk/sidecar/pkg/riskcontext"
)

func TestRunTraced_RecordsEveryStageInOrder(t *testing.T) {
	cfg := testConfig(true)
	pl := NewWithEvaluator(cfg, []Stage{
		NewValidateStage(),
		NewNormaliseStage(),
		NewScanStage(cfg, nil),
		NewAggregateStage(cfg, testWeights()),
	}, &mockEvaluator{decision: "SANITISE", targets: []string{"prompt"}})

	var tr Trace
	result := pl.RunTraced(&riskcontext.RiskContext{
		HookType:   "on_prompt",
		Provenance: "user",
		Payload:    "what is the weather today",
	}, &tr)

	if result.Decision != decision.Sanitise {
		t.Fatalf("decision = %d, want SANITISE", result.Decision)
	}
	want := []string{"validate", "normalise", "scan", "aggregate"}
	if len(tr.Stages) != len(want) {
		t.Fatalf("recorded %d stages, want %d: %+v", len(tr.Stages), len(want), tr.Stages)
	}
	for i, name := range want {
		if tr.Stages[i].Name != name {
			t.Errorf("stage %d = %q, want %q", i, tr.Stages[i].Name, name)
		}
		if tr.Stages[i].Duration < 0 {
			t.Errorf("stage %q has negative duration %v", name, tr.Stages[i].Duration)
		}
	}
	if tr.Policy < 0 || tr.Sanitise < 0 {
		t.Errorf("negative policy/sanitise duration: %+v", tr)
	}
}

func TestRunTraced_ShortCircuitStopsRecording(t *testing.T) {
	pl := buildPipeline(testConfig(true), []config.PatternEntry{})
	var tr Trace
	result := pl.RunTraced(&riskcontext.RiskContext{HookType: "bogus", Provenance: "user", Payload: "x"}, &tr)

	if result.Decision != decision.Block || result.BlockedAt != "validate" {
		t.Fatalf("got decision=%d blocked_at=%q, want BLOCK at validate", result.Decision, result.BlockedAt)
	}
	if len(tr.Stages) != 1 || tr.Stages[0].Name != "validate" {
		t.Errorf("stages = %+v, want only validate", tr.Stages)
	}
}

func TestRunTraced_NilTraceMatchesRun(t *testing.T) {
	pl := buildPipeline(testConfig(true), nil)
	rc := func() *riskcontext.RiskContext {
		return &riskcontext.RiskContext{HookType: "on_prompt", Provenance: "user", Payload: "hello"}
	}
	a, b := pl.Run(rc()), pl.RunTraced(rc(), nil)
	if a.Decision != b.Decision || a.Score != b.Score {
		t.Errorf("Run = %+v, RunTraced(nil) = %+v", a, b)
	}
}
