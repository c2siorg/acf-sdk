package pipeline

import (
	"math"
	"testing"

	"github.com/acf-sdk/sidecar/pkg/riskcontext"
)

func TestApplySignalWeightsClearsUnweightedInboundScores(t *testing.T) {
	signals := []riskcontext.Signal{
		{Category: "unweighted", Score: 0.99},
		{Category: "weighted", Score: 0.01},
		{Category: "zero_weight", Score: 0.88},
	}

	score := applySignalWeights(signals, map[string]float64{
		"weighted":    0.4,
		"zero_weight": 0,
	}, StaticWeights{
		"weighted":    0.4,
		"zero_weight": 0,
	})

	if score != 0.4 {
		t.Fatalf("score = %v, want 0.4", score)
	}
	if signals[0].Score != 0 {
		t.Errorf("unweighted inbound score = %v, want 0", signals[0].Score)
	}
	if signals[1].Score != 0.4 {
		t.Errorf("weighted score = %v, want 0.4", signals[1].Score)
	}
	if signals[2].Score != 0 {
		t.Errorf("zero-weight score = %v, want 0", signals[2].Score)
	}
}

func TestApplySignalWeightsPreservesApprovedUnweightedScores(t *testing.T) {
	signals := []riskcontext.Signal{
		{Category: "content_scan", Score: 0.6},
		{Category: "source_trust", Score: 0.2},
		{Category: "unknown", Score: 0.99},
		{Category: "weighted", Score: 0.01},
	}
	allowed := testSignalCategories{
		"content_scan": {},
		"source_trust": {},
		"weighted":     {},
	}

	score := applySignalWeights(signals, map[string]float64{"weighted": 0.4}, allowed)

	if score != 0.4 {
		t.Fatalf("score = %v, want 0.4", score)
	}
	for i, want := range []float64{0.6, 0.2, 0, 0.4} {
		if signals[i].Score != want {
			t.Errorf("signals[%d].Score = %v, want %v", i, signals[i].Score, want)
		}
	}
}

func TestApplySignalWeightsClearsInvalidApprovedScores(t *testing.T) {
	signals := []riskcontext.Signal{
		{Category: "content_scan", Score: -0.1},
		{Category: "content_scan", Score: 1.1},
		{Category: "content_scan", Score: math.NaN()},
		{Category: "content_scan", Score: math.Inf(1)},
	}

	applySignalWeights(signals, nil, testSignalCategories{"content_scan": {}})

	for i := range signals {
		if signals[i].Score != 0 {
			t.Errorf("signals[%d].Score = %v, want 0", i, signals[i].Score)
		}
	}
}

func TestStaticWeightsRemainStandaloneWeightSource(t *testing.T) {
	weights := StaticWeights{"jailbreak_pattern": 0.9}
	if got := weights.SignalWeights()["jailbreak_pattern"]; got != 0.9 {
		t.Fatalf("static weight = %v, want 0.9", got)
	}
	if !weights.SignalCategoryAllowed("jailbreak_pattern") {
		t.Fatal("static weighted category was not allowed for audit")
	}
	if weights.SignalCategoryAllowed("unweighted") {
		t.Fatal("unknown standalone category was allowed for audit")
	}
}
