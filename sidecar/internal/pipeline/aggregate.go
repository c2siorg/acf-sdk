// aggregate.go — Stage 4 of the pipeline.
// Combines scanner signals into a final risk score (0.0–1.0):
//   - Sums all signal scores (clamped to 1.0) so multiple signals compound
//   - Applies provenance trust weight as a multiplier
//   - If State is non-nil (v2), blends in prior_score (placeholder, no-op in v1)
//
// Writes rc.Score. Does not return hardBlock — score-based blocking is decided
// by the pipeline dispatcher after aggregate completes.
package pipeline

import (
	"github.com/acf-sdk/sidecar/internal/config"
	"github.com/acf-sdk/sidecar/pkg/riskcontext"
)

// AggregateStage combines signals into a final risk score.
type AggregateStage struct {
	cfg *config.Config
}

// NewAggregateStage constructs an AggregateStage.
func NewAggregateStage(cfg *config.Config) *AggregateStage {
	return &AggregateStage{cfg: cfg}
}

func (a *AggregateStage) Name() string { return "aggregate" }

// Run computes rc.Score from the signals in rc.Signals.
// Always returns hardBlock=false — the dispatcher applies threshold logic.
func (a *AggregateStage) Run(rc *riskcontext.RiskContext) (hardBlock bool) {
	score := sumSignalScore(rc.Signals)
	score *= a.cfg.ProvenanceWeight(rc.Provenance)
	score = clamp(score)

	// v2: blend in historical score from state store (no-op in v1 — State is nil).
	// Placeholder: Phase 3 populates this via the TTL state store.

	rc.Score = score
	return false
}

// sumSignalScore returns the sum of all signal scores, unclamped.
// clamp() is applied by the caller after provenance weighting.
// Additive scoring ensures multiple medium-risk signals compound correctly
// instead of the highest single signal masking the rest.
func sumSignalScore(signals []riskcontext.Signal) float64 {
	var total float64
	for _, sig := range signals {
		total += sig.Score
	}
	return total
}

// clamp ensures score stays within [0.0, 1.0].
func clamp(score float64) float64 {
	if score < 0 {
		return 0
	}
	if score > 1 {
		return 1
	}
	return score
}
