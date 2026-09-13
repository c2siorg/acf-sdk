// aggregate.go: Stage 4 of the pipeline.
// Combines scanner signals into a final risk score (0.0–1.0):
//   - Takes the maximum weight across all emitted signals (avoids score inflation)
//   - Applies provenance trust weight as a multiplier
//   - If State is non-nil (v2), blends in prior_score (placeholder, no-op in v1)
//
// Production signal weights, thresholds, and provenance trust weights come
// from 1 policy snapshot. Standalone pipelines use their supplied config and
// WeightSource.
//
// Writes rc.Score. Does not return hardBlock. Score-based blocking is decided
// by the pipeline dispatcher after aggregate completes.
package pipeline

import (
	"math"

	"github.com/acf-sdk/sidecar/internal/config"
	"github.com/acf-sdk/sidecar/pkg/riskcontext"
)

// WeightSource supplies the current signal weights: the risk-score
// contribution of each signal category. policy.Engine implements it by reading
// signal_weights from policy_config.yaml on every hot reload.
//
// The returned map is read-only. Implementations replace it wholesale rather
// than mutating it in place.
type WeightSource interface {
	SignalWeights() map[string]float64
}

// SignalCategorySource reports whether a signal name is safe to record.
type SignalCategorySource interface {
	SignalCategoryAllowed(category string) bool
}

// StaticWeights is a fixed WeightSource, for tests and for embedders that do
// not run a policy engine.
type StaticWeights map[string]float64

// SignalWeights returns w.
func (w StaticWeights) SignalWeights() map[string]float64 { return w }

// SignalCategoryAllowed permits the fixed categories in w.
func (w StaticWeights) SignalCategoryAllowed(category string) bool {
	_, ok := w[category]
	return ok
}

// AggregateStage combines signals into a final risk score.
type AggregateStage struct {
	cfg     *config.Config
	weights WeightSource
}

// NewAggregateStage constructs an AggregateStage. cfg supplies the provenance
// trust weights and weights supplies the per-signal weights.
func NewAggregateStage(cfg *config.Config, weights WeightSource) *AggregateStage {
	return &AggregateStage{cfg: cfg, weights: weights}
}

func (a *AggregateStage) Name() string { return "aggregate" }

// Run computes rc.Score from the signals in rc.Signals and back-fills each
// signal's Score field from the current signal weights so OPA sees
// fully-scored signals.
// Always returns hardBlock=false. The dispatcher applies threshold logic.
func (a *AggregateStage) Run(rc *riskcontext.RiskContext) (hardBlock bool) {
	var allowed SignalCategorySource
	if source, ok := a.weights.(SignalCategorySource); ok {
		allowed = source
	}
	score := applySignalWeights(rc.Signals, a.weights.SignalWeights(), allowed)
	score *= a.cfg.ProvenanceWeight(rc.Provenance)
	score = clamp(score)

	// v2: blend in historical score from state store (no-op in v1 because State is nil).

	rc.Score = score
	return false
}

// RunWithSnapshot scores a production request from the exact policy
// generation selected when the pipeline started it.
func (a *AggregateStage) RunWithSnapshot(rc *riskcontext.RiskContext, snapshot PolicySnapshot) (hardBlock bool) {
	score := applySignalWeights(rc.Signals, snapshot.SignalWeights(), snapshot)
	score *= snapshot.ProvenanceWeight(rc.Provenance)
	score = clamp(score)

	rc.Score = score
	return false
}

// applySignalWeights looks up each signal's weight, writes it back onto the
// signal (so OPA sees sig.score), and returns the maximum weight found.
// Returns 0.0 if no signals are present or none have a configured weight.
//
// A category with no active weight contributes nothing to the aggregate score.
// Its inbound score is preserved only when the active policy explicitly allows
// that category, because some OPA rules consume detector confidence directly.
// Unknown and invalid inbound scores are cleared.
func applySignalWeights(signals []riskcontext.Signal, weights map[string]float64, allowed SignalCategorySource) float64 {
	var maxW float64
	for i := range signals {
		inboundScore := signals[i].Score
		if w, ok := weights[signals[i].Category]; ok {
			signals[i].Score = w
			if w > maxW {
				maxW = w
			}
			continue
		}

		signals[i].Score = 0
		if allowed != nil && allowed.SignalCategoryAllowed(signals[i].Category) &&
			!math.IsNaN(inboundScore) && !math.IsInf(inboundScore, 0) &&
			inboundScore >= 0 && inboundScore <= 1 {
			signals[i].Score = inboundScore
		}
	}
	return maxW
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
