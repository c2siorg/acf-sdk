// Package pipeline orchestrates the four enforcement stages in order:
// validate → normalise → scan → aggregate.
//
// In strict mode (default), the pipeline short-circuits and returns BLOCK
// immediately when any stage emits a hard block signal. In non-strict mode,
// all stages run regardless and the full signal set is collected before the
// final decision is made. Non-strict mode is useful for debugging, auditing,
// and policy development.
//
// Phase 2: the final decision is derived from the aggregate score vs thresholds.
// OPA evaluation is wired in Phase 3.
package pipeline

import (
	"log"

	"github.com/acf-sdk/sidecar/internal/config"
	"github.com/acf-sdk/sidecar/internal/policy"
	"github.com/acf-sdk/sidecar/pkg/decision"
	"github.com/acf-sdk/sidecar/pkg/riskcontext"
)

// Result is the output of a pipeline run.
type Result struct {
	// Decision is one of transport.DecisionAllow, DecisionSanitise, DecisionBlock.
	Decision byte
	// Score is the final aggregated risk score (0.0–1.0).
	Score float64
	// Signals is the full list of signals emitted during the run, with scores
	// back-filled by the aggregate stage.
	Signals []riskcontext.Signal
	// BlockedAt names the stage that produced the first hard block signal,
	// or empty if no hard block occurred.
	BlockedAt string
	// SanitisedPayload is the transformed payload returned to the client when
	// decision == Sanitise. Nil for Allow and Block decisions.
	SanitisedPayload []byte
}

// Stage is a single pipeline stage. Run mutates rc in place and returns whether
// a hard block signal was emitted.
type Stage interface {
	Name() string
	Run(rc *riskcontext.RiskContext) (hardBlock bool)
}

// Evaluator is implemented by policy.Engine. It evaluates OPA policy for a
// given RiskContext and returns the decision string ("ALLOW"/"SANITISE"/"BLOCK")
// and the list of sanitise_targets declared by Rego.
// Defined here (not in the policy package) to keep the import one-directional:
// pipeline imports policy; policy imports only riskcontext — no cycle.
type Evaluator interface {
	Evaluate(rc *riskcontext.RiskContext) (decision string, sanitiseTargets []string, err error)
}

// Pipeline runs the four enforcement stages in order.
type Pipeline struct {
	cfg       *config.Config
	stages    []Stage
	evaluator Evaluator // nil → threshold fallback (Phase 2 behaviour)
}

// New constructs a Pipeline with no OPA evaluator (threshold fallback only).
// Stages must be provided in pipeline order: validate, normalise, scan, aggregate.
func New(cfg *config.Config, stages []Stage) *Pipeline {
	return &Pipeline{cfg: cfg, stages: stages}
}

// NewWithEvaluator constructs a Pipeline that calls ev after the four stages
// to obtain the final decision from OPA. Falls back to threshold if ev errors.
func NewWithEvaluator(cfg *config.Config, stages []Stage, ev Evaluator) *Pipeline {
	return &Pipeline{cfg: cfg, stages: stages, evaluator: ev}
}

// Run executes all pipeline stages against rc and returns a Result.
// In strict mode, the first hard block short-circuits execution.
// In non-strict mode, all stages run and the final decision is taken after aggregate.
func (p *Pipeline) Run(rc *riskcontext.RiskContext) Result {
	var blockedAt string

	for _, s := range p.stages {
		hardBlock := s.Run(rc)
		if hardBlock {
			if p.cfg.Pipeline.StrictMode {
				return Result{
					Decision:  decision.Block,
					Score:     rc.Score,
					Signals:   rc.Signals,
					BlockedAt: s.Name(),
				}
			}
			// non-strict: note the stage but keep running
			if blockedAt == "" {
				blockedAt = s.Name()
			}
		}
	}

	// After all stages: call OPA evaluator or fall back to threshold.
	var d byte
	var sanitised []byte

	if p.evaluator != nil {
		opaDecision, targets, err := p.evaluator.Evaluate(rc)
		if err != nil {
			log.Printf("pipeline: OPA evaluation error: %v (falling back to threshold)", err)
			d = thresholdDecision(rc.Score, p.cfg.Thresholds)
		} else {
			d = decisionByte(opaDecision)
			if d == decision.Sanitise && len(targets) > 0 {
				sanitised = policy.ApplySanitise(targets, rc)
			}
		}
	} else {
		d = thresholdDecision(rc.Score, p.cfg.Thresholds)
	}

	return Result{
		Decision:         d,
		Score:            rc.Score,
		Signals:          rc.Signals,
		BlockedAt:        blockedAt,
		SanitisedPayload: sanitised,
	}
}

// decisionByte converts an OPA decision string to a decision byte constant.
func decisionByte(s string) byte {
	switch s {
	case "BLOCK":
		return decision.Block
	case "SANITISE":
		return decision.Sanitise
	default:
		return decision.Allow
	}
}

// thresholdDecision maps a risk score to a decision byte using configured thresholds.
// OPA overrides this in Phase 3; in Phase 2 it is the final word.
func thresholdDecision(score float64, t config.ThresholdConfig) byte {
	switch {
	case score >= t.BlockScore:
		return decision.Block
	case score >= t.SanitiseScore:
		return decision.Sanitise
	default:
		return decision.Allow
	}
}
