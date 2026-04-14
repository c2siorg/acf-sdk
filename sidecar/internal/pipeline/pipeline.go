// Package pipeline orchestrates the four enforcement stages in order:
// validate → normalise → scan → aggregate, then an OPA policy evaluation.
//
// In strict mode (default), the pipeline short-circuits and returns BLOCK
// immediately when any stage emits a hard block signal. In non-strict mode,
// all stages run regardless and the full signal set is collected before the
// final decision is made. Non-strict mode is useful for debugging, auditing,
// and policy development.
//
// Every run is wrapped in a root span with one child span per stage and one
// span around the OPA evaluation that records what is sent to OPA and the
// decision it returns. Telemetry is emitted after the decision and never blocks
// the enforcement path; nil sinks fall back to noops.
package pipeline

import (
	"context"
	"log"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/acf-sdk/sidecar/internal/config"
	"github.com/acf-sdk/sidecar/internal/policy"
	"github.com/acf-sdk/sidecar/internal/telemetry"
	"github.com/acf-sdk/sidecar/pkg/decision"
	"github.com/acf-sdk/sidecar/pkg/riskcontext"
)

// Result is the output of a pipeline run.
type Result struct {
	// Decision is one of decision.Allow, decision.Sanitise, decision.Block.
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
// pipeline imports policy; policy imports only riskcontext, so there is no cycle.
type Evaluator interface {
	Evaluate(rc *riskcontext.RiskContext) (decision string, sanitiseTargets []string, err error)
}

// Options carries optional wiring for Pipeline construction. A nil Evaluator
// falls back to threshold scoring; nil Tracer/AuditSink install noops so the
// enforcement path never depends on telemetry being configured.
type Options struct {
	Evaluator     Evaluator
	Tracer        trace.Tracer
	AuditSink     telemetry.AuditSink
	PolicyVersion string
}

// Pipeline runs the four enforcement stages in order, then OPA evaluation.
type Pipeline struct {
	cfg           *config.Config
	stages        []Stage
	evaluator     Evaluator // nil → threshold fallback (Phase 2 behaviour)
	tracer        trace.Tracer
	audit         telemetry.AuditSink
	policyVersion string
}

// New constructs a Pipeline with no OPA evaluator (threshold fallback only) and
// noop telemetry. Stages must be provided in pipeline order:
// validate, normalise, scan, aggregate.
func New(cfg *config.Config, stages []Stage) *Pipeline {
	return NewWithOptions(cfg, stages, Options{})
}

// NewWithEvaluator constructs a Pipeline that calls ev after the four stages to
// obtain the final decision from OPA. Falls back to threshold if ev errors.
func NewWithEvaluator(cfg *config.Config, stages []Stage, ev Evaluator) *Pipeline {
	return NewWithOptions(cfg, stages, Options{Evaluator: ev})
}

// NewWithOptions constructs a Pipeline with an optional evaluator and
// observability hooks. Nil Tracer/AuditSink install noops.
func NewWithOptions(cfg *config.Config, stages []Stage, opts Options) *Pipeline {
	tracer := opts.Tracer
	if tracer == nil {
		tracer = telemetry.NoopTracer()
	}
	sink := opts.AuditSink
	if sink == nil {
		sink = telemetry.NopSink{}
	}
	return &Pipeline{
		cfg:           cfg,
		stages:        stages,
		evaluator:     opts.Evaluator,
		tracer:        tracer,
		audit:         sink,
		policyVersion: opts.PolicyVersion,
	}
}

// Run executes the pipeline with a fresh background context.
func (p *Pipeline) Run(rc *riskcontext.RiskContext) Result {
	return p.RunContext(context.Background(), rc)
}

// RunContext executes the pipeline with a caller-supplied context so spans link
// into an existing trace and ParentBased sampling is honoured.
func (p *Pipeline) RunContext(ctx context.Context, rc *riskcontext.RiskContext) Result {
	runCtx, runSpan := p.tracer.Start(ctx, "pipeline.Run",
		trace.WithAttributes(
			attribute.String("hook_type", rc.HookType),
			attribute.String("provenance", rc.Provenance),
		),
	)
	defer runSpan.End()

	start := time.Now()

	var blockedAt string
	var shortCircuit bool

	for _, s := range p.stages {
		prevSignals := len(rc.Signals)
		_, stageSpan := p.tracer.Start(runCtx, "stage."+s.Name())
		hardBlock := s.Run(rc)
		stageSpan.SetAttributes(
			attribute.Int("signals.added", len(rc.Signals)-prevSignals),
			attribute.Bool("hard_block", hardBlock),
		)
		stageSpan.End()

		if !hardBlock {
			continue
		}
		if blockedAt == "" {
			blockedAt = s.Name()
		}
		if p.cfg.Pipeline.StrictMode {
			shortCircuit = true
			break
		}
	}

	var result Result
	if shortCircuit {
		// Strict-mode hard block: BLOCK without consulting OPA.
		result = Result{
			Decision:  decision.Block,
			Score:     rc.Score,
			Signals:   rc.Signals,
			BlockedAt: blockedAt,
		}
	} else {
		d, sanitised := p.decide(runCtx, rc)
		result = Result{
			Decision:         d,
			Score:            rc.Score,
			Signals:          rc.Signals,
			BlockedAt:        blockedAt,
			SanitisedPayload: sanitised,
		}
	}

	elapsed := time.Since(start)
	annotateRunSpan(runSpan, result, elapsed)
	p.emitAudit(runSpan.SpanContext(), rc, result, elapsed)

	return result
}

// decide produces the final decision after the stages have run. When an OPA
// evaluator is configured it is consulted inside an "opa.evaluate" span that
// records what is sent to OPA and the decision returned; on evaluator error it
// falls back to threshold scoring. With no evaluator it is threshold scoring.
func (p *Pipeline) decide(ctx context.Context, rc *riskcontext.RiskContext) (byte, []byte) {
	if p.evaluator == nil {
		return thresholdDecision(rc.Score, p.cfg.Thresholds), nil
	}

	_, opaSpan := p.tracer.Start(ctx, "opa.evaluate",
		trace.WithAttributes(
			attribute.String("opa.input.hook_type", rc.HookType),
			attribute.Float64("opa.input.score", rc.Score),
			attribute.Int("opa.input.signals", len(rc.Signals)),
		),
	)
	defer opaSpan.End()

	opaDecision, targets, err := p.evaluator.Evaluate(rc)
	if err != nil {
		opaSpan.RecordError(err)
		opaSpan.SetAttributes(attribute.String("opa.outcome", "error_fallback_threshold"))
		log.Printf("pipeline: OPA evaluation error: %v (falling back to threshold)", err)
		return thresholdDecision(rc.Score, p.cfg.Thresholds), nil
	}

	d := decisionByte(opaDecision)
	opaSpan.SetAttributes(
		attribute.String("opa.output.decision", opaDecision),
		attribute.Int("opa.output.sanitise_targets", len(targets)),
	)

	var sanitised []byte
	if d == decision.Sanitise && len(targets) > 0 {
		sanitised = policy.ApplySanitise(targets, rc)
	}
	return d, sanitised
}

func annotateRunSpan(span trace.Span, r Result, elapsed time.Duration) {
	span.SetAttributes(
		attribute.String("decision", decisionText(r.Decision)),
		attribute.Float64("score", r.Score),
		attribute.Float64("duration_ms", float64(elapsed.Microseconds())/1000.0),
	)
	if r.BlockedAt != "" {
		span.SetAttributes(attribute.String("blocked_at", r.BlockedAt))
	}
}

func (p *Pipeline) emitAudit(sc trace.SpanContext, rc *riskcontext.RiskContext, r Result, elapsed time.Duration) {
	entry := telemetry.NewEntry()
	entry.HookType = rc.HookType
	entry.Decision = decisionText(r.Decision)
	entry.Score = r.Score
	entry.Signals = signalCategories(r.Signals)
	entry.Provenance = rc.Provenance
	entry.SessionID = rc.SessionID
	entry.PolicyVersion = p.policyVersion
	entry.BlockedAt = r.BlockedAt
	entry.DurationMillis = float64(elapsed.Microseconds()) / 1000.0
	if sc.IsValid() {
		entry.TraceID = sc.TraceID().String()
		entry.SpanID = sc.SpanID().String()
	}
	p.audit.Emit(entry)
}

// signalCategories projects the signal list down to its category names for the
// audit log. Raw scores are omitted; the audit record carries the aggregate
// score separately.
func signalCategories(sigs []riskcontext.Signal) []string {
	out := make([]string, 0, len(sigs))
	for _, s := range sigs {
		out = append(out, s.Category)
	}
	return out
}

func decisionText(d byte) string {
	switch d {
	case decision.Allow:
		return "allow"
	case decision.Sanitise:
		return "sanitise"
	case decision.Block:
		return "block"
	default:
		return "unknown"
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

// thresholdDecision maps a risk score to a decision byte using configured
// thresholds. Used as the fallback when no OPA evaluator is configured or
// evaluation errors.
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
