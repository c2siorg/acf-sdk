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
	"context"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/acf-sdk/sidecar/internal/config"
	"github.com/acf-sdk/sidecar/internal/telemetry"
	"github.com/acf-sdk/sidecar/pkg/decision"
	"github.com/acf-sdk/sidecar/pkg/riskcontext"
)

// Result is the output of a pipeline run.
type Result struct {
	// Decision is one of transport.DecisionAllow, DecisionSanitise, DecisionBlock.
	Decision byte
	// Score is the final aggregated risk score (0.0–1.0).
	Score float64
	// Signals is the full list of named signals emitted during the run.
	Signals []string
	// BlockedAt names the stage that produced the first hard block signal,
	// or empty if no hard block occurred.
	BlockedAt string
}

// Stage is a single pipeline stage. Run mutates rc in place and returns whether
// a hard block signal was emitted.
type Stage interface {
	Name() string
	Run(rc *riskcontext.RiskContext) (hardBlock bool)
}

// Options carries optional observability hooks for Pipeline construction.
// Nil fields fall back to noop sinks so the enforcement path never depends
// on telemetry being configured.
type Options struct {
	Tracer        trace.Tracer
	AuditSink     telemetry.AuditSink
	PolicyVersion string
}

// Pipeline runs the four enforcement stages in order.
type Pipeline struct {
	cfg           *config.Config
	stages        []Stage
	tracer        trace.Tracer
	audit         telemetry.AuditSink
	policyVersion string
}

// New constructs a Pipeline from the given config and ordered stages.
// Stages must be provided in pipeline order: validate, normalise, scan, aggregate.
// Telemetry is installed in noop mode; use NewWithOptions to wire real sinks.
func New(cfg *config.Config, stages []Stage) *Pipeline {
	return NewWithOptions(cfg, stages, Options{})
}

// NewWithOptions constructs a Pipeline with optional observability hooks.
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
		tracer:        tracer,
		audit:         sink,
		policyVersion: opts.PolicyVersion,
	}
}

// Run executes the pipeline with a fresh background context.
func (p *Pipeline) Run(rc *riskcontext.RiskContext) Result {
	return p.RunContext(context.Background(), rc)
}

// RunContext executes the pipeline with a caller-supplied context so spans
// link into an existing trace and ParentBased sampling is honoured.
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
		result = Result{
			Decision:  decision.Block,
			Score:     rc.Score,
			Signals:   rc.Signals,
			BlockedAt: blockedAt,
		}
	} else {
		result = Result{
			Decision:  thresholdDecision(rc.Score, p.cfg.Thresholds),
			Score:     rc.Score,
			Signals:   rc.Signals,
			BlockedAt: blockedAt,
		}
	}

	elapsed := time.Since(start)
	annotateRunSpan(runSpan, result, elapsed)
	p.emitAudit(runSpan.SpanContext(), rc, result, elapsed)

	return result
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
	entry.Signals = append([]string(nil), r.Signals...)
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
