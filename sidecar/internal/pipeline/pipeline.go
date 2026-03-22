package pipeline

import (
	"fmt"
	"github.com/c2siorg/acf-sdk/sidecar/pkg/riskcontext"
)

type PipelineInterface interface {
	Process(ctx *riskcontext.RiskContext)
}

type Pipeline struct{}

func (p *Pipeline) Process(ctx *riskcontext.RiskContext) {
	fmt.Printf("\n--- 🛡️  Pipeline Started (Session: %s) ---\n", ctx.SessionID)

	// Stage 1: Validate
	if err := Validate(ctx); err != nil {
		fmt.Printf("❌ Stage 1 (Validate) Failed: %v\n", err)
		ctx.Score = 1.0 
		ctx.Signals = append(ctx.Signals, "validation_error")
		return
	}
	fmt.Println("✅ Stage 1 (Validate) Passed")

	// Stage 2: Normalise
	Normalise(ctx)
	fmt.Printf("✅ Stage 2 (Normalise) Output: %v\n", ctx.Payload)

	// Stage 3: Scan
	Scan(ctx)
	fmt.Printf("✅ Stage 3 (Scan) Score: %.2f | Signals: %v\n", ctx.Score, ctx.Signals)

	// Stage 4: Aggregate
	Aggregate(ctx)
	fmt.Printf("✅ Stage 4 (Aggregate) Final Score: %.2f\n", ctx.Score)
	
	fmt.Println("--- 🏁 Pipeline Finished ---")
}