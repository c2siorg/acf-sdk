package pipeline

import (
	"github.com/c2siorg/acf-sdk/sidecar/pkg/riskcontext"
)

// Aggregate finalizes the risk score.
func Aggregate(ctx *riskcontext.RiskContext) {
	// If the Scan stage (Stage 3) found a kernel_match, 
	// we MUST ensure the score stays at 1.0 to trigger a BLOCK.
	for _, signal := range ctx.Signals {
		if signal == "kernel_match" {
			ctx.Score = 1.0
			return 
		}
	}

	// Fallback: If no critical match, keep the score as is 
	// (or cap it at 1.0 for safety)
	if ctx.Score > 1.0 {
		ctx.Score = 1.0
	}
}