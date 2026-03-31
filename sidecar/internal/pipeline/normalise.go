package pipeline

import (
	"strings"
	"github.com/c2siorg/acf-sdk/sidecar/pkg/riskcontext"
)

func Normalise(ctx *riskcontext.RiskContext) {
	payload, ok := ctx.Payload.(string)
	if !ok {
		return
	}
	// Transform to lowercase and trim to ensure Scan finds matches
	ctx.Payload = strings.ToLower(strings.TrimSpace(payload))
}