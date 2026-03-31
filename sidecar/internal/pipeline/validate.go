// validate.go — Stage 1 of the pipeline.
package pipeline

import (
	"errors"
	"strings"

	"github.com/c2siorg/acf-sdk/sidecar/pkg/riskcontext"
)

const MaxPayloadSize = 1024 * 1024 // 1MB

// Validate ensures the incoming request is structurally sound and verified.
func Validate(ctx *riskcontext.RiskContext) error {
	// 1. Structural Sanity Check
	// Assert Payload to string for size and content validation.
	payloadStr, ok := ctx.Payload.(string)
	if !ok || strings.TrimSpace(payloadStr) == "" {
		return errors.New("err: empty_payload")
	}

	// 2. Resource Protection (DoS Mitigation)
	if len(payloadStr) > MaxPayloadSize {
		return errors.New("err: payload_too_large")
	}

	// 3. Hook Context Validation
	// Ensuring the hook type is recognized so the policy engine is targeted correctly.
	isSupported := false
	supportedHooks := []string{"on_prompt", "on_response", "on_tool_call", "on_memory_read"}
	
	for _, h := range supportedHooks {
		if ctx.HookType == h {
			isSupported = true
			break
		}
	}

	if !isSupported {
		// Signals is a []string, so we append the flag.
		ctx.Signals = append(ctx.Signals, "unknown_hook_type")
	}

	// 4. Transport Verification Signal
	// In the new architecture, we check if the transport layer 
	// previously added the "transport_verified" signal to the slice.
	verified := false
	for _, s := range ctx.Signals {
		if s == "transport_verified" {
			verified = true
			break
		}
	}

	if !verified {
		// If the transport layer didn't set this, we treat it as unverified.
		ctx.Score = 1.0 // Max risk (0.0-1.0 scale)
		return errors.New("err: unverified_transport_integrity")
	}

	return nil
}