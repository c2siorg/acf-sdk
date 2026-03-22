package policy

import (
	"context"
	"fmt"

	"github.com/open-policy-agent/opa/rego"
	"github.com/c2siorg/acf-sdk/sidecar/pkg/riskcontext"
)

// Evaluate takes the RiskContext and runs it against the Rego policy.
// This is the 'Brain' of the ACF Kernel.
func Evaluate(ctx context.Context, riskCtx *riskcontext.RiskContext) (*riskcontext.PolicyResult, error) {
	// 1. Define the Inline Rego Policy.
	// We've updated the logic to DENY if ANY risk signals are present.
	regoQuery := `
		package acf.authz

		# Default values for safety
		default allow = false

		# The decision logic: 
		# 1. Allow if risk score is under 75.
		# 2. Allow only if NO malicious signals were found by the Lexical Scanner.
		allow {
			input.risk_score < 75
			not input.signals.injection_detected
		}

		# The structured output object
		result = {
			"decision": decision_msg,
			"reason": reason_msg
		}

		# Decision message mapping
		decision_msg = "ALLOW" {
			allow
		}
		else = "DENY"

		# Reason mapping
		reason_msg = "risk_score_within_threshold" {
			allow
		}
		else = "malicious_content_detected"
	`

	// 2. Prepare the OPA Evaluation
	query, err := rego.New(
		rego.Query("data.acf.authz.result"),
		rego.Module("acf_policy.rego", regoQuery),
	).PrepareForEval(ctx)

	if err != nil {
		return nil, fmt.Errorf("failed to prepare rego: %w", err)
	}

	// 3. Execute the Policy
	// We pass the entire riskCtx. OPA sees this as 'input'.
	results, err := query.Eval(ctx, rego.EvalInput(riskCtx))
	if err != nil {
		return nil, fmt.Errorf("rego evaluation failed: %w", err)
	}

	// 4. Parse the Result
	if len(results) == 0 || len(results[0].Expressions) == 0 {
		return &riskcontext.PolicyResult{
			Decision: "DENY",
			Reason:   "policy_engine_no_response",
		}, nil
	}

	// Extract the result map
	rawResult, ok := results[0].Expressions[0].Value.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected OPA result type: %T", results[0].Expressions[0].Value)
	}

	return &riskcontext.PolicyResult{
		Decision: fmt.Sprintf("%v", rawResult["decision"]),
		Reason:   fmt.Sprintf("%v", rawResult["reason"]),
	}, nil
}