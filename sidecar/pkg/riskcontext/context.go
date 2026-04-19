// Package riskcontext defines the RiskContext struct — the single payload
// that flows through the entire PDP pipeline. All pipeline stages read from
// and write to this struct. The schema is fixed across v1 and v2; the State
// field is null in v1 and populated by the TTL state store in v2.
package riskcontext

// Signal is a single detection signal emitted by a pipeline stage.
// Category names the signal type; Score is its contribution to the risk score (0.0–1.0).
// This shape matches what the Rego policies expect: sig.category and sig.score.
type Signal struct {
	Category string  `json:"category"`
	Score    float64 `json:"score"`
}

// RiskContext is the payload exchanged over IPC and passed through every
// pipeline stage in the sidecar. It is JSON-serialised as the frame payload.
type RiskContext struct {
	// Score is the aggregated risk score (0.0–1.0). Populated by the
	// aggregate stage. Zero on the inbound frame from the SDK.
	Score float64 `json:"score"`

	// Signals is the list of structured signals emitted by pipeline stages.
	// Empty on the inbound frame; populated as the pipeline runs.
	// Each signal carries a category and score matching the Rego policy schema.
	Signals []Signal `json:"signals"`

	// Provenance identifies the origin of the payload (e.g. "user", "rag",
	// "tool_output", "memory"). Set by the SDK before sending.
	Provenance string `json:"provenance"`

	// SessionID identifies the agent session. Used by the v2 state store.
	SessionID string `json:"session_id"`

	// HookType identifies which hook fired: "on_prompt", "on_context",
	// "on_tool_call", or "on_memory". Used by the policy engine to select
	// the correct Rego file.
	HookType string `json:"hook_type"`

	// Payload is the raw content to evaluate. Can be a string (on_prompt,
	// on_memory) or an object (on_tool_call, on_context chunk).
	Payload any `json:"payload"`

	// CanonicalText is the normalised form of Payload produced by the normalise
	// stage. It is the text the scan stage operates on. The original Payload is
	// never mutated — CanonicalText is a separate derived field.
	// Not serialised to JSON; internal to the sidecar pipeline only.
	CanonicalText string `json:"-"`

	// State is nil in v1. In v2 it is hydrated by the TTL state store before
	// the pipeline runs and contains session history for stateful policies.
	State any `json:"state"`
}
