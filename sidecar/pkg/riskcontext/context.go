// Package riskcontext defines the RiskContext struct — the single payload
// that flows through the entire PDP pipeline. All pipeline stages read from
// and write to this struct. The schema is fixed across v1 and v2; the State
// field is null in v1 and populated by the TTL state store in v2.
package riskcontext

// RiskContext is the payload exchanged over IPC and passed through every
// pipeline stage in the sidecar. It is JSON-serialised as the frame payload.
type RiskContext struct {
	// Score is the aggregated risk score (0.0–1.0). Populated by the
	// aggregate stage. Zero on the inbound frame from the SDK.
	Score float64 `json:"score"`

	// Signals is the list of named signals emitted by the scan stage.
	// Empty on the inbound frame; populated as the pipeline runs.
	Signals []string `json:"signals"`

	// Provenance identifies the origin of the payload (e.g. "user", "rag",
	// "tool_output", "memory"). Set by the SDK before sending.
	Provenance string `json:"provenance"`

	// SessionID identifies the agent session. Used by the v2 state store.
	SessionID string `json:"session_id"`

	// ExecutionID binds the request to a single agent execution. The validate
	// stage uses it to isolate signed provenance envelopes across requests.
	ExecutionID string `json:"execution_id,omitempty"`

	// ProvenanceNonce is a signed request nonce carried inside the JSON body.
	// It is distinct from the transport-frame nonce so the validate stage can
	// surface provenance-specific replay reasons in RiskContext.
	ProvenanceNonce string `json:"provenance_nonce,omitempty"`

	// ExpiresAtUnix is the signed provenance expiry timestamp in Unix seconds.
	ExpiresAtUnix int64 `json:"expires_at,omitempty"`

	// ProvenanceHMAC is the hex-encoded HMAC-SHA256 over the provenance-bound
	// request fields and payload content.
	ProvenanceHMAC string `json:"provenance_hmac,omitempty"`

	// ProvenanceTrust is a normalized signal for later stages. Validate writes
	// 0.0 on failure and 1.0 on success so aggregate/policy can consume it
	// without repeating crypto checks.
	ProvenanceTrust float64 `json:"provenance_trust,omitempty"`

	// ProvenanceFlags contains optional normalized failure reasons such as
	// replay, expired, or mismatch.
	ProvenanceFlags []string `json:"provenance_flags,omitempty"`
	
	// HookType identifies which hook fired: "on_prompt", "on_context",
	// "on_tool_call", or "on_memory". Used by the policy engine to select
	// the correct Rego file.
	HookType string `json:"hook_type"`

	// Payload is the raw content to evaluate. Can be a string (on_prompt,
	// on_memory) or an object (on_tool_call, on_context chunk).
	Payload any `json:"payload"`

	// State is nil in v1. In v2 it is hydrated by the TTL state store before
	// the pipeline runs and contains session history for stateful policies.
	State any `json:"state"`
}
