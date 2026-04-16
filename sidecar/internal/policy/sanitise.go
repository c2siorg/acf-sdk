// sanitise.go — string transformation functions called by the executor.
// Supported actions (declared by OPA in sanitise_targets):
//   - StripMatchedSegments: remove pattern-matched substrings
//   - Redact: replace matched segments with [REDACTED]
//   - InjectPrefix: prepend a warning string to the sanitised payload
package policy

import "strings"

// SanitiseRequest carries the payload text and the parameters for the transform.
type SanitiseRequest struct {
	// Text is the payload string to transform.
	Text string
	// MatchedSegments are the substrings to act on (used by Strip and Redact).
	MatchedSegments []string
	// Prefix is prepended by InjectPrefix; empty means no-op.
	Prefix string
}

// StripMatchedSegments removes every occurrence of each segment in
// req.MatchedSegments from req.Text. Empty segments are skipped.
func StripMatchedSegments(req SanitiseRequest) string {
	result := req.Text
	for _, seg := range req.MatchedSegments {
		if seg == "" {
			continue
		}
		result = strings.ReplaceAll(result, seg, "")
	}
	return result
}

// Redact replaces every occurrence of each segment in req.MatchedSegments
// with the literal string "[REDACTED]". Empty segments are skipped.
func Redact(req SanitiseRequest) string {
	result := req.Text
	for _, seg := range req.MatchedSegments {
		if seg == "" {
			continue
		}
		result = strings.ReplaceAll(result, seg, "[REDACTED]")
	}
	return result
}

// InjectPrefix prepends req.Prefix to req.Text separated by a single space.
// If req.Prefix is empty, req.Text is returned unchanged.
func InjectPrefix(req SanitiseRequest) string {
	if req.Prefix == "" {
		return req.Text
	}
	return req.Prefix + " " + req.Text
}
