// executor.go — reads the OPA decision output, calls sanitise if needed,
// and assembles the sanitised payload returned to the transport layer.
// OPA declares *what* to sanitise; this file performs the actual transformation.

package policy

import (
	"encoding/json"
	"strings"

	"github.com/acf-sdk/sidecar/pkg/riskcontext"
)

// ApplySanitise performs the sanitisation transforms declared by OPA and
// returns the encoded payload bytes to embed in the wire response.
// Returns nil if targets is empty or the payload cannot be extracted.
func ApplySanitise(targets []string, rc *riskcontext.RiskContext) []byte {
	if len(targets) == 0 {
		return nil
	}
	text := payloadText(rc)
	if text == "" {
		return nil
	}

	for _, target := range targets {
		switch target {
		case "prompt_text", "context_chunk", "memory_value", "tool_params":
			// Redact the dangerous content from the payload. The scanner matches
			// against CanonicalText, which normalise may have rewritten (URL/Base64
			// decode, NFKC, leetspeak, zero-width strip). When that rewrite changed
			// the text, CanonicalText is no longer a substring of the original
			// payload and an exact-match redaction would silently do nothing — the
			// chunk would come back with the attack intact despite a SANITISE
			// decision. So we only redact the canonical span when it actually
			// appears in the payload; otherwise we redact the whole value, which is
			// the safe choice for content already flagged as dangerous.
			//
			// TODO(v2): once RiskContext carries the original matched spans from
			// the scan stage, redact those directly and drop this fallback.
			seg := rc.CanonicalText
			if seg != "" && strings.Contains(text, seg) {
				text = Redact(SanitiseRequest{
					Text:            text,
					MatchedSegments: []string{seg},
				})
			} else {
				text = "[REDACTED]"
			}
		case "split_chunk":
			// Signal to the caller that the chunk must be split before processing.
			text = InjectPrefix(SanitiseRequest{
				Text:   text,
				Prefix: "[ACF:SPLIT_REQUIRED]",
			})
		}
	}

	return encodePayload(rc, text)
}

// payloadText extracts a string representation from rc.Payload.
// For string payloads, returns the string directly.
// For map payloads, extracts common content fields.
// Returns "" if the payload cannot be represented as text.
func payloadText(rc *riskcontext.RiskContext) string {
	switch v := rc.Payload.(type) {
	case string:
		return v
	case map[string]any:
		for _, key := range []string{"content", "value", "text", "prompt"} {
			if s, ok := v[key].(string); ok {
				return s
			}
		}
		// Fall back to full JSON for structured payloads.
		b, _ := json.Marshal(v)
		return string(b)
	default:
		return ""
	}
}

// encodePayload marshals the sanitised text back to bytes suitable for the
// wire response. String payloads are JSON-encoded as a string. Map payloads
// are wrapped in {"sanitised": <text>}.
func encodePayload(rc *riskcontext.RiskContext, sanitisedText string) []byte {
	switch rc.Payload.(type) {
	case string:
		b, _ := json.Marshal(sanitisedText)
		return b
	default:
		b, _ := json.Marshal(map[string]string{"sanitised": sanitisedText})
		return b
	}
}