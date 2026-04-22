// normalise.go — Stage 2 of the pipeline.
// Produces canonical text for scanning by applying (in order):
//  1. Recursive URL decoding
//  2. Recursive Base64 decoding
//  3. Unicode NFKC normalisation
//  4. Zero-width character stripping
//  5. Leetspeak cleaning
//
// The result is written to rc.CanonicalText. The original rc.Payload is never
// mutated. Normalise never emits a hard block signal — it is a pure transform.
package pipeline

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"

	"github.com/acf-sdk/sidecar/pkg/riskcontext"
)

// zeroWidthChars is the set of Unicode code points that are invisible and
// commonly used to bypass keyword detection.
var zeroWidthChars = []rune{
	'\u200b', // zero-width space
	'\u200c', // zero-width non-joiner
	'\u200d', // zero-width joiner
	'\u00ad', // soft hyphen
	'\ufeff', // BOM / zero-width no-break space
	'\u2060', // word joiner
	'\u180e', // mongolian vowel separator
}

// leetspeakMap maps common leet substitutions to their ASCII equivalents.
var leetspeakMap = map[rune]rune{
	'0': 'o',
	'1': 'l',
	'3': 'e',
	'4': 'a',
	'5': 's',
	'7': 't',
	'@': 'a',
	'$': 's',
	'!': 'i',
}

// NormaliseStage produces canonical text from the inbound payload.
type NormaliseStage struct{}

func (n *NormaliseStage) Name() string { return "normalise" }

// Run extracts text from rc.Payload, applies all normalisation transforms,
// and writes the result to rc.CanonicalText. Always returns hardBlock=false.
func (n *NormaliseStage) Run(rc *riskcontext.RiskContext) (hardBlock bool) {
	raw := payloadText(rc.Payload)
	rc.CanonicalText = normalise(raw)
	return false
}

// NewNormaliseStage constructs a NormaliseStage.
func NewNormaliseStage() *NormaliseStage {
	return &NormaliseStage{}
}

// payloadText extracts a string representation from the payload.
// For string payloads, returns the string directly.
// For other types, uses fmt.Sprintf as a best-effort fallback.
func payloadText(payload any) string {
	switch v := payload.(type) {
	case string:
		return v
	case map[string]any:
		// For structured payloads (on_tool_call, on_context), concatenate all
		// string values in sorted key order for a deterministic CanonicalText.
		// Go map iteration is random — without sorting, the same payload can
		// produce different CanonicalText across runs, causing flaky scan results.
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var parts []string
		for _, k := range keys {
			if s, ok := v[k].(string); ok {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, " ")
	default:
		return fmt.Sprintf("%v", v)
	}
}

// normalise applies all transforms to text and returns the canonical form.
func normalise(text string) string {
	text = decodeURL(text)
	text = decodeBase64(text)
	text = applyNFKC(text)
	text = stripZeroWidth(text)
	text = cleanLeetspeak(text)
	return text
}

// decodeURL repeatedly URL-decodes text until stable.
func decodeURL(text string) string {
	for {
		decoded, err := url.QueryUnescape(text)
		if err != nil || decoded == text {
			return text
		}
		text = decoded
	}
}

// decodeBase64 detects and recursively decodes base64-encoded segments.
// Stops when no decodable segment is found.
func decodeBase64(text string) string {
	for {
		decoded := tryBase64(text)
		if decoded == text {
			return text
		}
		text = decoded
	}
}

// tryBase64 attempts to base64-decode text. Returns the decoded string if
// successful and the result is printable ASCII/UTF-8, otherwise returns text.
func tryBase64(text string) string {
	// Only attempt if the text looks like a base64 candidate (length divisible
	// by 4 after stripping whitespace, or padded).
	candidate := strings.TrimSpace(text)
	if len(candidate) < 4 {
		return text
	}
	decoded, err := base64.StdEncoding.DecodeString(candidate)
	if err != nil {
		decoded, err = base64.URLEncoding.DecodeString(candidate)
		if err != nil {
			decoded, err = base64.RawStdEncoding.DecodeString(candidate)
			if err != nil {
				return text
			}
		}
	}
	// Only accept the decoded form if it is valid UTF-8 and contains printable chars.
	result := string(decoded)
	if !isPrintableUTF8(result) {
		return text
	}
	return result
}

// isPrintableUTF8 returns true if s is valid UTF-8 containing at least some
// printable characters and no null bytes.
func isPrintableUTF8(s string) bool {
	if strings.ContainsRune(s, 0) {
		return false
	}
	printable := 0
	for _, r := range s {
		if r == unicode.ReplacementChar {
			return false
		}
		if unicode.IsPrint(r) {
			printable++
		}
	}
	return printable > 0
}

// applyNFKC applies Unicode NFKC normalisation, which decomposes compatibility
// characters and recomposes them in canonical form. This collapses ligatures,
// full-width characters, and other visual equivalents.
func applyNFKC(text string) string {
	return norm.NFKC.String(text)
}

// stripZeroWidth removes all zero-width and invisible Unicode characters.
func stripZeroWidth(text string) string {
	zwSet := make(map[rune]bool, len(zeroWidthChars))
	for _, r := range zeroWidthChars {
		zwSet[r] = true
	}
	return strings.Map(func(r rune) rune {
		if zwSet[r] {
			return -1 // drop
		}
		return r
	}, text)
}

// cleanLeetspeak replaces common leet substitutions with their ASCII equivalents.
func cleanLeetspeak(text string) string {
	return strings.Map(func(r rune) rune {
		if mapped, ok := leetspeakMap[r]; ok {
			return mapped
		}
		return r
	}, text)
}
