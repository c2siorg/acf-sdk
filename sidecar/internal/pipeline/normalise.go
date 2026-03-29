// normalise.go — Stage 2 of the pipeline.
// Produces canonical text for scanning by applying (in order):
//   1. Unicode NFKC normalisation
//   2. Zero-width/invisible character stripping
//   3. Limited URL percent-decoding for valid %XX sequences
package pipeline

import (
	"net/url"
	"regexp"
	"strings"

	"golang.org/x/text/unicode/norm"
)

// NormalisationResult is the minimal output contract for layer-1 preprocessing.
type NormalisationResult struct {
	NormalisedText string
	OriginalText   string
}

var (
	// Zero-width and directional marks commonly used in prompt obfuscation.
	zeroWidthOrInvisible = regexp.MustCompile(
		"[\u200B\u200C\u200D\u2060\uFEFF\u00AD\u180E\u200E\u200F\u202A-\u202E]",
	)
	validPercentEncoded = regexp.MustCompile(`%(?:[0-9a-fA-F]{2})`)
)

// NormaliseText applies the lightweight, deterministic fast-path transforms.
func NormaliseText(in string) NormalisationResult {
	out := in
	out = norm.NFKC.String(out)
	out = zeroWidthOrInvisible.ReplaceAllString(out, "")
	out = decodeValidPercentEscapes(out)

	return NormalisationResult{
		NormalisedText: out,
		OriginalText:   in,
	}
}

// NormaliseJSONValue walks JSON-decoded values (from encoding/json) and applies
// NormaliseText to every string, recursively through slices and maps. Numbers,
// booleans, and null are left unchanged.
func NormaliseJSONValue(v any) any {
	if v == nil {
		return nil
	}
	switch t := v.(type) {
	case string:
		return NormaliseText(t).NormalisedText
	case []interface{}:
		out := make([]interface{}, len(t))
		for i, x := range t {
			out[i] = NormaliseJSONValue(x)
		}
		return out
	case map[string]interface{}:
		m := make(map[string]interface{}, len(t))
		for k, val := range t {
			m[k] = NormaliseJSONValue(val)
		}
		return m
	default:
		return v
	}
}

func decodeValidPercentEscapes(s string) string {
	// Skip parse work when no valid escapes exist.
	if !strings.Contains(s, "%") || !validPercentEncoded.MatchString(s) {
		return s
	}

	// url.QueryUnescape treats '+' as space. Preserve literal plus signs.
	escapedPlus := strings.ReplaceAll(s, "+", "%2B")
	decoded, err := url.QueryUnescape(escapedPlus)
	if err != nil {
		// Fail safe: preserve original if decode is invalid.
		return s
	}
	return decoded
}
