// normalise.go - Stage 2 of the pipeline.
// Produces canonical text for scanning by applying (in order):
//  1. Unicode NFKC normalisation
//  2. Invisible-format stripping
//  3. Bounded chained decode attempts (URL, Base64, hex)
//  4. Unicode NFKC normalisation again
//  5. Invisible-format stripping again
//  6. Leetspeak cleaning
//
// The result is written to rc.CanonicalText. The original rc.Payload is never
// mutated. Normalise never emits a hard block signal - it is a pure transform.
package pipeline

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"github.com/acf-sdk/sidecar/pkg/riskcontext"
)

const (
	maxDecodeRounds      = 4
	minEncodedTextLength = 8
)

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

// payloadText recursively extracts text from nested payload structures.
// Map keys are traversed in sorted order so canonical text stays stable across
// runs even when Go map iteration order changes.
func payloadText(payload any) string {
	parts := make([]string, 0, 8)
	collectPayloadText(&parts, payload)
	return strings.Join(parts, " ")
}

func collectPayloadText(parts *[]string, payload any) {
	if payload == nil {
		return
	}

	switch v := payload.(type) {
	case string:
		appendTextPart(parts, v)
		return
	case []any:
		for _, item := range v {
			collectPayloadText(parts, item)
		}
		return
	case map[string]any:
		for _, key := range sortedMapKeys(v) {
			collectPayloadText(parts, v[key])
		}
		return
	}

	rv := reflect.ValueOf(payload)
	if !rv.IsValid() {
		return
	}

	switch rv.Kind() {
	case reflect.Map:
		if rv.Type().Key().Kind() != reflect.String {
			appendTextPart(parts, fmt.Sprintf("%v", payload))
			return
		}
		keys := make([]string, 0, rv.Len())
		for _, key := range rv.MapKeys() {
			keys = append(keys, key.String())
		}
		sort.Strings(keys)
		for _, key := range keys {
			collectPayloadText(parts, rv.MapIndex(reflect.ValueOf(key)).Interface())
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < rv.Len(); i++ {
			collectPayloadText(parts, rv.Index(i).Interface())
		}
	case reflect.String:
		appendTextPart(parts, rv.String())
	default:
		appendTextPart(parts, fmt.Sprintf("%v", payload))
	}
}

func appendTextPart(parts *[]string, text string) {
	if trimmed := strings.TrimSpace(text); trimmed != "" {
		*parts = append(*parts, trimmed)
	}
}

func sortedMapKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// normalise applies all transforms to text and returns the canonical form.
func normalise(text string) string {
	text = applyNFKC(text)
	text = stripZeroWidth(text)

	for round := 0; round < maxDecodeRounds; round++ {
		changed := false

		if decoded, ok := tryDecodeURL(text); ok {
			text = decoded
			changed = true
		}
		if decoded, ok := tryDecodeBase64(text); ok {
			text = decoded
			changed = true
		}
		if decoded, ok := tryDecodeHex(text); ok {
			text = decoded
			changed = true
		}
		if !changed {
			break
		}

		// Re-apply canonicalisation after each successful decode step so the next
		// round sees normalized text rather than attacker-controlled wrappers.
		text = applyNFKC(text)
		text = stripZeroWidth(text)
	}

	text = applyNFKC(text)
	text = stripZeroWidth(text)
	return cleanLeetspeak(text)
}

func tryDecodeURL(text string) (string, bool) {
	if !strings.Contains(text, "%") {
		return text, false
	}

	decoded, err := url.PathUnescape(text)
	if err != nil || decoded == text {
		return text, false
	}

	return decoded, true
}

func tryDecodeBase64(text string) (string, bool) {
	candidate := strings.TrimSpace(text)
	if !looksLikeBase64Candidate(candidate) {
		return text, false
	}

	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.RawURLEncoding,
	} {
		decoded, err := enc.DecodeString(candidate)
		if err != nil {
			continue
		}
		if result, ok := decodedText(decoded); ok {
			return result, true
		}
	}

	return text, false
}

func looksLikeBase64Candidate(candidate string) bool {
	if len(candidate) < minEncodedTextLength || len(candidate)%4 == 1 {
		return false
	}

	for _, r := range candidate {
		if unicode.IsSpace(r) {
			return false
		}
		if !isBase64Rune(r) {
			return false
		}
	}

	return true
}

func isBase64Rune(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z':
		return true
	case r >= 'A' && r <= 'Z':
		return true
	case r >= '0' && r <= '9':
		return true
	case r == '+' || r == '/' || r == '=' || r == '-' || r == '_':
		return true
	default:
		return false
	}
}

func tryDecodeHex(text string) (string, bool) {
	candidate := strings.TrimSpace(text)
	candidate = strings.TrimPrefix(candidate, "0x")
	candidate = strings.TrimPrefix(candidate, "0X")
	if !looksLikeHexCandidate(candidate) {
		return text, false
	}

	decoded, err := hex.DecodeString(candidate)
	if err != nil {
		return text, false
	}
	if result, ok := decodedText(decoded); ok {
		return result, true
	}

	return text, false
}

func looksLikeHexCandidate(candidate string) bool {
	if len(candidate) < minEncodedTextLength || len(candidate)%2 != 0 {
		return false
	}

	for _, r := range candidate {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		case r >= 'A' && r <= 'F':
		default:
			return false
		}
	}

	return true
}

func decodedText(decoded []byte) (string, bool) {
	result := string(decoded)
	if !isPrintableUTF8(result) {
		return "", false
	}
	return result, true
}

// isPrintableUTF8 returns true if s is valid UTF-8 containing printable
// characters (including standard whitespace) and no null bytes.
func isPrintableUTF8(s string) bool {
	if !utf8.ValidString(s) || strings.ContainsRune(s, 0) {
		return false
	}

	printable := 0
	for _, r := range s {
		switch r {
		case '\n', '\r', '\t':
			printable++
			continue
		}
		if !unicode.IsPrint(r) {
			return false
		}
		printable++
	}

	return printable > 0
}

// applyNFKC applies Unicode NFKC normalisation, which decomposes compatibility
// characters and recomposes them in canonical form. This collapses ligatures,
// full-width characters, and other visual equivalents.
func applyNFKC(text string) string {
	return norm.NFKC.String(text)
}

// stripZeroWidth removes invisible format characters commonly used to hide
// malicious content in otherwise readable text while preserving ordinary
// whitespace such as spaces and newlines.
func stripZeroWidth(text string) string {
	return strings.Map(func(r rune) rune {
		if isInvisibleFormatRune(r) {
			return -1
		}
		return r
	}, text)
}

func isInvisibleFormatRune(r rune) bool {
	if unicode.In(r, unicode.Cf) {
		return true
	}

	switch r {
	case '\u034f': // combining grapheme joiner
		return true
	default:
		return false
	}
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
