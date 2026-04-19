package kernel

import (
	"encoding/base64"
	"strings"
	"unicode"
	"github.com/eddymontana/acf-sdk/internal/protocol"
)

// HygieneCheck runs the L1 stage: it cleans the input and sets the bitmask flags.
func HygieneCheck(rawInput string) (string, protocol.StatusFlags) {
	var flags protocol.StatusFlags
	cleanOutput := strings.TrimSpace(rawInput)

	// Vibhor's Catch: Base64 False Positive Floor
	// 1. Minimum length check to avoid decoding short benign words (like "abcd")
	// 2. Decode the string
	// 3. Verify the decoded output is actually printable text (not binary garbage)
	if len(cleanOutput) >= 12 {
		decoded, err := base64.StdEncoding.DecodeString(cleanOutput)
		if err == nil && len(decoded) > 0 && isPrintable(decoded) {
			cleanOutput = string(decoded)
			flags |= protocol.FlagBase64Detected
		}
	}

	flags |= protocol.FlagUnicodeClean
	return cleanOutput, flags
}

// Helper to ensure decoded content isn't binary noise
func isPrintable(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	for _, b := range data {
		// If it's not a standard printable char, space, tab, or newline, it's likely binary
		if !unicode.IsPrint(rune(b)) && !unicode.IsSpace(rune(b)) {
			return false
		}
	}
	return true
}