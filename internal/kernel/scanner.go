package kernel

import (
	"regexp"
	"strings"
	"unicode"
	"github.com/eddymontana/acf-sdk/internal/protocol"
)

var (
	// Simplified patterns because we pre-process the text
	sqlInjection  = regexp.MustCompile(`(?i)(SELECT|INSERT|DELETE|DROP|UPDATE|OR1=1|--|/\*)`)
	promptEvasion = regexp.MustCompile(`(?i)(ignoreprevious|systemprompt|danmode|asanai|youarenow|disregard)`)
)

func LexicalScan(input string) protocol.StatusFlags {
	var flags protocol.StatusFlags

	// Vibhor's Catch: Punctuation obfuscation (d.a.n m.o.d.e)
	// We strip all non-alphanumeric characters to flatten the text before scanning
	processed := stripPunctuation(input)

	if sqlInjection.MatchString(processed) {
		flags |= protocol.FlagSqlInjectionDetected
	}

	if promptEvasion.MatchString(processed) {
		flags |= protocol.FlagPromptInjectionDetected
	}

	return flags
}

// stripPunctuation removes everything except letters and numbers
func stripPunctuation(s string) string {
	var result strings.Builder
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			result.WriteRune(unicode.ToLower(r))
		}
	}
	return result.String()
}