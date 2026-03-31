package protocol

type StatusFlags uint16

const (
	FlagNone                   StatusFlags = 0
	FlagBase64Detected         StatusFlags = 1 << 0
	FlagUnicodeClean           StatusFlags = 1 << 1
	FlagSqlInjectionDetected   StatusFlags = 1 << 2 // L2 Flag
	FlagPromptInjectionDetected StatusFlags = 1 << 3 // L2 Flag
)

// HasFlag checks if a specific bit is set
func (f StatusFlags) HasFlag(flag StatusFlags) bool {
	return f&flag != 0
}