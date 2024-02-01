package reporter

import (
	"fmt"
	"strings"
)

// VerbosityLevel is used to determine what amount of information should be given in OSV-Scanner's runtime.
type VerbosityLevel uint8

const (
	// ErrorLevel is for unexpected problems that require attention.
	ErrorLevel = iota
	// WarnLevel is for indicating potential issues or something that should be brought to the attention of users.
	WarnLevel
	// InfoLevel is for general information about what OSV-Scanner is doing during its runtime.
	InfoLevel
	// VerboseLevel is for providing even more information compared to InfoLevel about the inner workings of OSV-Scanner.
	VerboseLevel
)

var verbosityLevels = []string{
	"error",
	"warn",
	"info",
	"verbose",
}

func VerbosityLevels() []string {
	return verbosityLevels
}

func ParseVerbosityLevel(text string) (VerbosityLevel, error) {
	switch text {
	case "error":
		return ErrorLevel, nil
	case "warn":
		return WarnLevel, nil
	case "info":
		return InfoLevel, nil
	case "verbose":
		return VerboseLevel, nil
	default:
		var l VerbosityLevel

		return l, fmt.Errorf("invalid verbosity level \"%s\" - must be one of: %s", text, strings.Join(VerbosityLevels(), ", "))
	}
}
