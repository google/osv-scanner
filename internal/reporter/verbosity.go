package reporter

import (
	"fmt"
	"log/slog"
	"strings"
)

// VerbosityLevel is used to determine what amount of information should be given in OSV-Scanner's runtime.
type VerbosityLevel slog.Level

const (
	// ErrorLevel is for unexpected problems that require attention.
	ErrorLevel = slog.LevelError
	// WarnLevel is for indicating potential issues or something that should be brought to the attention of users.
	WarnLevel = slog.LevelWarn
	// InfoLevel is for general information about what OSV-Scanner is doing during its runtime.
	InfoLevel = slog.LevelInfo
)

var verbosityLevels = []string{
	"error",
	"warn",
	"info",
}

func VerbosityLevels() []string {
	return verbosityLevels
}

func ParseVerbosityLevel(text string) (slog.Level, error) {
	switch text {
	case "error":
		return ErrorLevel, nil
	case "warn":
		return WarnLevel, nil
	case "info":
		return InfoLevel, nil
	default:
		return 0, fmt.Errorf("invalid verbosity level \"%s\" - must be one of: %s", text, strings.Join(VerbosityLevels(), ", "))
	}
}
