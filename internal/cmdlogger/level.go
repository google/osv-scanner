package cmdlogger

import (
	"fmt"
	"log/slog"
	"strings"
)

var levels = []string{
	"error",
	"warn",
	"info",
}

func Levels() []string {
	return levels
}

func ParseLevel(text string) (slog.Level, error) {
	switch text {
	case "error":
		return slog.LevelError, nil
	case "warn":
		return slog.LevelWarn, nil
	case "info":
		return slog.LevelInfo, nil
	default:
		return slog.LevelInfo, fmt.Errorf("invalid verbosity level \"%s\" - must be one of: %s", text, strings.Join(Levels(), ", "))
	}
}
