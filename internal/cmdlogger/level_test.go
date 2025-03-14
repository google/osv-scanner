package cmdlogger_test

import (
	"log/slog"
	"testing"

	"github.com/google/osv-scanner/v2/internal/cmdlogger"
)

func TestParseVerbosityLevel_GivenValidLevels(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		level slog.Level
	}{
		{input: "error", level: slog.LevelError},
		{input: "warn", level: slog.LevelWarn},
		{input: "info", level: slog.LevelInfo},
	}

	for _, tt := range tests {
		lvl, err := cmdlogger.ParseLevel(tt.input)
		if err != nil {
			t.Error(err)
		}
		if lvl != tt.level {
			t.Errorf("level should be supported: %s", tt.input)
		}
	}
}

func TestParseVerbosityLevel_GivenInvalidLevels(t *testing.T) {
	t.Parallel()

	_, err := cmdlogger.ParseLevel("invalidlvl")
	if err == nil {
		t.Error("expected invalid level to be an error")
	}
}
