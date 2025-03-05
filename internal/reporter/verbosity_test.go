package reporter_test

import (
	"log/slog"
	"testing"

	"github.com/google/osv-scanner/v2/internal/reporter"
)

func TestParseVerbosityLevel_GivenValidLevels(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input       string
		expectedLvl slog.Level
	}{
		{input: "error", expectedLvl: reporter.ErrorLevel},
		{input: "warn", expectedLvl: reporter.WarnLevel},
		{input: "info", expectedLvl: reporter.InfoLevel},
	}

	for _, tt := range tests {
		lvl, err := reporter.ParseVerbosityLevel(tt.input)
		if err != nil {
			t.Error(err)
		}
		if lvl != tt.expectedLvl {
			t.Errorf("level should be supported: %s", tt.input)
		}
	}
}

func TestParseVerbosityLevel_GivenInvalidLevels(t *testing.T) {
	t.Parallel()

	_, err := reporter.ParseVerbosityLevel("invalidlvl")
	if err == nil {
		t.Error("expected invalid level to be an error")
	}
}
