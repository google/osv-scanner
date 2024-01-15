package reporter_test

import (
	"testing"

	"github.com/google/osv-scanner/pkg/reporter"
)

func TestParseVerbosityLevel_GivenValidLevels(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input       string
		expectedLvl reporter.VerbosityLevel
	}{
		{input: "error", expectedLvl: reporter.ErrorLevel},
		{input: "warn", expectedLvl: reporter.WarnLevel},
		{input: "info", expectedLvl: reporter.InfoLevel},
		{input: "verbose", expectedLvl: reporter.VerboseLevel},
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
