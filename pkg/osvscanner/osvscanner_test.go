package osvscanner_test

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/google/osv-scanner/v2/pkg/osvscanner"
)

// TestDoScan_GemfileLock tests that DoScan can scan a Gemfile.lock,
// and that it does not return an error if no vulnerabilities are found.
func TestDoScan_LogHandlerOverride(t *testing.T) {
	actions := osvscanner.ScannerActions{
		DirectoryPaths: []string{"../../cmd/osv-scanner/testdata/locks-many/Gemfile.lock"},
	}

	output := bytes.NewBuffer(nil)
	slog.SetDefault(slog.New(slog.NewTextHandler(output, nil)))

	_, _ = osvscanner.DoScan(actions)

	// Test that normally logging is output correctly to the default slog handler.
	if output.Len() == 0 {
		t.Errorf("output.Len() = %d, want %d", output.Len(), 0)
	}

	// Clear output buffer for next run
	output.Truncate(0)

	// Test if output is overridden
	altOutput := bytes.NewBuffer(nil)
	osvscanner.SetLogger(slog.NewTextHandler(altOutput, nil))

	_, _ = osvscanner.DoScan(actions)

	// Normal slog output should be empty.
	if output.Len() != 0 {
		t.Errorf("output.Len() = %d, want %d", output.Len(), 0)
		t.Errorf("Got: %s", output.String())
	}

	// altOutput should contain data now instead.
	if altOutput.Len() == 0 {
		t.Errorf("altOutput.Len() = %d, want %d", altOutput.Len(), 0)
	}
}
