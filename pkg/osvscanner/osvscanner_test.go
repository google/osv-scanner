package osvscanner_test

import (
	"bytes"
	"errors"
	"log/slog"
	"testing"

	"github.com/google/osv-scanner/v2/pkg/osvscanner"
)

// TestDoScan_LogHandlerOverride tests that the SetLogger override works correctly
//
//nolint:paralleltest // No parallel test since slog.SetDefault sets global behavior
func TestDoScan_LogHandlerOverride(t *testing.T) {
	// Restore default slog behavior at the ned of the test
	defaultHandler := slog.Default()
	defer func() {
		slog.SetDefault(defaultHandler)
	}()

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

func TestDoContainerScan_EmptyImage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		actions osvscanner.ScannerActions
	}{
		{
			name:    "empty actions",
			actions: osvscanner.ScannerActions{},
		},
		{
			name: "image archive with empty image",
			actions: osvscanner.ScannerActions{
				IsImageArchive: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := osvscanner.DoContainerScan(tt.actions)
			if !errors.Is(err, osvscanner.ErrNoImageSpecified) {
				t.Errorf("DoContainerScan() error = %v, want %v", err, osvscanner.ErrNoImageSpecified)
			}
		})
	}
}
