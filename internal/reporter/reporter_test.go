package reporter_test

import (
	"bytes"
	"testing"

	"github.com/google/osv-scanner/v2/internal/reporter"
	"github.com/google/osv-scanner/v2/pkg/models"
)

func TestPrintResult(t *testing.T) {
	t.Parallel()

	for _, format := range reporter.Format() {
		stdout := &bytes.Buffer{}

		err := reporter.PrintResult(&models.VulnerabilityResults{}, format, stdout, 0, false)
		if err != nil {
			t.Errorf("Reporter for '%s' format not implemented", format)
		}
	}
}

func TestPrintResult_UnsupportedFormatter(t *testing.T) {
	t.Parallel()

	stdout := &bytes.Buffer{}

	err := reporter.PrintResult(&models.VulnerabilityResults{}, "unsupported", stdout, 0, true)

	if err == nil {
		t.Errorf("Did not get expected error")
	}

	// Verify spdx-2.3-json format is also rejected
	err = reporter.PrintResult(&models.VulnerabilityResults{}, "spdx-2.3-json", stdout, 0, true)
	if err == nil {
		t.Errorf("Expected error for unsupported format spdx-2.3-json, got nil")
	}
}
