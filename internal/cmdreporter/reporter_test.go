package cmdreporter_test

import (
	"bytes"
	"testing"

	"github.com/google/osv-scanner/v2/internal/cmdreporter"
	"github.com/google/osv-scanner/v2/pkg/models"
)

func TestPrintResult(t *testing.T) {
	t.Parallel()

	for _, format := range cmdreporter.Format() {
		stdout := &bytes.Buffer{}

		err := cmdreporter.PrintResult(&models.VulnerabilityResults{}, format, stdout, 0)
		if err != nil {
			t.Errorf("Reporter for '%s' format not implemented", format)
		}
	}
}

func TestPrintResult_UnsupportedFormatter(t *testing.T) {
	t.Parallel()

	stdout := &bytes.Buffer{}

	err := cmdreporter.PrintResult(&models.VulnerabilityResults{}, "unsupported", stdout, 0)

	if err == nil {
		t.Errorf("Did not get expected error")
	}
}
