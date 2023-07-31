package reporter_test

import (
	"bytes"
	"testing"

	"github.com/google/osv-scanner/pkg/reporter"
)

func TestGetReporter(t *testing.T) {
	t.Parallel()

	for _, format := range reporter.Format() {
		stdout := &bytes.Buffer{}
		stderr := &bytes.Buffer{}

		_, err := reporter.New(format, stdout, stderr, 0)
		if err != nil {
			t.Errorf("Reporter for '%s' format not implemented", format)
		}
	}
}
