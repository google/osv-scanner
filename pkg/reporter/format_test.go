package reporter_test

import (
	"bytes"
	"testing"

	"github.com/google/osv-scanner/pkg/reporter"
)

func TestNew(t *testing.T) {
	t.Parallel()

	for _, format := range reporter.Format() {
		stdout := &bytes.Buffer{}
		stderr := &bytes.Buffer{}

		_, err := reporter.New(format, stdout, stderr, reporter.InfoLevel, 0)
		if err != nil {
			t.Errorf("Reporter for '%s' format not implemented", format)
		}
	}
}

func TestNew_UnsupportedFormatter(t *testing.T) {
	t.Parallel()

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	_, err := reporter.New("unsupported", stdout, stderr, reporter.InfoLevel, 0)

	if err == nil {
		t.Errorf("Did not get expected error")
	}
}
