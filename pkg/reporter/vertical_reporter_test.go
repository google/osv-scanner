package reporter_test

import (
	"bytes"
	"io"
	"log/slog"
	"testing"

	"github.com/google/osv-scanner/v2/pkg/reporter"
)

func TestVerticalReporter_Errorf(t *testing.T) {
	t.Parallel()

	writer := &bytes.Buffer{}
	r := reporter.NewVerticalReporter(io.Discard, writer, reporter.ErrorLevel, false, 0)
	text := "hello world!"

	slog.Error("%s", text)

	if writer.String() != text {
		t.Error("Error level message should have been printed")
	}
	if !r.HasErrored() {
		t.Error("HasErrored() should have returned true")
	}
}

func TestVerticalReporter_Warnf(t *testing.T) {
	t.Parallel()

	text := "hello world!"
	tests := []struct {
		lvl              reporter.VerbosityLevel
		expectedPrintout string
	}{
		{lvl: reporter.WarnLevel, expectedPrintout: text},
		{lvl: reporter.ErrorLevel, expectedPrintout: ""},
	}

	for _, tt := range tests {
		writer := &bytes.Buffer{}
		r := reporter.NewVerticalReporter(writer, io.Discard, tt.lvl, false, 0)

		r.Warnf("%s", text)

		if writer.String() != tt.expectedPrintout {
			t.Errorf("expected \"%s\", got \"%s\"", tt.expectedPrintout, writer.String())
		}
	}
}

func TestVerticalReporter_Infof(t *testing.T) {
	t.Parallel()

	text := "hello world!"
	tests := []struct {
		lvl              reporter.VerbosityLevel
		expectedPrintout string
	}{
		{lvl: reporter.InfoLevel, expectedPrintout: text},
		{lvl: reporter.WarnLevel, expectedPrintout: ""},
	}

	for _, test := range tests {
		writer := &bytes.Buffer{}
		r := reporter.NewVerticalReporter(writer, io.Discard, test.lvl, false, 0)

		r.Infof("%s", text)

		if writer.String() != test.expectedPrintout {
			t.Errorf("expected \"%s\", got \"%s\"", test.expectedPrintout, writer.String())
		}
	}
}
