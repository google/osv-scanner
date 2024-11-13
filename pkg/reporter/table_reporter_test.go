package reporter_test

import (
	"bytes"
	"io"
	"testing"

	"github.com/google/osv-scanner/pkg/reporter"
)

func TestTableReporter_Errorf(t *testing.T) {
	t.Parallel()

	writer := &bytes.Buffer{}
	r := reporter.NewTableReporter(io.Discard, writer, reporter.ErrorLevel, false, 0)
	text := "hello world!"

	r.Errorf("%s", text)

	if writer.String() != text {
		t.Error("Error level message should have been printed")
	}
	if !r.HasErrored() {
		t.Error("HasErrored() should have returned true")
	}
}

func TestTableReporter_Warnf(t *testing.T) {
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
		r := reporter.NewTableReporter(writer, io.Discard, tt.lvl, false, 0)

		r.Warnf("%s", text)

		if writer.String() != tt.expectedPrintout {
			t.Errorf("expected \"%s\", got \"%s\"", tt.expectedPrintout, writer.String())
		}
	}
}

func TestTableReporter_Infof(t *testing.T) {
	t.Parallel()

	text := "hello world!"
	tests := []struct {
		lvl              reporter.VerbosityLevel
		expectedPrintout string
	}{
		{lvl: reporter.InfoLevel, expectedPrintout: text},
		{lvl: reporter.WarnLevel, expectedPrintout: ""},
	}

	for _, tt := range tests {
		writer := &bytes.Buffer{}
		r := reporter.NewTableReporter(writer, io.Discard, tt.lvl, false, 0)

		r.Infof("%s", text)

		if writer.String() != tt.expectedPrintout {
			t.Errorf("expected \"%s\", got \"%s\"", tt.expectedPrintout, writer.String())
		}
	}
}

func TestTableReporter_Verbosef(t *testing.T) {
	t.Parallel()

	text := "hello world!"
	tests := []struct {
		lvl              reporter.VerbosityLevel
		expectedPrintout string
	}{
		{lvl: reporter.VerboseLevel, expectedPrintout: text},
		{lvl: reporter.InfoLevel, expectedPrintout: ""},
	}

	for _, tt := range tests {
		writer := &bytes.Buffer{}
		r := reporter.NewTableReporter(writer, io.Discard, tt.lvl, false, 0)

		r.Verbosef("%s", text)

		if writer.String() != tt.expectedPrintout {
			t.Errorf("expected \"%s\", got \"%s\"", tt.expectedPrintout, writer.String())
		}
	}
}
