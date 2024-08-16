package reporter_test

import (
	"bytes"
	"io"
	"testing"

	"github.com/google/osv-scanner/pkg/reporter"
)

func TestJSONReporter_Errorf(t *testing.T) {
	t.Parallel()

	writer := &bytes.Buffer{}
	r := reporter.NewJSONReporter(io.Discard, writer, reporter.ErrorLevel)
	text := "hello world!"

	r.Errorf("%s", text)

	if writer.String() != text {
		t.Error("Error level message should have been printed")
	}
	if !r.HasErrored() {
		t.Error("HasErrored() should have returned true")
	}
}

func TestJSONReporter_Warnf(t *testing.T) {
	t.Parallel()

	text := "hello world!"
	tests := []struct {
		lvl              reporter.VerbosityLevel
		expectedPrintout string
	}{
		{lvl: reporter.WarnLevel, expectedPrintout: text},
		{lvl: reporter.ErrorLevel, expectedPrintout: ""},
	}

	for _, test := range tests {
		writer := &bytes.Buffer{}
		r := reporter.NewJSONReporter(io.Discard, writer, test.lvl)

		r.Warnf("%s", text)

		if writer.String() != test.expectedPrintout {
			t.Errorf("expected \"%s\", got \"%s\"", test.expectedPrintout, writer.String())
		}
	}
}

func TestJSONReporter_Infof(t *testing.T) {
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
		r := reporter.NewJSONReporter(io.Discard, writer, test.lvl)

		r.Infof("%s", text)

		if writer.String() != test.expectedPrintout {
			t.Errorf("expected \"%s\", got \"%s\"", test.expectedPrintout, writer.String())
		}
	}
}

func TestJSONReporter_Verbosef(t *testing.T) {
	t.Parallel()

	text := "hello world!"
	tests := []struct {
		lvl              reporter.VerbosityLevel
		expectedPrintout string
	}{
		{lvl: reporter.VerboseLevel, expectedPrintout: text},
		{lvl: reporter.InfoLevel, expectedPrintout: ""},
	}

	for _, test := range tests {
		writer := &bytes.Buffer{}
		r := reporter.NewJSONReporter(io.Discard, writer, test.lvl)

		r.Verbosef("%s", text)

		if writer.String() != test.expectedPrintout {
			t.Errorf("expected \"%s\", got \"%s\"", test.expectedPrintout, writer.String())
		}
	}
}
