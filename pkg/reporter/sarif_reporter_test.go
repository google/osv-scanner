package reporter

import (
	"bytes"
	"io"
	"testing"
)

func TestSarifReporter_Errorf(t *testing.T) {
	t.Parallel()

	writer := &bytes.Buffer{}
	r := NewSarifReporter(io.Discard, writer, ErrorLevel)
	text := "hello world!"

	r.Errorf(text)

	if writer.String() != text {
		t.Error("Error level message should have been printed")
	}
	if !r.HasErrored() {
		t.Error("HasErrored() should have returned true")
	}
}

func TestSarifReporter_Warnf(t *testing.T) {
	t.Parallel()

	text := "hello world!"
	tests := []struct {
		lvl              VerbosityLevel
		expectedPrintout string
	}{
		{lvl: WarnLevel, expectedPrintout: text},
		{lvl: ErrorLevel, expectedPrintout: ""},
	}

	for _, test := range tests {
		writer := &bytes.Buffer{}
		r := NewSarifReporter(io.Discard, writer, test.lvl)

		r.Warnf(text)

		if writer.String() != test.expectedPrintout {
			t.Errorf("expected \"%s\", got \"%s\"", test.expectedPrintout, writer.String())
		}
	}
}

func TestSarifReporter_Infof(t *testing.T) {
	t.Parallel()

	text := "hello world!"
	tests := []struct {
		lvl              VerbosityLevel
		expectedPrintout string
	}{
		{lvl: InfoLevel, expectedPrintout: text},
		{lvl: WarnLevel, expectedPrintout: ""},
	}

	for _, test := range tests {
		writer := &bytes.Buffer{}
		r := NewSarifReporter(io.Discard, writer, test.lvl)

		r.Infof(text)

		if writer.String() != test.expectedPrintout {
			t.Errorf("expected \"%s\", got \"%s\"", test.expectedPrintout, writer.String())
		}
	}
}

func TestSarifReporter_Verbosef(t *testing.T) {
	t.Parallel()

	text := "hello world!"
	tests := []struct {
		lvl              VerbosityLevel
		expectedPrintout string
	}{
		{lvl: VerboseLevel, expectedPrintout: text},
		{lvl: InfoLevel, expectedPrintout: ""},
	}

	for _, test := range tests {
		writer := &bytes.Buffer{}
		r := NewSarifReporter(io.Discard, writer, test.lvl)

		r.Verbosef(text)

		if writer.String() != test.expectedPrintout {
			t.Errorf("expected \"%s\", got \"%s\"", test.expectedPrintout, writer.String())
		}
	}
}
