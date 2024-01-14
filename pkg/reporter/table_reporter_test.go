package reporter

import (
	"bytes"
	"io"
	"testing"
)

func TestTableReporter_Errorf(t *testing.T) {
	t.Parallel()

	writer := &bytes.Buffer{}
	r := NewTableReporter(io.Discard, writer, ErrorLevel, false, 0)
	text := "hello world!"

	r.Errorf(text)

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
		lvl              VerbosityLevel
		expectedPrintout string
	}{
		{lvl: WarnLevel, expectedPrintout: text},
		{lvl: ErrorLevel, expectedPrintout: ""},
	}

	for _, test := range tests {
		writer := &bytes.Buffer{}
		r := NewTableReporter(writer, io.Discard, test.lvl, false, 0)

		r.Warnf(text)

		if writer.String() != test.expectedPrintout {
			t.Errorf("expected \"%s\", got \"%s\"", test.expectedPrintout, writer.String())
		}
	}
}

func TestTableReporter_Infof(t *testing.T) {
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
		r := NewTableReporter(writer, io.Discard, test.lvl, false, 0)

		r.Infof(text)

		if writer.String() != test.expectedPrintout {
			t.Errorf("expected \"%s\", got \"%s\"", test.expectedPrintout, writer.String())
		}
	}
}

func TestTableReporter_Verbosef(t *testing.T) {
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
		r := NewTableReporter(writer, io.Discard, test.lvl, false, 0)

		r.Verbosef(text)

		if writer.String() != test.expectedPrintout {
			t.Errorf("expected \"%s\", got \"%s\"", test.expectedPrintout, writer.String())
		}
	}
}

func TestTableReporter_CanPrintAtLevel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		lvl      VerbosityLevel
		expected bool
	}{
		{lvl: VerboseLevel, expected: true},
		{lvl: InfoLevel, expected: false},
	}

	for _, test := range tests {
		r := NewTableReporter(io.Discard, io.Discard, test.lvl, true, 0)

		actual := r.CanPrintAtLevel(VerboseLevel)

		if test.expected != actual {
			t.Errorf("Expected CanPrintAtLevel to return %t given a verbosity level of VerboseLevel", test.expected)
		}
	}
}
