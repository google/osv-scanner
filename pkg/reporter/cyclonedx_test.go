package reporter_test

import (
	"bytes"
	"io"
	"testing"

	"github.com/google/osv-scanner/pkg/models"
	"github.com/google/osv-scanner/pkg/reporter"
)

func TestCycloneDXReporter_Errorf(t *testing.T) {
	t.Parallel()

	tests := []struct {
		version models.CycloneDXVersion
	}{
		{version: models.CycloneDXVersion14},
		{version: models.CycloneDXVersion15},
	}

	text := "hello world!"
	for _, tt := range tests {
		writer := &bytes.Buffer{}
		r := reporter.NewCycloneDXReporter(io.Discard, writer, tt.version, reporter.ErrorLevel)

		r.Errorf("%s", text)

		if writer.String() != text {
			t.Error("Error level message should have been printed")
		}
		if !r.HasErrored() {
			t.Error("HasErrored() should have returned true")
		}
	}
}

func TestCycloneDXReporter_Warnf(t *testing.T) {
	t.Parallel()

	text := "hello world!"
	tests := []struct {
		lvl              reporter.VerbosityLevel
		expectedPrintout string
		version          models.CycloneDXVersion
	}{
		{lvl: reporter.WarnLevel, expectedPrintout: text, version: models.CycloneDXVersion14},
		{lvl: reporter.WarnLevel, expectedPrintout: text, version: models.CycloneDXVersion15},
		{lvl: reporter.ErrorLevel, expectedPrintout: "", version: models.CycloneDXVersion14},
		{lvl: reporter.ErrorLevel, expectedPrintout: "", version: models.CycloneDXVersion15},
	}

	for _, tt := range tests {
		writer := &bytes.Buffer{}
		r := reporter.NewCycloneDXReporter(io.Discard, writer, tt.version, tt.lvl)

		r.Warnf("%s", text)

		if writer.String() != tt.expectedPrintout {
			t.Errorf("expected \"%s\", got \"%s\"", tt.expectedPrintout, writer.String())
		}
	}
}

func TestCycloneDXReporter_Infof(t *testing.T) {
	t.Parallel()

	text := "hello world!"
	tests := []struct {
		lvl              reporter.VerbosityLevel
		expectedPrintout string
		version          models.CycloneDXVersion
	}{
		{lvl: reporter.InfoLevel, expectedPrintout: text, version: models.CycloneDXVersion14},
		{lvl: reporter.InfoLevel, expectedPrintout: text, version: models.CycloneDXVersion15},
		{lvl: reporter.WarnLevel, expectedPrintout: "", version: models.CycloneDXVersion14},
		{lvl: reporter.WarnLevel, expectedPrintout: "", version: models.CycloneDXVersion15},
	}

	for _, tt := range tests {
		writer := &bytes.Buffer{}
		r := reporter.NewCycloneDXReporter(io.Discard, writer, tt.version, tt.lvl)

		r.Infof("%s", text)

		if writer.String() != tt.expectedPrintout {
			t.Errorf("expected \"%s\", got \"%s\"", tt.expectedPrintout, writer.String())
		}
	}
}

func TestCycloneDXReporter_Verbosef(t *testing.T) {
	t.Parallel()
	text := "hello world!"
	tests := []struct {
		version          models.CycloneDXVersion
		lvl              reporter.VerbosityLevel
		expectedPrintout string
	}{
		{
			version:          models.CycloneDXVersion14,
			lvl:              reporter.VerboseLevel,
			expectedPrintout: text,
		},
		{
			version:          models.CycloneDXVersion15,
			lvl:              reporter.VerboseLevel,
			expectedPrintout: text,
		},
		{
			version:          models.CycloneDXVersion14,
			lvl:              reporter.InfoLevel,
			expectedPrintout: "",
		},
		{
			version:          models.CycloneDXVersion15,
			lvl:              reporter.InfoLevel,
			expectedPrintout: "",
		},
	}

	for _, tt := range tests {
		writer := &bytes.Buffer{}
		r := reporter.NewCycloneDXReporter(io.Discard, writer, tt.version, tt.lvl)

		r.Verbosef("%s", text)

		if writer.String() != tt.expectedPrintout {
			t.Errorf("expected \"%s\", got \"%s\"", tt.expectedPrintout, writer.String())
		}
	}
}
