package reporter

import (
	"fmt"
	"io"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/google/osv-scanner/pkg/reporter/sbom"
)

type CycloneDXReporter struct {
	hasErrored bool
	stdout     io.Writer
	stderr     io.Writer
	level      VerbosityLevel
	version    sbom.CycloneDXVersion
}

func NewCycloneDXReporter(stdout io.Writer, stderr io.Writer, version sbom.CycloneDXVersion, level VerbosityLevel) *CycloneDXReporter {
	return &CycloneDXReporter{
		stdout:     stdout,
		stderr:     stderr,
		hasErrored: false,
		level:      level,
		version:    version,
	}
}

func (r *CycloneDXReporter) Errorf(msg string, a ...any) {
	_, _ = fmt.Fprintf(r.stderr, msg, a...)
	r.hasErrored = true
}

func (r *CycloneDXReporter) Warnf(format string, a ...any) {
	if WarnLevel <= r.level {
		fmt.Fprintf(r.stderr, format, a...)
	}
}

func (r *CycloneDXReporter) Infof(format string, a ...any) {
	if InfoLevel <= r.level {
		fmt.Fprintf(r.stderr, format, a...)
	}
}

func (r *CycloneDXReporter) Verbosef(format string, a ...any) {
	if VerboseLevel <= r.level {
		fmt.Fprintf(r.stderr, format, a...)
	}
}

func (r *CycloneDXReporter) HasErrored() bool {
	return r.hasErrored
}

func (r *CycloneDXReporter) PrintResult(vulnerabilityResults *models.VulnerabilityResults) error {
	bomCreator := sbom.SpecVersionToBomCreator[r.version]
	bom := bomCreator(r.stderr, vulnerabilityResults.ResultsByPURL)
	encoder := cyclonedx.NewBOMEncoder(r.stdout, cyclonedx.BOMFileFormatJSON)

	return encoder.Encode(bom)
}
