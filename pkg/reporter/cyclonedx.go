package reporter

import (
	"fmt"
	"github.com/google/osv-scanner/pkg/grouper"
	"io"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/google/osv-scanner/pkg/reporter/sbom"
)

type CycloneDXReporter struct {
	hasErrored bool
	stdout     io.Writer
	stderr     io.Writer
	version    sbom.CycloneDXVersion
	level      VerbosityLevel
}

func NewCycloneDXReporter(stdout, stderr io.Writer, version sbom.CycloneDXVersion, level VerbosityLevel) *CycloneDXReporter {
	return &CycloneDXReporter{
		stdout:     stdout,
		stderr:     stderr,
		hasErrored: false,
		version:    version,
		level:      level,
	}
}

func (r *CycloneDXReporter) Errorf(format string, a ...any) {
	fmt.Fprintf(r.stderr, format, a...)
	r.hasErrored = true
}

func (r *CycloneDXReporter) HasErrored() bool {
	return r.hasErrored
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

func (r *CycloneDXReporter) PrintResult(vulnerabilityResults *models.VulnerabilityResults) error {
	bomCreator := sbom.SpecVersionToBomCreator[r.version]
	resultsByPurl, errors := grouper.GroupByPURL(vulnerabilityResults.Results)

	for _, err := range errors {
		r.Warnf("Failed to parse package URL: %v", err)
	}

	bom := bomCreator(resultsByPurl)
	encoder := cyclonedx.NewBOMEncoder(r.stdout, cyclonedx.BOMFileFormatJSON)

	return encoder.Encode(bom)
}
