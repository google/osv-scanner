package output

import (
	"errors"
	"io"
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/google/osv-scanner/internal/output/sbom"
	"github.com/google/osv-scanner/internal/utility/purl"
	"github.com/google/osv-scanner/pkg/models"
)

// This method creates a CycloneDX SBOM and returns it. Error being returned here are from components being filtered during PURL grouping
func CreateCycloneDXBOM(vulnResult *models.VulnerabilityResults, cycloneDXVersion models.CycloneDXVersion) (*cyclonedx.BOM, error) {
	bomCreator := sbom.SpecVersionToBomCreator[cycloneDXVersion]
	resultsByPurl, errs := purl.Group(vulnResult.Results)

	return bomCreator(resultsByPurl, vulnResult.Artifacts), errors.Join(errs...)
}

// PrintCycloneDXResults writes results to the provided writer in CycloneDX format
func PrintCycloneDXResults(vulnResult *models.VulnerabilityResults, cycloneDXVersion models.CycloneDXVersion, outputWriter io.Writer) error {
	bom, errs := CreateCycloneDXBOM(vulnResult, cycloneDXVersion)
	encoder := cyclonedx.NewBOMEncoder(outputWriter, cyclonedx.BOMFileFormatJSON)
	encoder.SetPretty(testing.Testing())

	if bom == nil {
		return errs
	}
	encodingErr := encoder.EncodeVersion(bom, bom.SpecVersion)

	return errors.Join(encodingErr, errs)
}
