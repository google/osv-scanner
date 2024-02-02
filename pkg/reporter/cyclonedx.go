package reporter

import (
	"fmt"
	"io"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/google/osv-scanner/pkg/reporter/purl"
)

const cycloneDx14Schema = "http://cyclonedx.org/schema/bom-1.4.schema.json"

type CycloneDXReporter struct {
	hasPrintedError bool
	stdout          io.Writer
	stderr          io.Writer
}

type packageDetails struct {
	Name      string
	Version   string
	Ecosystem string
}

func NewCycloneDXReporter(stdout io.Writer, stderr io.Writer) *CycloneDXReporter {
	return &CycloneDXReporter{
		stdout:          stdout,
		stderr:          stderr,
		hasPrintedError: false,
	}
}

func (r *CycloneDXReporter) PrintError(msg string) {
	_, _ = fmt.Fprint(r.stderr, msg)
	r.hasPrintedError = true
}

func (r *CycloneDXReporter) PrintErrorf(msg string, a ...any) {
	fmt.Fprintf(r.stderr, msg, a...)
	r.hasPrintedError = true
}

func (r *CycloneDXReporter) HasPrintedError() bool {
	return r.hasPrintedError
}

func (r *CycloneDXReporter) PrintText(msg string) {
	_, _ = fmt.Fprint(r.stderr, msg)
}

func (r *CycloneDXReporter) PrintTextf(msg string, a ...any) {
	fmt.Fprintf(r.stderr, msg, a...)
}

func (r *CycloneDXReporter) PrintResult(vulnResults *models.VulnerabilityResults) error {
	bom := toCycloneDX14Bom(vulnResults.Results)
	encoder := cyclonedx.NewBOMEncoder(r.stdout, cyclonedx.BOMFileFormatJSON)

	return encoder.Encode(bom)
}

func toCycloneDX14Bom(packageSources []models.PackageSource) *cyclonedx.BOM {
	bom := cyclonedx.NewBOM()
	components := make([]cyclonedx.Component, 0)
	bom.JSONSchema = cycloneDx14Schema
	bom.SpecVersion = cyclonedx.SpecVersion1_4
	bom.Components = &components

	uniquePackages := groupByPackage(packageSources)

	for packageURL, packageDetail := range uniquePackages {
		component := cyclonedx.Component{}
		component.Name = packageDetail.Name
		component.Version = packageDetail.Version
		component.BOMRef = packageURL
		component.PackageURL = packageURL
		components = append(components, component)
	}

	return bom
}

func groupByPackage(packageSources []models.PackageSource) map[string]packageDetails {
	uniquePackages := make(map[string]packageDetails)

	for _, packageSource := range packageSources {
		for _, pkg := range packageSource.Packages {
			packageURL := purl.From(pkg.Package)
			if packageURL == nil {
				continue
			}
			_, packageExists := uniquePackages[packageURL.ToString()]
			if !packageExists {
				newPackage := packageDetails{
					Name:      pkg.Package.Name,
					Version:   pkg.Package.Version,
					Ecosystem: pkg.Package.Ecosystem,
				}
				uniquePackages[packageURL.ToString()] = newPackage
			}
		}
	}

	return uniquePackages
}
