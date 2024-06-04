package sbom

import (
	"fmt"
	"io"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/google/osv-scanner/pkg/models"
)

func ToCycloneDX15Bom(stderr io.Writer, uniquePackages map[string]models.PackageDetails) *cyclonedx.BOM {
	bom := cyclonedx.NewBOM()
	components := make([]cyclonedx.Component, 0)
	bom.JSONSchema = cycloneDx15Schema
	bom.SpecVersion = cyclonedx.SpecVersion1_5

	for packageURL, packageDetail := range uniquePackages {
		component := cyclonedx.Component{}
		occurrences := make([]cyclonedx.EvidenceOccurrence, len(packageDetail.Locations))
		component.Name = packageDetail.Name
		component.BOMRef = packageURL
		component.PackageURL = packageURL
		component.Type = componentType
		component.Evidence = &cyclonedx.Evidence{Occurrences: &occurrences}

		if packageDetail.Version != "" {
			component.Version = packageDetail.Version
		}

		for index, packageLocations := range packageDetail.Locations {
			jsonLocation, err := packageLocations.MarshalToJSONString()
			if err != nil {
				_, _ = fmt.Fprintf(stderr, "An error occurred when creating the jsonLocation structure : %v", err.Error())
				continue
			}

			occurrence := cyclonedx.EvidenceOccurrence{
				Location: jsonLocation,
			}
			(*component.Evidence.Occurrences)[index] = occurrence
		}
		components = append(components, component)
	}
	bom.Components = &components

	return bom
}
