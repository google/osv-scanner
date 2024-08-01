package sbom

import (
	"github.com/CycloneDX/cyclonedx-go"
	"github.com/google/osv-scanner/pkg/models"
)

func ToCycloneDX15Bom(uniquePackages map[string]models.PackageVulns) *cyclonedx.BOM {
	bom := buildCycloneDXBom(uniquePackages, onComponentCreated)
	bom.JSONSchema = cycloneDx15Schema
	bom.SpecVersion = cyclonedx.SpecVersion1_5

	return bom
}

func onComponentCreated(component *cyclonedx.Component, details models.PackageVulns) {
	occurrences := make([]cyclonedx.EvidenceOccurrence, len(details.Locations))
	component.Evidence = &cyclonedx.Evidence{Occurrences: &occurrences}

	for index, packageLocations := range details.Locations {
		jsonLocation, err := packageLocations.MarshalToJSONString()

		if err != nil {
			continue
		}
		occurrence := cyclonedx.EvidenceOccurrence{
			Location: jsonLocation,
		}
		(*component.Evidence.Occurrences)[index] = occurrence
	}
}
