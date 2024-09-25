package sbom

import (
	"github.com/CycloneDX/cyclonedx-go"
	"github.com/google/osv-scanner/pkg/models"
)

func ToCycloneDX15Bom(uniquePackages map[string]models.PackageVulns, artifacts []models.ScannedArtifact) *cyclonedx.BOM {
	bom := buildCycloneDXBom(uniquePackages, artifacts, onComponentCreated)
	bom.JSONSchema = cycloneDx15Schema
	bom.SpecVersion = cyclonedx.SpecVersion1_5

	return bom
}

func onComponentCreated(component *cyclonedx.Component, details models.PackageVulns) {
	occurrences := make([]cyclonedx.EvidenceOccurrence, 0)

	for _, packageLocations := range details.Locations {
		cleanedLocation := packageLocations.Clean()

		if cleanedLocation == nil {
			continue
		}
		jsonLocation, err := packageLocations.MarshalToJSONString()

		if err != nil {
			continue
		}
		occurrence := cyclonedx.EvidenceOccurrence{
			Location: jsonLocation,
		}
		occurrences = append(occurrences, occurrence)
	}
	if len(occurrences) > 0 {
		component.Evidence = &cyclonedx.Evidence{Occurrences: &occurrences}
	}
}
