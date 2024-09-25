package sbom

import (
	"github.com/google/osv-scanner/pkg/models"

	"github.com/CycloneDX/cyclonedx-go"
)

func ToCycloneDX14Bom(uniquePackages map[string]models.PackageVulns, artifacts []models.ScannedArtifact) *cyclonedx.BOM {
	bom := buildCycloneDXBom(uniquePackages, artifacts, func(_ *cyclonedx.Component, _ models.PackageVulns) {})
	bom.JSONSchema = cycloneDx14Schema
	bom.SpecVersion = cyclonedx.SpecVersion1_4

	return bom
}
