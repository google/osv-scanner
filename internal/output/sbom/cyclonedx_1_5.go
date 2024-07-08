package sbom

import (
	"github.com/CycloneDX/cyclonedx-go"
	"github.com/google/osv-scanner/pkg/models"
)

func ToCycloneDX15Bom(uniquePackages map[string]models.PackageVulns) *cyclonedx.BOM {
	bom := buildCycloneDXBom(uniquePackages)
	bom.JSONSchema = cycloneDx15Schema
	bom.SpecVersion = cyclonedx.SpecVersion1_5

	return bom
}
