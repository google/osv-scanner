package sbom

import (
	"github.com/CycloneDX/cyclonedx-go"
	"github.com/google/osv-scanner/v2/pkg/models"
)

func ToCycloneDX16Bom(uniquePackages map[string]models.PackageVulns) *cyclonedx.BOM {
	bom := buildCycloneDXBom(uniquePackages)
	bom.JSONSchema = cycloneDx16Schema
	bom.SpecVersion = cyclonedx.SpecVersion1_6

	return bom
}
