package sbom

import (
	"github.com/CycloneDX/cyclonedx-go"
	"github.com/google/osv-scanner/v2/pkg/models"
)

func ToCycloneDX17Bom(uniquePackages map[string]models.PackageVulns) *cyclonedx.BOM {
	bom := buildCycloneDXBom(uniquePackages)
	bom.JSONSchema = cycloneDx17Schema
	bom.SpecVersion = cyclonedx.SpecVersion1_7

	return bom
}
