// Package sbom provides functionality to generate SBOMs from scan results.
package sbom

import (
	"github.com/google/osv-scanner/v2/pkg/models"

	"github.com/CycloneDX/cyclonedx-go"
)

func ToCycloneDX14Bom(uniquePackages map[string]models.PackageVulns) *cyclonedx.BOM {
	bom := buildCycloneDXBom(uniquePackages)
	bom.JSONSchema = cycloneDx14Schema
	bom.SpecVersion = cyclonedx.SpecVersion1_4

	return bom
}
