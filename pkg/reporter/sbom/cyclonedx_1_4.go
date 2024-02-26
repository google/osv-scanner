package sbom

import (
	"io"

	"github.com/google/osv-scanner/pkg/grouper"

	"github.com/google/osv-scanner/pkg/models"

	"github.com/CycloneDX/cyclonedx-go"
)

func ToCycloneDX14Bom(_ io.Writer, packageSources []models.PackageSource) *cyclonedx.BOM {
	bom := cyclonedx.NewBOM()
	components := make([]cyclonedx.Component, 0)
	bom.JSONSchema = cycloneDx14Schema
	bom.SpecVersion = cyclonedx.SpecVersion1_4

	uniquePackages := grouper.GroupByPURL(packageSources)

	for packageURL, packageDetail := range uniquePackages {
		component := cyclonedx.Component{}
		component.Name = packageDetail.Name
		component.Version = packageDetail.Version
		component.BOMRef = packageURL
		component.PackageURL = packageURL
		component.Type = componentType
		components = append(components, component)
	}
	bom.Components = &components

	return bom
}
