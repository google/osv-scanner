package sbom

import (
	"github.com/google/osv-scanner/pkg/models"

	"github.com/CycloneDX/cyclonedx-go"
)

var SpecVersionToBomCreator = map[models.CycloneDXVersion]CycloneDXBomCreator{
	models.CycloneDXVersion14: ToCycloneDX14Bom,
	models.CycloneDXVersion15: ToCycloneDX15Bom,
}

type CycloneDXBomCreator func(packageSources map[string]models.PackageVulns) *cyclonedx.BOM

const (
	cycloneDx14Schema = "http://cyclonedx.org/schema/bom-1.4.schema.json"
	cycloneDx15Schema = "http://cyclonedx.org/schema/bom-1.5.schema.json"
)

const libraryComponentType = "library"

var SeverityMapper = map[models.SeverityType]cyclonedx.ScoringMethod{
	models.SeverityCVSSV2: cyclonedx.ScoringMethodCVSSv2,
	models.SeverityCVSSV3: cyclonedx.ScoringMethodCVSSv3,
	models.SeverityCVSSV4: cyclonedx.ScoringMethodCVSSv4,
}
