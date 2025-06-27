package sbom

import (
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"

	"github.com/CycloneDX/cyclonedx-go"
)

var SpecVersionToBomCreator = map[models.CycloneDXVersion]CycloneDXBomCreator{
	models.CycloneDXVersion14: ToCycloneDX14Bom,
	models.CycloneDXVersion15: ToCycloneDX15Bom,
	models.CycloneDXVersion16: ToCycloneDX16Bom,
}

type CycloneDXBomCreator func(packageSources map[string]models.PackageVulns) *cyclonedx.BOM

const (
	cycloneDx14Schema = "http://cyclonedx.org/schema/bom-1.4.schema.json"
	cycloneDx15Schema = "http://cyclonedx.org/schema/bom-1.5.schema.json"
	cycloneDx16Schema = "http://cyclonedx.org/schema/bom-1.6.schema.json"
)

const libraryComponentType = "library"

var SeverityMapper = map[osvschema.SeverityType]cyclonedx.ScoringMethod{
	osvschema.SeverityCVSSV2: cyclonedx.ScoringMethodCVSSv2,
	osvschema.SeverityCVSSV3: cyclonedx.ScoringMethodCVSSv3,
	osvschema.SeverityCVSSV4: cyclonedx.ScoringMethodCVSSv4,
}
