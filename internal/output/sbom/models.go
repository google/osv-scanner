package sbom

import (
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"

	"github.com/CycloneDX/cyclonedx-go"
)

var SpecVersionToSpecVersion = map[models.CycloneDXVersion]cyclonedx.SpecVersion{
	models.CycloneDXVersion14: cyclonedx.SpecVersion1_4,
	models.CycloneDXVersion15: cyclonedx.SpecVersion1_5,
	models.CycloneDXVersion16: cyclonedx.SpecVersion1_6,
	models.CycloneDXVersion17: cyclonedx.SpecVersion1_7,
}

const libraryComponentType = "library"

var SeverityMapper = map[osvschema.Severity_Type]cyclonedx.ScoringMethod{
	osvschema.Severity_CVSS_V2: cyclonedx.ScoringMethodCVSSv2,
	osvschema.Severity_CVSS_V3: cyclonedx.ScoringMethodCVSSv3,
	osvschema.Severity_CVSS_V4: cyclonedx.ScoringMethodCVSSv4,
}
