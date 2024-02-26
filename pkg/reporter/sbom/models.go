package sbom

import (
	"io"

	"github.com/google/osv-scanner/pkg/models"

	"github.com/CycloneDX/cyclonedx-go"
)

type CycloneDXVersion int

const (
	CycloneDXVersion14 CycloneDXVersion = iota
	CycloneDXVersion15
)

var SpecVersionToBomCreator = map[CycloneDXVersion]BomCreator{
	CycloneDXVersion14: ToCycloneDX14Bom,
	CycloneDXVersion15: ToCycloneDX15Bom,
}

type BomCreator func(stderr io.Writer, packageSources map[string]models.PackageDetails) *cyclonedx.BOM

const (
	cycloneDx14Schema = "http://cyclonedx.org/schema/bom-1.4.schema.json"
	cycloneDx15Schema = "http://cyclonedx.org/schema/bom-1.5.schema.json"
)

const componentType = "library"
