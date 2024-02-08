package sbom

import (
	"io"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/google/osv-scanner/pkg/models"
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

type BomCreator func(stderr io.Writer, packageSources []models.PackageSource) *cyclonedx.BOM

type packageDetails struct {
	Name      string
	Version   string
	Ecosystem string
	Locations []packageLocations
}

type packageLocation struct {
	Filename    string `json:"file_name"`
	LineStart   int    `json:"line_start"`
	LineEnd     int    `json:"line_end"`
	ColumnStart int    `json:"column_start"`
	ColumnEnd   int    `json:"column_end"`
}

type packageLocations struct {
	Block packageLocation `json:"block"`
}

const (
	cycloneDx14Schema = "http://cyclonedx.org/schema/bom-1.4.schema.json"
	cycloneDx15Schema = "http://cyclonedx.org/schema/bom-1.5.schema.json"
)

const componentType = "library"
