package imodels

import (
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/os/apk"
	"github.com/google/osv-scalibr/extractor/filesystem/os/dpkg"
	"github.com/google/osv-scalibr/extractor/filesystem/os/rpm"
	"github.com/google/osv-scanner/internal/imodels/ecosystem"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"

	scalibrosv "github.com/google/osv-scalibr/extractor/filesystem/osv"
)

// // TODO: This will be removed and replaced with the V2 model
// type ScannedPackage struct {
// 	PURL        string
// 	Name        string
// 	Ecosystem   lockfile.Ecosystem
// 	Commit      string
// 	Version     string
// 	Source      models.SourceInfo
// 	ImageOrigin *models.ImageOriginDetails
// 	DepGroups   []string
// }

type PackageInfo struct {
	Name       string // Name will be SourceName matching the osv-schema
	Version    string
	Ecosystem  ecosystem.Parsed
	Location   string // Contains Inventory.Locations[0]
	SourceType SourceType

	Commit     string
	Repository string

	// For package sources
	DepGroups []string

	// For OS packages
	OSPackageName string

	AdditionalLocations []string // Contains Inventory.Locations[1..]
}

func FromInventory(inventory *extractor.Inventory) PackageInfo {
	pkgInfo := PackageInfo{
		Name:                inventory.Name,
		Version:             inventory.Version,
		Ecosystem:           ecosystem.Parse(inventory.Ecosystem()),
		Location:            inventory.Locations[0],
		AdditionalLocations: inventory.Locations[1:],
		// TODO: SourceType
	}

	if inventory.SourceCode != nil {
		pkgInfo.Commit = inventory.SourceCode.Commit
		pkgInfo.Repository = inventory.SourceCode.Repo
	}

	if dg, ok := inventory.Metadata.(scalibrosv.DepGroups); ok {
		pkgInfo.DepGroups = dg.DepGroups()
	}

	// TODO: Add entry for every ecosystem osvschema supports (Bitnami?)
	// TODO: Add SourceName into pkgInfo Name
	switch pkgInfo.Ecosystem.Ecosystem {
	case osvschema.EcosystemAlpine:
		metadata := inventory.Metadata.(*apk.Metadata)
		pkgInfo.OSPackageName = metadata.PackageName
	case osvschema.EcosystemDebian:
	case osvschema.EcosystemUbuntu:
		metadata := inventory.Metadata.(*dpkg.Metadata)
		pkgInfo.OSPackageName = metadata.PackageName
	case osvschema.EcosystemRedHat:
	case osvschema.EcosystemRockyLinux:
	case osvschema.EcosystemAlmaLinux:
		metadata := inventory.Metadata.(*rpm.Metadata)
		pkgInfo.OSPackageName = metadata.PackageName
	}

	return pkgInfo
}

type PackageScanResult struct {
	PackageInfo PackageInfo
	// TODO: Use osvschema.Vulnerability instead
	Vulnerabilities    []models.Vulnerability
	Licenses           []models.License
	ImageOriginLayerID string

	// TODO:
	// SourceAnalysis *SourceAnalysis
	// Any additional scan enrichment steps
}

type ImageMetadata struct {
	// TODO:
	// OS
	// BaseImage
	// LayerMetadata []LayerMetadata
}

type SourceType int
