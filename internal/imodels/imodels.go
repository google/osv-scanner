package imodels

import (
	"log"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/os/apk"
	"github.com/google/osv-scalibr/extractor/filesystem/os/dpkg"
	"github.com/google/osv-scalibr/extractor/filesystem/os/rpm"
	"github.com/google/osv-scalibr/extractor/filesystem/sbom/cdx"
	"github.com/google/osv-scalibr/extractor/filesystem/sbom/spdx"
	"github.com/google/osv-scanner/internal/imodels/ecosystem"
	"github.com/google/osv-scanner/internal/scalibrextract/vcs/gitrepo"
	"github.com/google/osv-scanner/pkg/models"

	scalibrosv "github.com/google/osv-scalibr/extractor/filesystem/osv"
)

var sbomExtractors = map[string]struct{}{
	spdx.Extractor{}.Name(): {},
	cdx.Extractor{}.Name():  {},
}

var gitExtractors = map[string]struct{}{
	gitrepo.Extractor{}.Name(): {},
}

var osExtractors = map[string]struct{}{
	dpkg.Extractor{}.Name(): {},
	apk.Extractor{}.Name():  {},
	rpm.Extractor{}.Name():  {},
}

// PackageInfo represents a package found during a scan. This is generally
// converted directly from the extractor.Inventory type, with some restructuring
// for easier use within osv-scanner itself.
type PackageInfo struct {
	Name      string // Name will be SourceName matching the osv-schema
	Version   string
	Ecosystem ecosystem.Parsed

	Location   string // Contains Inventory.Locations[0]
	SourceType SourceType

	Commit     string
	Repository string

	// For package sources
	DepGroups []string

	// For OS packages
	// This is usually the BinaryName, while Name is the SourceName
	OSPackageName string

	AdditionalLocations []string // Contains Inventory.Locations[1..]
}

// FromInventory converts an extractor.Inventory into a PackageInfo.
//
// For ease of use, this function does not return an error, but will log
// warnings when encountering unexpected inventory entries
func FromInventory(inventory *extractor.Inventory) PackageInfo {
	pkgInfo := PackageInfo{
		Name:                inventory.Name,
		Version:             inventory.Version,
		Location:            inventory.Locations[0],
		AdditionalLocations: inventory.Locations[1:],
		// TODO: SourceType
	}

	// Ignore this error for now as we can't do too much about an unknown ecosystem
	eco, err := ecosystem.Parse(inventory.Ecosystem())
	if err != nil {
		// TODO(v2): Replace with slog
		log.Printf("Warning: %s\n", err.Error())
	}

	pkgInfo.Ecosystem = eco

	if inventory.SourceCode != nil {
		pkgInfo.Commit = inventory.SourceCode.Commit
		pkgInfo.Repository = inventory.SourceCode.Repo
	}

	if dg, ok := inventory.Metadata.(scalibrosv.DepGroups); ok {
		pkgInfo.DepGroups = dg.DepGroups()
	}
	if inventory.Extractor != nil {
		extractorName := inventory.Extractor.Name()
		if _, ok := osExtractors[extractorName]; ok {
			pkgInfo.SourceType = SourceTypeOSPackage
		} else if _, ok := sbomExtractors[extractorName]; ok {
			pkgInfo.SourceType = SourceTypeSBOM

			// TODO (V2): SBOMs have a special case where we manually convert the PURL here
			// instead while PURL to ESI conversion is not complete
			purl := inventory.Extractor.ToPURL(inventory)

			if purl != nil {
				// Error should never happen here since the PURL is from an already parsed purl
				pi, _ := models.PURLToPackage(purl.String())
				pkgInfo.Name = pi.Name
				pkgInfo.Version = pi.Version
				parsed, err := ecosystem.Parse(pi.Ecosystem)
				if err != nil {
					// TODO: Replace with slog
					log.Printf("Warning, found unexpected ecosystem in purl %q, likely will not return any results for this package.\n", purl.String())
				}
				pkgInfo.Ecosystem = parsed
			}
		} else if _, ok := gitExtractors[extractorName]; ok {
			pkgInfo.SourceType = SourceTypeGit
		} else {
			pkgInfo.SourceType = SourceTypeProjectPackage
		}
	}

	if metadata, ok := inventory.Metadata.(*apk.Metadata); ok {
		pkgInfo.OSPackageName = metadata.PackageName
	} else if metadata, ok := inventory.Metadata.(*dpkg.Metadata); ok {
		pkgInfo.OSPackageName = metadata.PackageName
		// Debian uses source name on osv.dev
		// (fallback to using the normal name if source name is empty)
		if metadata.SourceName != "" {
			pkgInfo.Name = metadata.SourceName
		}
	} else if metadata, ok := inventory.Metadata.(*rpm.Metadata); ok {
		pkgInfo.OSPackageName = metadata.PackageName
	}

	return pkgInfo
}

// PackageScanResult represents a package and its associated vulnerabilities and licenses.
// This struct is used to store the results of a scan at a per package level.
type PackageScanResult struct {
	PackageInfo PackageInfo
	// TODO: Use osvschema.Vulnerability instead
	Vulnerabilities []models.Vulnerability
	Licenses        []models.License
	LayerDetails    *extractor.LayerDetails

	// TODO(v2):
	// SourceAnalysis *SourceAnalysis
	// Any additional scan enrichment steps
}

// SourceType categorizes packages based on the extractor that extracted
// the "source", for use in the output.
type SourceType int

const (
	SourceTypeUnknown SourceType = iota
	SourceTypeOSPackage
	SourceTypeProjectPackage
	SourceTypeSBOM
	SourceTypeGit
)
