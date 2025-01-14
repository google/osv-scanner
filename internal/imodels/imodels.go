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
	"github.com/ossf/osv-schema/bindings/go/osvschema"

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

// PackageInfo provides getter functions for commonly used fields of inventory
// and applies transformations when required for use in osv-scanner
type PackageInfo struct {
	// purlCache is used to cache the special case for SBOMs where we convert Name, Version, and Ecosystem from purls
	// extracted from the SBOM
	purlCache *models.PackageInfo
	*extractor.Inventory
}

func (pkg *PackageInfo) Name() string {
	// TODO(v2): SBOM special case, to be removed after PURL to ESI conversion within each extractor is complete
	if pkg.purlCache != nil {
		return pkg.purlCache.Name
	}

	if pkg.Ecosystem().Ecosystem == osvschema.EcosystemGo && pkg.Inventory.Name == "go" {
		return "stdlib"
	}

	if metadata, ok := pkg.Inventory.Metadata.(*dpkg.Metadata); ok {
		// Debian uses source name on osv.dev
		// (fallback to using the normal name if source name is empty)
		if metadata.SourceName != "" {
			return metadata.SourceName
		}
	}

	if metadata, ok := pkg.Inventory.Metadata.(*apk.Metadata); ok {
		if metadata.OriginName != "" {
			return metadata.OriginName
		}
	}

	return pkg.Inventory.Name
}

func (pkg *PackageInfo) Ecosystem() ecosystem.Parsed {
	ecosystemStr := pkg.Inventory.Ecosystem()

	// TODO(v2): SBOM special case, to be removed after PURL to ESI conversion within each extractor is complete
	if pkg.purlCache != nil {
		ecosystemStr = pkg.purlCache.Ecosystem
	}

	// TODO: Maybe cache this parse result
	eco, err := ecosystem.Parse(ecosystemStr)
	if err != nil {
		// Ignore this error for now as we can't do too much about an unknown ecosystem
		// TODO(v2): Replace with slog
		log.Printf("Warning: %s\n", err.Error())
	}

	return eco
}

func (pkg *PackageInfo) Version() string {
	// TODO(v2): SBOM special case, to be removed after PURL to ESI conversion within each extractor is complete
	if pkg.purlCache != nil {
		return pkg.purlCache.Version
	}

	return pkg.Inventory.Version
}

func (pkg *PackageInfo) Location() string {
	if len(pkg.Inventory.Locations) > 0 {
		return pkg.Inventory.Locations[0]
	}

	return ""
}

func (pkg *PackageInfo) Commit() string {
	if pkg.Inventory.SourceCode != nil {
		return pkg.Inventory.SourceCode.Commit
	}

	return ""
}

func (pkg *PackageInfo) SourceType() SourceType {
	if pkg.Inventory.Extractor == nil {
		return SourceTypeUnknown
	}

	extractorName := pkg.Inventory.Extractor.Name()
	if _, ok := osExtractors[extractorName]; ok {
		return SourceTypeOSPackage
	} else if _, ok := sbomExtractors[extractorName]; ok {
		return SourceTypeSBOM
	} else if _, ok := gitExtractors[extractorName]; ok {
		return SourceTypeGit
	}

	return SourceTypeProjectPackage
}

func (pkg *PackageInfo) DepGroups() []string {
	if dg, ok := pkg.Inventory.Metadata.(scalibrosv.DepGroups); ok {
		return dg.DepGroups()
	}

	return []string{}
}

func (pkg *PackageInfo) OSPackageName() string {
	if metadata, ok := pkg.Inventory.Metadata.(*apk.Metadata); ok {
		return metadata.PackageName
	}
	if metadata, ok := pkg.Inventory.Metadata.(*dpkg.Metadata); ok {
		return metadata.PackageName
	}
	if metadata, ok := pkg.Inventory.Metadata.(*rpm.Metadata); ok {
		return metadata.PackageName
	}

	return ""
}

// FromInventory converts an extractor.Inventory into a PackageInfo.
func FromInventory(inventory *extractor.Inventory) PackageInfo {
	pi := PackageInfo{Inventory: inventory}
	if pi.SourceType() == SourceTypeSBOM {
		purl := pi.Inventory.Extractor.ToPURL(pi.Inventory)
		if purl != nil {
			purlCache, _ := models.PURLToPackage(purl.String())
			pi.purlCache = &purlCache
		}
	}

	return pi
}

// PackageScanResult represents a package and its associated vulnerabilities and licenses.
// This struct is used to store the results of a scan at a per package level.
type PackageScanResult struct {
	PackageInfo PackageInfo
	// TODO: Use osvschema.Vulnerability instead
	Vulnerabilities []*models.Vulnerability
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
