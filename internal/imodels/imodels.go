// Package imodels defines internal models for osv-scanner.
package imodels

import (
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/enricher/vulnmatch/osvutil"
	"github.com/google/osv-scalibr/extractor"
	apkmetadata "github.com/google/osv-scalibr/extractor/filesystem/os/apk/metadata"
	dpkgmetadata "github.com/google/osv-scalibr/extractor/filesystem/os/dpkg/metadata"
	rpmmetadata "github.com/google/osv-scalibr/extractor/filesystem/os/rpm/metadata"
	"github.com/google/osv-scalibr/inventory/osvecosystem"
	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/language/osv/osvscannerjson"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/vcs/gitrepo"
	"github.com/google/osv-scanner/v2/internal/scalibrplugin"

	scalibrosv "github.com/google/osv-scalibr/extractor/filesystem/osv"
	"github.com/google/osv-scanner/v2/pkg/models"
)

var gitExtractors = map[string]struct{}{
	gitrepo.Name: {},
}

// ParsePackage parses SCALIBR package metadata into OSV normalized package.
// This does not affect matching. It is only used for reporting and filtering.
func ParsePackage(pkg *extractor.Package) osvutil.NormalizedPackage {
	parsed := osvutil.ParsePackage(pkg)

	if metadata, ok := pkg.Metadata.(*osvscannerjson.Metadata); ok {
		newEco, err := osvecosystem.Parse(metadata.Ecosystem)
		if err != nil {
			cmdlogger.Warnf("Warning: error parsing osvscanner.json ecosystem: %s", err.Error())
		} else if !newEco.IsEmpty() {
			parsed.Ecosystem = newEco
		}
	}

	return parsed
}

func Location(pkg *extractor.Package) string {
	// Use the scan root, defaulting to / for virtual filesystems (e.g. container images)
	scanRoot := pkg.ScanRoot
	if scanRoot == "" {
		scanRoot = "/"
	}

	return filepath.Join(scanRoot, pkg.Location.PathOrEmpty())
}

func SourceType(pkg *extractor.Package) models.SourceType {
	for _, extractorName := range pkg.Plugins {
		if strings.HasPrefix(extractorName, "os/") {
			return models.SourceTypeOSPackage
		} else if _, ok := scalibrplugin.ExtractorPresets["sbom"][extractorName]; ok {
			return models.SourceTypeSBOM
		} else if _, ok := gitExtractors[extractorName]; ok {
			return models.SourceTypeGit
		} else if _, ok := scalibrplugin.ExtractorPresets["artifact"][extractorName]; ok {
			return models.SourceTypeArtifact
		} else if _, ok := scalibrplugin.ExtractorPresets["lockfile"][extractorName]; ok {
			return models.SourceTypeProjectPackage
		}
	}

	return models.SourceTypeUnknown
}

func DepGroups(pkg *extractor.Package) []string {
	if dg, ok := pkg.Metadata.(scalibrosv.DepGroups); ok {
		return dg.DepGroups()
	}

	return []string{}
}

func OSPackageName(pkg *extractor.Package) string {
	if metadata, ok := pkg.Metadata.(*apkmetadata.Metadata); ok {
		return metadata.PackageName
	}
	if metadata, ok := pkg.Metadata.(*dpkgmetadata.Metadata); ok {
		return metadata.PackageName
	}
	if metadata, ok := pkg.Metadata.(*rpmmetadata.Metadata); ok {
		return metadata.PackageName
	}

	return ""
}
