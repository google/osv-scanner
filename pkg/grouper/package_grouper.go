package grouper

import (
	"github.com/google/osv-scanner/pkg/models"
	"github.com/google/osv-scanner/pkg/reporter/purl"
)

func GroupByPURL(packageSources []models.PackageSource) map[string]models.PackageDetails {
	uniquePackages := make(map[string]models.PackageDetails)

	for _, packageSource := range packageSources {
		for _, pkg := range packageSource.Packages {
			packageURL := purl.From(pkg.Package)
			if packageURL == nil {
				continue
			}
			existingPackage, packageExists := uniquePackages[packageURL.ToString()]
			isLocationExtracted := isLocationExtractedSuccessfully(pkg.Package)
			location := extractPackageLocations(packageSource.Source, pkg.Package)

			if packageExists && isLocationExtracted {
				// Package exists and location exists we need to add a location
				existingPackage.Locations = append(existingPackage.Locations, location)
				uniquePackages[packageURL.ToString()] = existingPackage
			} else if !packageExists {
				// The package does not exists we need to add it
				// Create a new package and update the map
				newPackage := models.PackageDetails{
					Name:      pkg.Package.Name,
					Version:   pkg.Package.Version,
					Ecosystem: pkg.Package.Ecosystem,
					Locations: make([]models.PackageLocations, 0),
				}

				if isLocationExtracted {
					// We add location only if it has been extracted successfully
					newPackage.Locations = append(newPackage.Locations, location)
				}
				uniquePackages[packageURL.ToString()] = newPackage
			}
		}
	}

	return uniquePackages
}

func isLocationExtractedSuccessfully(pkgInfos models.PackageInfo) bool {
	return pkgInfos.Line.Start > 0 && pkgInfos.Line.End > 0 && pkgInfos.Column.Start > 0 && pkgInfos.Column.End > 0
}

func extractPackageLocations(pkgSource models.SourceInfo, pkgInfos models.PackageInfo) models.PackageLocations {
	return models.PackageLocations{
		Block: models.PackageLocation{
			Filename:    pkgSource.Path,
			LineStart:   pkgInfos.Line.Start,
			LineEnd:     pkgInfos.Line.End,
			ColumnStart: pkgInfos.Column.Start,
			ColumnEnd:   pkgInfos.Column.End,
		},
	}
}
