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
			location := extractPackageLocations(packageSource.Source, pkg.Package)
			if packageExists {
				// Package exists we need to add a location
				existingPackage.Locations = append(existingPackage.Locations, location)
				uniquePackages[packageURL.ToString()] = existingPackage
			} else {
				// Create a new package and update the map
				newPackage := models.PackageDetails{
					Name:      pkg.Package.Name,
					Version:   pkg.Package.Version,
					Ecosystem: pkg.Package.Ecosystem,
					Locations: make([]models.PackageLocations, 1),
				}
				newPackage.Locations[0] = location
				uniquePackages[packageURL.ToString()] = newPackage
			}
		}
	}

	return uniquePackages
}

func extractPackageLocations(pkgSource models.SourceInfo, pkgInfos models.PackageInfo) models.PackageLocations {
	return models.PackageLocations{
		Block: &models.PackageLocation{
			Filename:    pkgSource.Path,
			LineStart:   pkgInfos.Line.Start,
			LineEnd:     pkgInfos.Line.End,
			ColumnStart: pkgInfos.Column.Start,
			ColumnEnd:   pkgInfos.Column.End,
		},
	}
}
