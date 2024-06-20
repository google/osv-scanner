package purl

import (
	"slices"

	"github.com/google/osv-scanner/pkg/models"
)

// Group takes a list of packages, and group them in a map using their PURL
// as key It is a way to have only one instance of each package, even if some has
// been detected multiple times. If the function fails to create a PURL from a
// package, it generates an error, continue to group the other packages and
// reports both grouped packages and all generated errors.
func Group(packageSources []models.PackageSource) (map[string]models.PackageVulns, []error) {
	uniquePackages := make(map[string]models.PackageVulns)
	errors := make([]error, 0)

	for _, packageSource := range packageSources {
		for _, pkg := range packageSource.Packages {
			packageURL, err := From(pkg.Package)
			if err != nil {
				errors = append(errors, err)
				continue
			}
			packageVulns, packageExists := uniquePackages[packageURL.ToString()]
			if packageExists {
				// Entry already exists, we need to merge slices which are not expected to be the exact same
				packageVulns.DepGroups = append(packageVulns.DepGroups, pkg.DepGroups...)

				uniquePackages[packageURL.ToString()] = packageVulns
			} else {
				// Entry does not exists yet, lets create it
				newPackageVuln := models.PackageVulns{
					Package: models.PackageInfo{
						Name:      pkg.Package.Name,
						Version:   pkg.Package.Version,
						Ecosystem: pkg.Package.Ecosystem,
					},
					DepGroups:         slices.Clone(pkg.DepGroups),
					Vulnerabilities:   slices.Clone(pkg.Vulnerabilities),
					Groups:            slices.Clone(pkg.Groups),
					Licenses:          slices.Clone(pkg.Licenses),
					LicenseViolations: slices.Clone(pkg.LicenseViolations),
				}

				uniquePackages[packageURL.ToString()] = newPackageVuln
			}
		}
	}

	return uniquePackages, errors
}
