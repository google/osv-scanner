package output

import (
	"github.com/google/osv-scanner/pkg/models"
	"golang.org/x/exp/slices"
)

type pkgWithSource struct {
	Package models.PackageInfo
	Source  models.SourceInfo
}

type groupedVulns struct {
	DisplayID    string
	PkgSource    map[pkgWithSource]struct{}
	AliasedVulns map[string]models.Vulnerability
}

// groupFixedVersions builds the fixed versions for each ID Group, with keys formatted like so:
// `Source:ID`
func groupFixedVersions(flattened []models.VulnerabilityFlattened) map[string][]string {
	groupFixedVersions := map[string][]string{}

	// Get the fixed versions indexed by each group of vulnerabilities
	// Prepend source path as same vulnerability in two projects should be counted twice
	// Remember to sort and compact before displaying later
	for _, vf := range flattened {
		groupIdx := vf.Source.String() + ":" + vf.GroupInfo.IndexString()
		pkg := models.Package{
			Ecosystem: models.Ecosystem(vf.Package.Ecosystem),
			Name:      vf.Package.Name,
		}
		groupFixedVersions[groupIdx] =
			append(groupFixedVersions[groupIdx], vf.Vulnerability.FixedVersions()[pkg]...)
	}

	// Remove duplicates
	for k := range groupFixedVersions {
		fixedVersions := groupFixedVersions[k]
		slices.Sort(fixedVersions)
		groupFixedVersions[k] = slices.Compact(fixedVersions)
	}

	return groupFixedVersions
}

func groupByVulnGroups(vulns *models.VulnerabilityResults) map[string]*groupedVulns {
	// Map of Vuln IDs to
	results := map[string]*groupedVulns{}

	for _, res := range vulns.Results {
		for _, pkg := range res.Packages {
			for _, gi := range pkg.Groups {
				var data *groupedVulns
				// See if this vulnerability group already exists (from another package or source)
				for _, id := range gi.IDs {
					existingData, ok := results[id]
					if ok {
						data = existingData
						break
					}
				}
				// If not create this group
				if data == nil {
					data = &groupedVulns{
						DisplayID:    slices.MinFunc(gi.IDs, idSortFunc),
						PkgSource:    make(map[pkgWithSource]struct{}),
						AliasedVulns: make(map[string]models.Vulnerability),
					}
				} else {
					// Edge case can happen here where vulnerabilities in an alias group affect different packages
					// And that the vuln of one package happen to have a higher priority DisplayID, it will not be selected.
					//
					// This line fixes that
					data.DisplayID = slices.MinFunc(append(gi.IDs, data.DisplayID), idSortFunc)
				}
				// Point all the IDs of the same group to the same data, either newly created or existing
				for _, id := range gi.IDs {
					results[id] = data
				}
			}
			for _, v := range pkg.Vulnerabilities {
				newPkgSource := pkgWithSource{
					Package: pkg.Package,
					Source:  res.Source,
				}
				entry := results[v.ID]
				entry.PkgSource[newPkgSource] = struct{}{}
				entry.AliasedVulns[v.ID] = v
			}
		}
	}

	return results
}
