package lockfile

import (
	"strings"

	"github.com/google/osv-scanner/pkg/models"
	"golang.org/x/exp/maps"
)

// TODO : THIS FILE SHOULD BE MOVED TO ITS OWN INTERNAL PACKAGE ONCE WE CUT ORIGINAL REPO LINKS

/*
MatcherDependencyMap is a helper structure meant to represent metadata needed in order to extract data during a custom json Unmarshal process
Typical usage will be in a structure representing the file to deserialize a specific section from it (package.json dependencies section for example).
It helps us to pass data from the context and have a specific type to create a custom UnmarshalJson method.

rootType defines what section we are currently deserializing (as all section will go through the same unmarshal method)
filePath defines which file we are parsing, it is used to define the location of a package
lineOffset defines the character offset between the start of the file and the start of the section
packages is the array of packages we extracted from the parser we need to update with matcher information

For an example, you can check out match-composer.go or match-package-json.go
*/
type MatcherDependencyMap struct {
	RootType   int
	FilePath   string
	LineOffset int
	Packages   []*PackageDetails
}

/*
UpdatePackageDetails updates the PackageDetails structure with the following information :

- Is the package direct (if we find it in a matcher, it is always direct)
- Package location in the matched file (block, name and version)
- new dependency group (when not empty)

pkg is the PackageDetails structure to update
content is the full file content as string
indexes is a [6]int array representing block, name and version location offsets (as defined by ExtractPackageIndexes)
depGroup represent the new dependency group to add
*/
func (depMap *MatcherDependencyMap) UpdatePackageDetails(pkg *PackageDetails, content string, indexes []int, depGroup string) {
	if pkg == nil {
		return
	}

	pkg.IsDirect = true
	if len(indexes) > 0 {
		depMap.updatePackageDetailLocation(pkg, content, indexes)
	}
	if len(depGroup) > 0 {
		pkg.DepGroups = append(pkg.DepGroups, depGroup)
		propagateDepGroups(pkg, make(map[*PackageDetails]struct{}))
	}
}

func (depMap *MatcherDependencyMap) updatePackageDetailLocation(pkg *PackageDetails, content string, indexes []int) {
	lineStart := depMap.LineOffset + strings.Count(content[:indexes[0]], "\n")
	lineStartIndex := strings.LastIndex(content[:indexes[0]], "\n")
	lineEnd := depMap.LineOffset + strings.Count(content[:indexes[1]], "\n")
	lineEndIndex := strings.LastIndex(content[:indexes[1]], "\n")

	pkg.BlockLocation = models.FilePosition{
		Filename: depMap.FilePath,
		Line: models.Position{
			Start: lineStart + 1,
			End:   lineEnd + 1,
		},
		Column: models.Position{
			Start: indexes[0] - lineStartIndex,
			End:   indexes[1] - lineEndIndex,
		},
	}

	pkg.NameLocation = &models.FilePosition{
		Filename: depMap.FilePath,
		Line: models.Position{
			Start: lineStart + 1,
			End:   lineStart + 1,
		},
		Column: models.Position{
			Start: indexes[2] - lineStartIndex,
			End:   indexes[3] - lineStartIndex,
		},
	}

	pkg.VersionLocation = &models.FilePosition{
		Filename: depMap.FilePath,
		Line: models.Position{
			Start: lineEnd + 1,
			End:   lineEnd + 1,
		},
		Column: models.Position{
			Start: indexes[4] - lineEndIndex,
			End:   indexes[5] - lineEndIndex,
		},
	}
}

/*
propagateDepGroups traverse the tree of dependency from the top level parent
and to merge child dependency group with its parent to have a complete array of all dependency groups found.
*/
func propagateDepGroups(root *PackageDetails, visitedMap map[*PackageDetails]struct{}) {
	if _, visited := visitedMap[root]; visited {
		return
	}
	visitedMap[root] = struct{}{}
	newDepGroups := make(map[string]bool)
	for _, group := range root.DepGroups {
		newDepGroups[group] = true
	}

	for _, deps := range root.Dependencies {
		for _, group := range deps.DepGroups {
			newDepGroups[group] = true
		}
		deps.DepGroups = maps.Keys(newDepGroups)
		propagateDepGroups(deps, visitedMap)
	}
}
