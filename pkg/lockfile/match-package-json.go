package lockfile

import (
	"encoding/json"
	"io"

	jsonUtils "github.com/google/osv-scanner/internal/json"
)

const (
	typeDependencies = iota
	typeDevDependencies
	typeOptionalDependencies
)

type PackageJSONMatcher struct{}

/*
packageJSONDependencyMap is here to have access to all MatcherDependencyMap methods and at the same time having
a different type to have a clear UnmarshallJSON method for the json decoder and avoid overlaps with other matchers.
*/
type packageJSONDependencyMap struct {
	MatcherDependencyMap
}

type packageJSONFile struct {
	Dependencies         packageJSONDependencyMap `json:"dependencies"`
	DevDependencies      packageJSONDependencyMap `json:"devDependencies"`
	OptionalDependencies packageJSONDependencyMap `json:"optionalDependencies"`
}

func (m PackageJSONMatcher) GetSourceFile(lockfile DepFile) (DepFile, error) {
	return lockfile.Open("package.json")
}

func (depMap *packageJSONDependencyMap) UnmarshalJSON(data []byte) error {
	content := string(data)

	for _, pkg := range depMap.Packages {
		var pkgIndexes []int

		for _, targetedVersion := range pkg.TargetVersions {
			pkgIndexes = jsonUtils.ExtractPackageIndexes(pkg.Name, targetedVersion, content)
			if len(pkgIndexes) > 0 {
				break
			}
		}

		if len(pkgIndexes) == 0 {
			// The matcher haven't found package information, lets skip it
			continue
		}
		var depGroup string
		if depMap.RootType == typeDependencies {
			depGroup = "prod"
		} else if depMap.RootType == typeDevDependencies {
			depGroup = "dev"
		} else if depMap.RootType == typeOptionalDependencies {
			depGroup = "optional"
		}

		if (depMap.RootType == typeDevDependencies || depMap.RootType == typeOptionalDependencies) && pkg.BlockLocation.Line.Start != 0 {
			// If it is a dev or optional dependency definition and we already found a package location,
			// we skip it to prioritize non-dev dependencies
			pkgIndexes = []int{}
		}
		depMap.UpdatePackageDetails(pkg, content, pkgIndexes, depGroup)
	}

	return nil
}

/*
Match works by leveraging the json decoder to only parse json sections of interest (e.g dependencies)
Whenever the json decoder try to deserialize a file, it will look at json sections it needs to deserialize
and then call the proper UnmarshallJSON method of the type. As the JSON decoder expect us to only deserialize it,
not trying to find the exact location in the file of the content, it does not provide us buffer information (offset, file path, etc...)

To work around this limitation, we are pre-filling the structure with all the field we will need during the deserialization :
  - The root type to know which json section we are deserializing
  - The file path to be able to fill properly location fields of PackageDetails
  - The line offset to be able to compute the line of any found dependencies in the file
  - And a list of pointer to the original PackageDetails extracted by the parser to be able to modify them with the json section content
*/
func (m PackageJSONMatcher) Match(sourcefile DepFile, packages []PackageDetails) error {
	content, err := io.ReadAll(sourcefile)
	if err != nil {
		return err
	}
	contentStr := string(content)
	dependenciesLineOffset := jsonUtils.GetSectionOffset("dependencies", contentStr)
	devDependenciesLineOffset := jsonUtils.GetSectionOffset("devDependencies", contentStr)
	optionalDepenenciesLineOffset := jsonUtils.GetSectionOffset("optionalDependencies", contentStr)

	jsonFile := packageJSONFile{
		Dependencies: packageJSONDependencyMap{
			MatcherDependencyMap: MatcherDependencyMap{
				RootType:   typeDependencies,
				FilePath:   sourcefile.Path(),
				LineOffset: dependenciesLineOffset,
			},
		},
		DevDependencies: packageJSONDependencyMap{
			MatcherDependencyMap: MatcherDependencyMap{
				RootType:   typeDevDependencies,
				FilePath:   sourcefile.Path(),
				LineOffset: devDependenciesLineOffset,
			},
		},
		OptionalDependencies: packageJSONDependencyMap{
			MatcherDependencyMap: MatcherDependencyMap{
				RootType:   typeOptionalDependencies,
				FilePath:   sourcefile.Path(),
				LineOffset: optionalDepenenciesLineOffset,
			},
		},
	}
	packagesPtr := make([]*PackageDetails, len(packages))
	for index := range packages {
		packagesPtr[index] = &packages[index]
	}
	jsonFile.Dependencies.Packages = packagesPtr
	jsonFile.DevDependencies.Packages = packagesPtr
	jsonFile.OptionalDependencies.Packages = packagesPtr

	return json.Unmarshal(content, &jsonFile)
}

var _ Matcher = PackageJSONMatcher{}
