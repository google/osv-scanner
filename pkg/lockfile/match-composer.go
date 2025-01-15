package lockfile

import (
	"encoding/json"
	"io"
	"path/filepath"

	jsonUtils "github.com/google/osv-scanner/internal/json"
)

const composerFilename = "composer.json"

type ComposerMatcher struct{}

const (
	typeRequire = iota
	typeRequireDev
)

/*
ComposerMatcherDependencyMap is here to have access to all MatcherDependencyMap methods and at the same time having
a different type to have a clear UnmarshallJSON method for the json decoder and avoid overlaps with other matchers.
*/
type ComposerMatcherDependencyMap struct {
	MatcherDependencyMap
}

type composerFile struct {
	Require    ComposerMatcherDependencyMap `json:"require"`
	RequireDev ComposerMatcherDependencyMap `json:"require-dev"`
}

func (depMap *ComposerMatcherDependencyMap) UnmarshalJSON(bytes []byte) error {
	content := string(bytes)

	for _, pkg := range depMap.Packages {
		if depMap.RootType == typeRequireDev && pkg.BlockLocation.Line.Start != 0 {
			// If it is dev dependency definition and we already found a package location,
			// we skip it to prioritize non-dev dependencies
			continue
		}
		pkgIndexes := jsonUtils.ExtractPackageIndexes(pkg.Name, "", content)
		if len(pkgIndexes) == 0 {
			// The matcher haven't found package information, lets skip the package
			continue
		}
		depMap.UpdatePackageDetails(pkg, content, pkgIndexes, "")
	}

	return nil
}

func (matcher ComposerMatcher) GetSourceFile(lockfile DepFile) (DepFile, error) {
	lockfileDir := filepath.Dir(lockfile.Path())
	sourceFilePath := filepath.Join(lockfileDir, composerFilename)
	file, err := OpenLocalDepFile(sourceFilePath)

	return file, err
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
func (matcher ComposerMatcher) Match(sourceFile DepFile, packages []PackageDetails) error {
	content, err := io.ReadAll(sourceFile)
	if err != nil {
		return err
	}
	contentStr := string(content)
	requireLineOffset := jsonUtils.GetSectionOffset("require", contentStr)
	requireDevLineOffset := jsonUtils.GetSectionOffset("require-dev", contentStr)

	jsonFile := composerFile{
		Require: ComposerMatcherDependencyMap{
			MatcherDependencyMap: MatcherDependencyMap{
				RootType:   typeRequire,
				FilePath:   sourceFile.Path(),
				LineOffset: requireLineOffset,
				Packages:   make([]*PackageDetails, len(packages)),
			},
		},
		RequireDev: ComposerMatcherDependencyMap{
			MatcherDependencyMap: MatcherDependencyMap{
				RootType:   typeRequireDev,
				FilePath:   sourceFile.Path(),
				LineOffset: requireDevLineOffset,
				Packages:   make([]*PackageDetails, len(packages)),
			},
		},
	}

	for index := range packages {
		jsonFile.Require.Packages[index] = &packages[index]
		jsonFile.RequireDev.Packages[index] = &packages[index]
	}

	return json.Unmarshal(content, &jsonFile)
}
