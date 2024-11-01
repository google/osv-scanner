package lockfile

import (
	"encoding/json"
	"io"
	"path/filepath"
	"strings"

	"github.com/google/osv-scanner/internal/cachedregexp"
	"github.com/google/osv-scanner/pkg/models"
)

const composerFilename = "composer.json"

type ComposerMatcher struct{}

const (
	typeRequire = iota
	typeRequireDev
)

type dependencyMap struct {
	rootType   int
	filePath   string
	lineOffset int
	packages   []*PackageDetails
}

type composerFile struct {
	Require    dependencyMap `json:"require"`
	RequireDev dependencyMap `json:"require-dev"`
}

func (depMap *dependencyMap) UnmarshalJSON(bytes []byte) error {
	content := string(bytes)

	for _, pkg := range depMap.packages {
		if depMap.rootType == typeRequireDev && pkg.BlockLocation.Line.Start != 0 {
			// If it is dev dependency definition and we already found a package location,
			// we skip it to prioritize non-dev dependencies
			continue
		}
		pkgIndexes := depMap.extractPackageIndexes(pkg.Name, content)
		if len(pkgIndexes) == 0 {
			// The matcher haven't found package information, lets skip the package
			continue
		}
		depMap.updatePackageDetails(pkg, content, pkgIndexes)
	}

	return nil
}

func (matcher ComposerMatcher) GetSourceFile(lockfile DepFile) (DepFile, error) {
	lockfileDir := filepath.Dir(lockfile.Path())
	sourceFilePath := filepath.Join(lockfileDir, composerFilename)
	file, err := OpenLocalDepFile(sourceFilePath)

	return file, err
}

func (matcher ComposerMatcher) Match(sourceFile DepFile, packages []PackageDetails) error {
	content, err := io.ReadAll(sourceFile)
	if err != nil {
		return err
	}
	contentStr := string(content)
	requireIndex := cachedregexp.MustCompile("\"require\"\\s*:\\s*{").FindStringIndex(contentStr)
	requireDevIndex := cachedregexp.MustCompile("\"require-dev\"\\s*:\\s*{").FindStringIndex(contentStr)
	requireLineOffset, requireDevLineOffset := 0, 0

	if len(requireIndex) > 1 {
		requireLineOffset = strings.Count(contentStr[:requireIndex[1]], "\n")
	}
	if len(requireDevIndex) > 1 {
		requireDevLineOffset = strings.Count(contentStr[:requireDevIndex[1]], "\n")
	}

	jsonFile := composerFile{
		Require: dependencyMap{
			rootType:   typeRequire,
			filePath:   sourceFile.Path(),
			lineOffset: requireLineOffset,
			packages:   make([]*PackageDetails, len(packages)),
		},
		RequireDev: dependencyMap{
			rootType:   typeRequireDev,
			filePath:   sourceFile.Path(),
			lineOffset: requireDevLineOffset,
			packages:   make([]*PackageDetails, len(packages)),
		},
	}

	for index := range packages {
		jsonFile.Require.packages[index] = &packages[index]
		jsonFile.RequireDev.packages[index] = &packages[index]
	}

	return json.Unmarshal(content, &jsonFile)
}

/*
This method find where a package is defined in the composer.json file. It returns the block indexes along with
name and version. Composer does not accept a package being declared twice in the same block, so this method will always return zero or one row

The expected result is a [6]int, with the following structure :
- index 0/1 represents block start/end
- index 2/3 represents name start/end
- index 4/5 represents version start/end
*/
func (depMap *dependencyMap) extractPackageIndexes(pkgName string, content string) []int {
	pkgMatcher := cachedregexp.MustCompile(".*\"(?P<pkgName>" + pkgName + ")\"\\s*:\\s*\"(?P<version>.*)\"")
	result := pkgMatcher.FindAllStringSubmatchIndex(content, -1)

	if len(result) == 0 || len(result[0]) < 6 {
		return []int{}
	}

	return result[0]
}

func (depMap *dependencyMap) updatePackageDetails(pkg *PackageDetails, content string, indexes []int) {
	lineStart := depMap.lineOffset + strings.Count(content[:indexes[0]], "\n")
	lineStartIndex := strings.LastIndex(content[:indexes[0]], "\n")
	lineEnd := depMap.lineOffset + strings.Count(content[:indexes[1]], "\n")
	lineEndIndex := strings.LastIndex(content[:indexes[1]], "\n")

	pkg.IsDirect = true

	pkg.BlockLocation = models.FilePosition{
		Filename: depMap.filePath,
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
		Filename: depMap.filePath,
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
		Filename: depMap.filePath,
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
