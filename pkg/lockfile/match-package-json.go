package lockfile

import (
	"io"
	"strings"

	"github.com/google/osv-scanner/internal/cachedregexp"

	"github.com/google/osv-scanner/internal/utility/fileposition"
	"github.com/google/osv-scanner/pkg/models"
)

type PackageJSONMatcher struct{}

const (
	namePrefix    = "\""
	nameSuffix    = "\"\\s*:"
	versionPrefix = ":\\s*\""
	versionSuffix = "\",?"
)

func (m PackageJSONMatcher) GetSourceFile(lockfile DepFile) (DepFile, error) {
	return lockfile.Open("package.json")
}

func tryGetNameLocation(name string, line string, lineNumber int) *models.FilePosition {
	nameRegexp := cachedregexp.QuoteMeta(name) + "(@.*)?"

	return fileposition.ExtractDelimitedRegexpPositionInBlock([]string{line}, nameRegexp, lineNumber, namePrefix, nameSuffix)
}

func tryGetVersionLocation(targetVersion string, version string, line string, lineNumber int) *models.FilePosition {
	if targetVersion == version {
		return fileposition.ExtractDelimitedRegexpPositionInBlock([]string{line}, targetVersion, lineNumber, versionPrefix, versionSuffix)
	}
	versionRegexp := ".*" + cachedregexp.QuoteMeta(targetVersion) + ".*"

	return fileposition.ExtractDelimitedRegexpPositionInBlock([]string{line}, versionRegexp, lineNumber, versionPrefix, versionSuffix)
}

func updatePackageLocations(pkg *PackageDetails, nameLocation *models.FilePosition, versionLocation *models.FilePosition, line string, lineNumber int, sourcefilePath string) {
	// Update block location
	startColumn := fileposition.GetFirstNonEmptyCharacterIndexInLine(line)
	endColumn := fileposition.GetLastNonEmptyCharacterIndexInLine(strings.TrimSuffix(line, ","))
	pkg.BlockLocation = models.FilePosition{
		Line:     models.Position{Start: lineNumber, End: lineNumber},
		Column:   models.Position{Start: startColumn, End: endColumn},
		Filename: sourcefilePath,
	}
	// Update name location
	nameLocation.Filename = sourcefilePath
	pkg.NameLocation = nameLocation
	// Update version location
	versionLocation.Filename = sourcefilePath
	pkg.VersionLocation = versionLocation
}

func (m PackageJSONMatcher) Match(sourcefile DepFile, packages []PackageDetails) error {
	content, err := io.ReadAll(sourcefile)
	if err != nil {
		return err
	}

	lines := fileposition.BytesToLines(content)
	for index, line := range lines {
		lineNumber := index + 1
		for key, pkg := range packages {
			nameLocation := tryGetNameLocation(pkg.Name, line, lineNumber)
			if nameLocation != nil {
				for _, targetVersion := range pkg.TargetVersions {
					// TODO: what to do if version is not in the same line as the name?
					versionLocation := tryGetVersionLocation(targetVersion, pkg.Version, line, lineNumber)
					if versionLocation != nil {
						updatePackageLocations(&packages[key], nameLocation, versionLocation, line, lineNumber, sourcefile.Path())
					}
				}
			}
		}
	}

	return nil
}

var _ Matcher = PackageJSONMatcher{}
