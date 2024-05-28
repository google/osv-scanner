package lockfile

import (
	"fmt"
	"io"
	"strings"

	"github.com/google/osv-scanner/internal/cachedregexp"
	"github.com/google/osv-scanner/internal/utility/fileposition"
	"github.com/google/osv-scanner/pkg/models"
)

type PackageJSONMatcher struct{}

func (m PackageJSONMatcher) GetSourceFile(lockfile DepFile) (DepFile, error) {
	return lockfile.Open("package.json")
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
			if strings.Contains(line, pkg.Name) {
				// TODO: what to do if version is not in the same line as the name?
				for _, targetVersion := range pkg.TargetVersions {
					if strings.Contains(line, targetVersion) {
						startColumn := fileposition.GetFirstNonEmptyCharacterIndexInLine(line)
						endColumn := fileposition.GetLastNonEmptyCharacterIndexInLine(strings.TrimSuffix(line, ","))

						packages[key].BlockLocation = models.FilePosition{
							Line:     models.Position{Start: lineNumber, End: lineNumber},
							Column:   models.Position{Start: startColumn, End: endColumn},
							Filename: sourcefile.Path(),
						}

						nameLocation := fileposition.ExtractDelimitedStringPositionInBlock([]string{line}, pkg.Name, lineNumber, "\"", "\"")
						if nameLocation != nil {
							nameLocation.Filename = sourcefile.Path()
							packages[key].NameLocation = nameLocation
						}

						versionRegexp := fmt.Sprintf(".*%s.*", cachedregexp.QuoteMeta(targetVersion))
						versionLocation := fileposition.ExtractDelimitedRegexpPositionInBlock([]string{line}, versionRegexp, lineNumber, ":\\s*\"", "\",?")
						if versionLocation != nil {
							versionLocation.Filename = sourcefile.Path()
							packages[key].VersionLocation = versionLocation
						}
					}
				}
			}
		}
	}

	return nil
}

var _ Matcher = PackageJSONMatcher{}
