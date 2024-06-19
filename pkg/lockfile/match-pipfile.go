package lockfile

import (
	"io"
	"strings"

	"github.com/google/osv-scanner/internal/utility/fileposition"
	"github.com/google/osv-scanner/pkg/models"
)

type PipfileMatcher struct{}

func (m PipfileMatcher) GetSourceFile(lockfile DepFile) (DepFile, error) {
	return lockfile.Open("Pipfile")
}

func (m PipfileMatcher) Match(sourcefile DepFile, packages []PackageDetails) error {
	content, err := io.ReadAll(sourcefile)
	if err != nil {
		return err
	}

	lines := fileposition.BytesToLines(content)

	for index, line := range lines {
		lineNumber := index + 1
		for key, pkg := range packages {
			// There are some libraries that use upper case names, but their name is resolve as lower case (i.e. Django != django)
			lowerLine := strings.ToLower(line)
			lowerName := strings.ToLower(pkg.Name)
			// We only need to find the package name because there cannot be multiple entries of the same dependency in the source file nor the lock file
			if strings.Contains(lowerLine, lowerName) {
				startColumn := fileposition.GetFirstNonEmptyCharacterIndexInLine(lowerLine)
				endColumn := fileposition.GetLastNonEmptyCharacterIndexInLine(lowerLine)

				packages[key].BlockLocation = models.FilePosition{
					Line:     models.Position{Start: lineNumber, End: lineNumber},
					Column:   models.Position{Start: startColumn, End: endColumn},
					Filename: sourcefile.Path(),
				}

				nameLocation := fileposition.ExtractStringPositionInBlock([]string{lowerLine}, lowerName, lineNumber)
				if nameLocation != nil {
					nameLocation.Filename = sourcefile.Path()
					packages[key].NameLocation = nameLocation
				}

				versionLocation := fileposition.ExtractDelimitedRegexpPositionInBlock([]string{lowerLine}, ".*", lineNumber, "=\\s*\"", "\"")
				if versionLocation != nil {
					versionLocation.Filename = sourcefile.Path()
					packages[key].VersionLocation = versionLocation
				}
			}
		}
	}

	return nil
}

var _ Matcher = PipfileMatcher{}
