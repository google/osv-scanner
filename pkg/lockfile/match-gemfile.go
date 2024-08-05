package lockfile

import (
	"io"
	"path/filepath"
	"strings"

	"github.com/google/osv-scanner/internal/cachedregexp"

	"github.com/google/osv-scanner/internal/utility/fileposition"
	"github.com/google/osv-scanner/pkg/models"
)

const gemfileFilename = "Gemfile"
const gemField = "gem"

// This is used to clean properties from the gem function syntax
// We are keeping quotes to stay consistent with the version as we can have multiple version qualifiers
var gemSyntaxRemover = strings.NewReplacer(",", "")

// We use a specific remover to clean quotes when we fetch the name to find it in the index
var gemNameSyntaxRemover = strings.NewReplacer(",", "", "\"", "", "'", "")

type GemfileMatcher struct{}

type gemInformation struct {
	name          string
	blockLine     models.Position
	blockColumn   models.Position
	nameLine      models.Position
	nameColumn    models.Position
	versionLine   *models.Position
	versionColumn *models.Position
}

func (matcher GemfileMatcher) GetSourceFile(lockfile DepFile) (DepFile, error) {
	lockfileDir := filepath.Dir(lockfile.Path())
	sourceFilePath := filepath.Join(lockfileDir, gemfileFilename)
	file, err := OpenLocalDepFile(sourceFilePath)

	return file, err
}

func (matcher GemfileMatcher) Match(sourceFile DepFile, packages []PackageDetails) error {
	content, err := io.ReadAll(sourceFile)

	if err != nil {
		return err
	}

	indexedPkgs := indexPackages(packages)
	lines := fileposition.BytesToLines(content)

	for index, line := range lines {
		lineNumber := index + 1
		lineFields := strings.Fields(line)

		if len(lineFields) == 0 {
			continue
		} else if lineFields[0] == gemField {
			// We found a package definition, we need to find which one it is.
			// It can be multi-lined
			gemLines := accumulateGemLines(lines, index)
			info := extractInfoFromGemLines(gemLines, lineNumber)
			pkg, exists := indexedPkgs[info.name]

			if !exists {
				// It should always exists, we should have less dependencies here than in the lockfile
				// If it does not exists, lockfile is not updated, so we skip the dependency
				continue
			}
			updatePackageDetails(sourceFile.Path(), info, pkg)
		}
	}

	return nil
}

func updatePackageDetails(filePath string, info gemInformation, pkg *PackageDetails) {
	pkg.BlockLocation = models.FilePosition{
		Line:     info.blockLine,
		Column:   info.blockColumn,
		Filename: filePath,
	}

	pkg.NameLocation = &models.FilePosition{
		Line:     info.nameLine,
		Column:   info.nameColumn,
		Filename: filePath,
	}

	if info.versionLine != nil && info.versionColumn != nil {
		pkg.VersionLocation = &models.FilePosition{
			Line:     *info.versionLine,
			Column:   *info.versionColumn,
			Filename: filePath,
		}
	}
}

func accumulateGemLines(lines []string, startIndex int) []string {
	result := make([]string, 0)

	for i := startIndex; i < len(lines); i++ {
		result = append(result, lines[i])
		if !shouldContinueAccumulate(lines[i]) {
			break
		}
	}

	return result
}

func shouldContinueAccumulate(line string) bool {
	commentRemover := cachedregexp.MustCompile("#.*$")
	cleanedLine := strings.TrimSpace(commentRemover.ReplaceAllString(line, ""))

	return len(cleanedLine) == 0 || strings.HasSuffix(cleanedLine, ",")
}

func extractInfoFromGemLines(gemLines []string, startLineNumber int) gemInformation {
	info := gemInformation{}

	// We fill information about the block first
	info.blockLine = models.Position{
		Start: startLineNumber,
		End:   startLineNumber + len(gemLines) - 1,
	}
	info.blockColumn = models.Position{
		Start: strings.Index(gemLines[0], "gem") + 1,
		End:   len(gemLines[len(gemLines)-1]) + 1,
	}

	// Then we extract the name as it is a mandatory field
	// It is always in the first line as it is the first gem function argument, it can't be multi-lined
	extractName(gemLines[0], startLineNumber, &info)

	// Then we check if we have versions specifiers
	// They are always before positional arguments, after the name, and in a sequence.
	// They can be multi-lined
	extractVersions(gemLines, startLineNumber, &info)

	return info
}

func extractName(line string, startLineNumber int, info *gemInformation) {
	fields := strings.Fields(line)
	nameToLocate := gemSyntaxRemover.Replace(fields[1])
	info.name = gemNameSyntaxRemover.Replace(fields[1])
	nameColumnStart := strings.Index(line, nameToLocate)
	info.nameLine = models.Position{
		Start: startLineNumber,
		End:   startLineNumber,
	}
	info.nameColumn = models.Position{
		Start: nameColumnStart + 1,
		End:   nameColumnStart + 1 + len(nameToLocate),
	}
}

func extractVersions(lines []string, startLineNumber int, info *gemInformation) {
	versionLineStart, versionLineEnd := -1, -1
	versionColumnStart, versionColumnEnd := -1, -1

	for index, line := range lines {
		fields := strings.Fields(line)
		startFieldIndex := 0

		if index == 0 {
			// It's the first gem line, which have "gem" + name, so we start to search after those two
			startFieldIndex = 2
		}
		for fieldIndex := startFieldIndex; fieldIndex < len(fields); fieldIndex++ {
			if isCommentField(fields[fieldIndex]) {
				// We found a comment, go to next line
				break
			} else if !isVersionField(fields[fieldIndex]) {
				// Once it is not a version field anymore, it means we only have positional arguments anymore
				// If we have not declared any version start, it means no version has been declared, we return early
				if versionLineStart == -1 {
					return
				}

				break
			}

			// We have a version field, if we haven't registered a start line, we do it
			if versionLineStart == -1 {
				versionLineStart = startLineNumber + index
				versionColumnStart = strings.Index(line, fields[fieldIndex]) + 1
			}

			// And we update the end information
			version := gemSyntaxRemover.Replace(fields[fieldIndex])
			versionLineEnd = startLineNumber + index
			versionColumnEnd = strings.Index(line, fields[fieldIndex]) + len(version) + 1
		}

		if versionLineStart != -1 {
			break
		}
	}

	// And now we fill the info structure with everything
	info.versionLine = &models.Position{
		Start: versionLineStart,
		End:   versionLineEnd,
	}
	info.versionColumn = &models.Position{
		Start: versionColumnStart,
		End:   versionColumnEnd,
	}
}

// If the field starts with anything followed by ':', it means it is one of the named arguments
// The only non-named arguments are name and version
// caller must be sure to call this after name has already been passed
func isVersionField(field string) bool {
	matcher := cachedregexp.MustCompile("^\\w*:")
	matched := matcher.MatchString(field)

	return !matched
}

func isCommentField(field string) bool {
	return strings.HasPrefix(field, "#")
}

func indexPackages(packages []PackageDetails) map[string]*PackageDetails {
	result := make(map[string]*PackageDetails)
	for index, pkg := range packages {
		result[pkg.Name] = &packages[index]
	}

	return result
}
