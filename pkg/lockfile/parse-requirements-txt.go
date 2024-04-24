package lockfile

import (
	"bufio"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/google/osv-scanner/internal/utility/fileposition"
	"github.com/google/osv-scanner/pkg/models"

	"github.com/google/osv-scanner/internal/cachedregexp"
)

const PipEcosystem Ecosystem = "PyPI"

// todo: expand this to support more things, e.g.
//
//	https://pip.pypa.io/en/stable/reference/requirements-file-format/#example
func parseLine(path string, line string, lineNumber int, lineOffset int, columnStart int, columnEnd int) PackageDetails {
	// Remove environment markers
	// pre https://pip.pypa.io/en/stable/reference/requirement-specifiers/#overview
	line = strings.Split(line, ";")[0]

	var constraint string
	name := line

	version := "0.0.0"

	if strings.Contains(line, "==") {
		constraint = "=="
	}

	if strings.Contains(line, ">=") {
		constraint = ">="
	}

	if strings.Contains(line, "~=") {
		constraint = "~="
	}

	if strings.Contains(line, "!=") {
		constraint = "!="
	}

	if constraint != "" {
		unprocessedName, unprocessedVersion, _ := strings.Cut(line, constraint)
		name = strings.TrimSpace(unprocessedName)

		if constraint != "!=" {
			version, _, _ = strings.Cut(strings.TrimSpace(unprocessedVersion), " ")
		}
	} else if strings.Contains(line, "@") {
		unprocessedName, unprocessedFileLocation, _ := strings.Cut(line, "@")
		name = strings.TrimSpace(unprocessedName)
		fileLocation := strings.TrimSpace(unprocessedFileLocation)
		if strings.HasSuffix(fileLocation, ".whl") {
			version = extractVersionFromWheelURL(fileLocation)
		}
	}

	return PackageDetails{
		Name:    normalizedRequirementName(name),
		Version: version,
		BlockLocation: models.FilePosition{
			Line:   models.Position{Start: lineNumber, End: lineNumber + lineOffset},
			Column: models.Position{Start: columnStart, End: columnEnd},
		},
		Ecosystem:  PipEcosystem,
		CompareAs:  PipEcosystem,
		SourceFile: path,
	}
}

// normalizedName ensures that the package name is normalized per PEP-0503
// and then removing "added support" syntax if present.
//
// This is done to ensure we don't miss any advisories, as while the OSV
// specification says that the normalized name should be used for advisories,
// that's not the case currently in our databases, _and_ Pip itself supports
// non-normalized names in the requirements.txt, so we need to normalize
// on both sides to ensure we don't have false negatives.
//
// It's possible that this will cause some false positives, but that is better
// than false negatives, and can be dealt with when/if it actually happens.
func normalizedRequirementName(name string) string {
	// per https://www.python.org/dev/peps/pep-0503/#normalized-names
	name = cachedregexp.MustCompile(`[-_.]+`).ReplaceAllString(name, "-")
	name = strings.ToLower(name)
	name, _, _ = strings.Cut(name, "[")

	return name
}

func removeComments(line string) string {
	var re = cachedregexp.MustCompile(`(^|\s+)#.*$`)

	return strings.TrimSpace(re.ReplaceAllString(line, ""))
}

func isNotRequirementLine(line string) bool {
	return line == "" ||
		// flags are not supported
		strings.HasPrefix(line, "-") ||
		// file urls
		strings.HasPrefix(line, "https://") ||
		strings.HasPrefix(line, "http://") ||
		// file paths are not supported (relative or absolute)
		strings.HasPrefix(line, ".") ||
		strings.HasPrefix(line, "/")
}

func isLineContinuation(line string) bool {
	// checks that the line ends with an odd number of back slashes,
	// meaning the last one isn't escaped
	var re = cachedregexp.MustCompile(`([^\\]|^)(\\{2})*\\$`)

	return re.MatchString(line)
}

// Please note the whl filename has been standardized here :
// https://packaging.python.org/en/latest/specifications/binary-distribution-format/#file-name-convention
func extractVersionFromWheelURL(wheelURL string) string {
	paths := strings.Split(wheelURL, "/")
	filename := paths[len(paths)-1]
	parts := strings.Split(filename, "-")

	if len(parts) < 2 {
		return "0.0.0"
	}

	return parts[1]
}

type RequirementsTxtExtractor struct{}

func (e RequirementsTxtExtractor) ShouldExtract(path string) bool {
	baseFilepath := filepath.Base(path)
	return strings.Contains(baseFilepath, "requirements") && strings.HasSuffix(baseFilepath, ".txt")
}

func (e RequirementsTxtExtractor) Extract(f DepFile) ([]PackageDetails, error) {
	return parseRequirementsTxt(f, map[string]struct{}{})
}

func parseRequirementsTxt(f DepFile, requiredAlready map[string]struct{}) ([]PackageDetails, error) {
	packages := map[string]PackageDetails{}

	group := strings.TrimSuffix(filepath.Base(f.Path()), filepath.Ext(f.Path()))
	hasGroup := func(groups []string) bool {
		for _, g := range groups {
			if g == group {
				return true
			}
		}

		return false
	}

	scanner := bufio.NewScanner(f)
	var lineNumber, lineOffset, columnStart, columnEnd int

	for scanner.Scan() {
		lineNumber += lineOffset + 1
		lineOffset = 0

		line := scanner.Text()
		lastLine := line
		columnStart = fileposition.GetFirstNonEmptyCharacterIndexInLine(line)

		for isLineContinuation(line) {
			line = strings.TrimSuffix(line, "\\")

			if scanner.Scan() {
				lineOffset++
				newLine := scanner.Text()
				line += newLine
				lastLine = newLine
			}
		}

		line = removeComments(line)
		if ar := strings.TrimPrefix(line, "-r "); ar != line {
			if strings.HasPrefix(ar, "http://") || strings.HasPrefix(ar, "https://") {
				// If the linked requirement file is not locally stored, we skip it
				continue
			}
			err := func() error {
				af, err := f.Open(ar)

				if err != nil {
					return fmt.Errorf("failed to include %s: %w", line, err)
				}

				defer af.Close()

				if _, ok := requiredAlready[af.Path()]; ok {
					return nil
				}

				requiredAlready[af.Path()] = struct{}{}

				details, err := parseRequirementsTxt(af, requiredAlready)

				if err != nil {
					return fmt.Errorf("failed to include %s: %w", line, err)
				}

				for _, detail := range details {
					packages[detail.Name+"@"+detail.Version] = detail
				}

				return nil
			}()

			if err != nil {
				return []PackageDetails{}, err
			}

			continue
		}

		if isNotRequirementLine(line) {
			continue
		}

		columnEnd = fileposition.GetLastNonEmptyCharacterIndexInLine(lastLine)

		detail := parseLine(f.Path(), line, lineNumber, lineOffset, columnStart, columnEnd)
		key := detail.Name + "@" + detail.Version
		if _, ok := packages[key]; !ok {
			packages[key] = detail
		}
		d := packages[key]
		if !hasGroup(d.DepGroups) {
			d.DepGroups = append(d.DepGroups, group)
			packages[key] = d
		}
	}

	if err := scanner.Err(); err != nil {
		return []PackageDetails{}, fmt.Errorf("error while scanning %s: %w", f.Path(), err)
	}

	return pkgDetailsMapToSlice(packages), nil
}

var _ Extractor = RequirementsTxtExtractor{}

//nolint:gochecknoinits
func init() {
	registerExtractor("requirements.txt", RequirementsTxtExtractor{})
}

func ParseRequirementsTxt(pathToLockfile string) ([]PackageDetails, error) {
	return extractFromFile(pathToLockfile, RequirementsTxtExtractor{})
}
