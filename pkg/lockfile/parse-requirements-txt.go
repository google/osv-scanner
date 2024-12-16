package lockfile

import (
	"bufio"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/google/osv-scanner/internal/utility/fileposition"
	"github.com/google/osv-scanner/pkg/models"

	"github.com/google/osv-scanner/internal/cachedregexp"
	"golang.org/x/exp/maps"
)

const PipEcosystem Ecosystem = "PyPI"

// CommentType represents the type of dependency comment
type CommentType int

const (
	// CommentTypeNone represents a comment that doesn't have any special meaning,
	// and signifies we're parsing a multiline comment.
	CommentTypeNone CommentType = iota

	// CommentTypeIndirect represents a comment that signifies a package is an
	// indirect dependency.
	CommentTypeIndirect

	// CommentTypeDirect represents a comment that signifies a package is a direct
	// dependency.
	CommentTypeDirect
)

// Comment represents a parsed requirements.txt comment
type Comment struct {
	Content string
	Type    CommentType
}

// CommentParser handles parsing of requirements.txt comments
type CommentParser struct {
	currentComments []*Comment
	multiline       bool
}

// ParseComment parses a single comment line and returns the parsed comment
func (p *CommentParser) ParseComment(line string) *Comment {
	// Early return if not a comment
	if !strings.HasPrefix(strings.TrimSpace(line), "#") {
		return nil
	}

	// Remove spaces before and after the `#`
	content := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "#"))

	// Handle empty comments
	if content == "" {
		return &Comment{Type: CommentTypeDirect}
	}

	// Continue multiline comments
	if len(p.currentComments) != 0 {
		comment := p.continueMultilineComment(content)
		p.currentComments = append(p.currentComments, comment)

		return comment
	}

	// Parse new comment
	return p.parseNewComment(content)
}

// parseNewComment starts parsing a new comment (or series of comments) and returns the first line's parsed comment
func (p *CommentParser) parseNewComment(content string) *Comment {
	// Handle "via" prefix
	if !strings.HasPrefix(strings.ToLower(content), "via") {
		return &Comment{Type: CommentTypeDirect, Content: content}
	}

	content = strings.TrimPrefix(strings.ToLower(content), "via")
	content = strings.TrimSpace(content)

	// If the comment was just "# via", start multiline parsing
	if content == "" {
		p.currentComments = append(p.currentComments, &Comment{Type: CommentTypeNone})
		p.multiline = true

		return p.currentComments[0]
	}

	// Else, parse a single-line comment
	return p.parseCommentContent(content)
}

// continueMultilineComment continues parsing a multiline comment and returns the parsed comment
func (p *CommentParser) continueMultilineComment(content string) *Comment {
	comment := p.parseCommentContent(content)
	return comment
}

// parseCommentContent parses the content of a comment and returns the parsed comment
// This is used for both single-line and multiline comments
func (p *CommentParser) parseCommentContent(content string) *Comment {
	// Parse to see if there's a package name only
	if isValidPackageName(content) {
		return &Comment{
			Type:    CommentTypeIndirect,
			Content: content,
		}
	}

	// Parse to see if there's the "-r" prefix, indicating a file reference
	if strings.HasPrefix(content, "-r ") {
		return &Comment{
			Type:    CommentTypeDirect,
			Content: strings.TrimPrefix(content, "-r "),
		}
	}

	// Else, treat as a manually-added comment
	return &Comment{Type: CommentTypeDirect, Content: content}
}

// reset resets the parser state
func (p *CommentParser) reset() {
	p.currentComments = []*Comment{}
	p.multiline = false
}

func (p *CommentParser) IsDirect() bool {
	for _, comment := range p.currentComments {
		if comment.Type == CommentTypeDirect {
			return true
		}
	}

	return false
}

func isValidPackageName(name string) bool {
	return cachedregexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(name)
}

// todo: expand this to support more things, e.g.
//
//	https://pip.pypa.io/en/stable/reference/requirements-file-format/#example
func parseLine(path string, line string, lineNumber int, lineOffset int, columnStart int, columnEnd int) PackageDetails {
	// Remove environment markers
	// pre https://pip.pypa.io/en/stable/reference/requirement-specifiers/#overview
	line = strings.Split(line, ";")[0]

	var constraint string
	name := line

	version := ""

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

	block := strings.Split(line, "\n")
	blockLocation := models.FilePosition{
		Line:     models.Position{Start: lineNumber, End: lineNumber + lineOffset},
		Column:   models.Position{Start: columnStart, End: columnEnd},
		Filename: path,
	}

	nameLocation := fileposition.ExtractStringPositionInBlock(block, name, lineNumber)
	if nameLocation != nil {
		nameLocation.Filename = path
	}

	versionLocation := fileposition.ExtractStringPositionInBlock(block, version, lineNumber)
	if versionLocation != nil {
		versionLocation.Filename = path
	}

	return PackageDetails{
		Name:            normalizedRequirementName(name),
		Version:         version,
		BlockLocation:   blockLocation,
		NameLocation:    nameLocation,
		VersionLocation: versionLocation,
		PackageManager:  models.Requirements,
		Ecosystem:       PipEcosystem,
		CompareAs:       PipEcosystem,
		IsDirect:        true,
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
	re := cachedregexp.MustCompile(`(\s*)#.*$`)

	return strings.TrimSpace(re.ReplaceAllString(line, ""))
}

func isComment(line string) bool {
	re := cachedregexp.MustCompile(`^\s*#`)

	return re.MatchString(line)
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
	re := cachedregexp.MustCompile(`([^\\]|^)(\\{2})*\\$`)

	return re.MatchString(line)
}

// Please note the whl filename has been standardized here :
// https://packaging.python.org/en/latest/specifications/binary-distribution-format/#file-name-convention
func extractVersionFromWheelURL(wheelURL string) string {
	paths := strings.Split(wheelURL, "/")
	filename := paths[len(paths)-1]
	parts := strings.Split(filename, "-")

	if len(parts) < 2 {
		return ""
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

	// inHeaderComments is only true if we're in a block of comments at the top of the file
	inHeaderComments := false
	autoGenerated := false

	// This is used to store the last package details parsed,
	// so we can update it with information parsed from the comments following it
	lastPkg := PackageDetails{}
	lastPkgKey := ""

	commentParser := &CommentParser{}

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
				line += "\n" + newLine
				lastLine = newLine
			}
		}

		isCommentLine := isComment(line)

		if isCommentLine && (inHeaderComments || lineNumber == 1) {
			inHeaderComments = true

			if strings.Contains(line, "autogenerated") {
				autoGenerated = true
			}
		} else {
			inHeaderComments = false
		}

		// Attempt to parse the comment if this is a comment line in an autogenerated file
		if autoGenerated && isCommentLine {
			comment := commentParser.ParseComment(line)

			// If this was a single-line comment, check if we should set `IsDirect` to false.
			if !commentParser.multiline && comment.Type == CommentTypeIndirect {
				lastPkg.IsDirect = false
				packages[lastPkgKey] = lastPkg
			}
		} else {
			if commentParser.multiline && len(commentParser.currentComments) > 0 {
				direct := commentParser.IsDirect()
				lastPkg.IsDirect = direct
				packages[lastPkgKey] = lastPkg
			}

			commentParser.reset()
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

		lastPkg = d
		lastPkgKey = key
	}

	// if we had a multiline comment at the end of the file, we need to update the last package
	if commentParser.multiline && len(commentParser.currentComments) > 0 {
		direct := commentParser.IsDirect()
		lastPkg.IsDirect = direct
		packages[lastPkgKey] = lastPkg
	}

	if err := scanner.Err(); err != nil {
		return []PackageDetails{}, fmt.Errorf("error while scanning %s: %w", f.Path(), err)
	}

	return maps.Values(packages), nil
}

var _ Extractor = RequirementsTxtExtractor{}

//nolint:gochecknoinits
func init() {
	registerExtractor("requirements.txt", RequirementsTxtExtractor{})
}

func ParseRequirementsTxt(pathToLockfile string) ([]PackageDetails, error) {
	return extractFromFile(pathToLockfile, RequirementsTxtExtractor{})
}
