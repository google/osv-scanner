package lockfile

import (
	"bufio"
	"fmt"
	"log"
	"path/filepath"
	"strings"

	"github.com/google/osv-scanner/pkg/models"

	"github.com/google/osv-scanner/internal/cachedregexp"
)

const BundlerEcosystem Ecosystem = "RubyGems"

const (
	lockfileSectionBUNDLED      = "BUNDLED WITH"
	lockfileSectionDEPENDENCIES = "DEPENDENCIES"
	lockfileSectionPLATFORMS    = "PLATFORMS"
	lockfileSectionRUBY         = "RUBY VERSION"
	lockfileSectionGIT          = "GIT"
	lockfileSectionGEM          = "GEM"
	lockfileSectionPATH         = "PATH"
	lockfileSectionPLUGIN       = "PLUGIN SOURCE"
)

type parserState string

const (
	parserStateSource      parserState = "source"
	parserStateDependency  parserState = "dependency"
	parserStatePlatform    parserState = "platform"
	parserStateRuby        parserState = "ruby"
	parserStateBundledWith parserState = "bundled_with"
)

type gemfileLockfileParser struct {
	state          parserState
	dependencies   []PackageDetails
	bundlerVersion string
	rubyVersion    string

	// holds the commit of the gem that is currently being parsed, if found
	currentGemCommit string

	// whether or not the parser is in the `DEPENDENCIES` section
	isInDepSection bool
}

// This function returns whether or not the given line section is a source section.
func (parser *gemfileLockfileParser) isSourceSection(line string) bool {
	if strings.Contains(line, lockfileSectionDEPENDENCIES) {
		parser.isInDepSection = true
		return true
	}

	if strings.Contains(line, lockfileSectionGIT) ||
		strings.Contains(line, lockfileSectionGEM) ||
		strings.Contains(line, lockfileSectionPATH) ||
		strings.Contains(line, lockfileSectionPLUGIN) {
		parser.isInDepSection = false
		return true
	}

	return false
}

func (parser *gemfileLockfileParser) addDependency(name string, version string) {
	if !parser.isInDepSection {
		parser.dependencies = append(parser.dependencies, PackageDetails{
			Name:           name,
			Version:        version,
			PackageManager: models.Bundler,
			Ecosystem:      BundlerEcosystem,
			CompareAs:      BundlerEcosystem,
			Commit:         parser.currentGemCommit,
		})

		return
	}

	// find the package that exists already from parsing the `GEM` section
	// and set it as a direct dep

	for i, dep := range parser.dependencies {
		if dep.Name == name {
			parser.dependencies[i].IsDirect = true
			return
		}
	}
}

func (parser *gemfileLockfileParser) parseSpec(line string) {
	// nameVersionReg := cachedregexp.MustCompile(`^( {2}| {4}| {6})(?! )(.*?)(?: \(([^-]*)(?:-(.*))?\))?(!)?$`)
	nameVersionReg := cachedregexp.MustCompile(`^( +)(.*?)(?: \(([^-]*)(?:-(.*))?\))?(!)?$`)

	results := nameVersionReg.FindStringSubmatch(line)

	if results == nil {
		return
	}

	spaces := results[1]

	if spaces == "" {
		log.Fatal("Weird error when parsing spec in Gemfile.lock (unexpectedly had no spaces) - please report this")
	}

	if len(spaces) == 4 || (len(spaces) == 2 && parser.isInDepSection) {
		parser.addDependency(results[2], results[3])
	}
}

func (parser *gemfileLockfileParser) parseSource(line string) {
	if line == "  specs" {
		// todo: skip for now
		return
	}

	// OPTIONS      = /^  ([a-z]+): (.*)$/i.freeze
	optionsRegexp := cachedregexp.MustCompile(`(?i)^ {2}([a-z]+): (.*)$`)

	// todo: support
	options := optionsRegexp.FindStringSubmatch(line)

	if options != nil {
		commit := strings.TrimPrefix(options[0], "  revision: ")

		// if the prefix was removed then the gem being parsed is git based, so
		// we store the commit to be included later
		if commit != options[0] {
			parser.currentGemCommit = commit
		}

		return
	}

	// todo: source check

	parser.parseSpec(line)
}

func isNotIndented(line string) bool {
	re := cachedregexp.MustCompile(`^\S`)

	return re.MatchString(line)
}

func (parser *gemfileLockfileParser) parseLineBasedOnState(line string) {
	switch parser.state {
	case parserStatePlatform:
		break
	case parserStateRuby:
		parser.rubyVersion = strings.TrimSpace(line)
	case parserStateBundledWith:
		parser.bundlerVersion = strings.TrimSpace(line)
	case parserStateDependency:
	case parserStateSource:
		parser.parseSource(line)
	default:
		log.Fatalf("Unknown supported '%s'\n", parser.state)
	}
}

func (parser *gemfileLockfileParser) parse(line string) {
	if parser.isSourceSection(line) {
		// clear the stateful package details,
		// since we're now parsing a new group
		parser.currentGemCommit = ""
		parser.state = parserStateSource
		parser.parseSource(line)

		return
	}

	switch line {
	case lockfileSectionDEPENDENCIES:
		parser.state = parserStateDependency
	case lockfileSectionPLATFORMS:
		parser.state = parserStatePlatform
	case lockfileSectionRUBY:
		parser.state = parserStateRuby
	case lockfileSectionBUNDLED:
		parser.state = parserStateBundledWith
	default:
		if isNotIndented(line) {
			parser.state = ""
		}

		if parser.state != "" {
			parser.parseLineBasedOnState(line)
		}
	}
}

type GemfileLockExtractor struct {
	WithMatcher
}

func (e GemfileLockExtractor) ShouldExtract(path string) bool {
	return filepath.Base(path) == "Gemfile.lock"
}

func (e GemfileLockExtractor) Extract(f DepFile) ([]PackageDetails, error) {
	var parser gemfileLockfileParser

	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		parser.parse(scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return []PackageDetails{}, fmt.Errorf("error while scanning %s: %w", f.Path(), err)
	}

	return parser.dependencies, nil
}

var GemfileExtractor = GemfileLockExtractor{
	WithMatcher{Matchers: []Matcher{
		&GemfileMatcher{},
		&GemspecFileMatcher{},
	}},
}

//nolint:gochecknoinits
func init() {
	registerExtractor("Gemfile.lock", GemfileExtractor)
}

func ParseGemfileLock(pathToLockfile string) ([]PackageDetails, error) {
	return ExtractFromFile(pathToLockfile, GemfileExtractor)
}
