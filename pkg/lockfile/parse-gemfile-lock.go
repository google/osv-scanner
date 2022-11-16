package lockfile

import (
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
)

const BundlerEcosystem Ecosystem = "RubyGems"

const lockfileSectionBUNDLED = "BUNDLED WITH"
const lockfileSectionDEPENDENCIES = "DEPENDENCIES"
const lockfileSectionPLATFORMS = "PLATFORMS"
const lockfileSectionRUBY = "RUBY VERSION"
const lockfileSectionGIT = "GIT"
const lockfileSectionGEM = "GEM"
const lockfileSectionPATH = "PATH"
const lockfileSectionPLUGIN = "PLUGIN SOURCE"

type parserState string

const parserStateSource parserState = "source"
const parserStateDependency parserState = "dependency"
const parserStatePlatform parserState = "platform"
const parserStateRuby parserState = "ruby"
const parserStateBundledWith parserState = "bundled_with"

func isSourceSection(line string) bool {
	return strings.Contains(line, lockfileSectionGIT) ||
		strings.Contains(line, lockfileSectionGEM) ||
		strings.Contains(line, lockfileSectionPATH) ||
		strings.Contains(line, lockfileSectionPLUGIN)
}

type gemfileLockfileParser struct {
	state          parserState
	dependencies   []PackageDetails
	bundlerVersion string
	rubyVersion    string

	// holds the commit of the gem that is currently being parsed, if found
	currentGemCommit string
}

func (parser *gemfileLockfileParser) addDependency(name string, version string) {
	parser.dependencies = append(parser.dependencies, PackageDetails{
		Name:      name,
		Version:   version,
		Ecosystem: BundlerEcosystem,
		CompareAs: BundlerEcosystem,
		Commit:    parser.currentGemCommit,
	})
}

func (parser *gemfileLockfileParser) parseSpec(line string) {
	// nameVersionReg := regexp.MustCompile(`^( {2}| {4}| {6})(?! )(.*?)(?: \(([^-]*)(?:-(.*))?\))?(!)?$`)
	nameVersionReg := regexp.MustCompile(`^( +)(.*?)(?: \(([^-]*)(?:-(.*))?\))?(!)?$`)

	results := nameVersionReg.FindStringSubmatch(line)

	if results == nil {
		return
	}

	spaces := results[1]

	if spaces == "" {
		log.Fatal("Weird error when parsing spec in Gemfile.lock (unexpectedly had no spaces) - please report this")
	}

	if len(spaces) == 4 {
		parser.addDependency(results[2], results[3])
	}
}

func (parser *gemfileLockfileParser) parseSource(line string) {
	if line == "  specs" {
		// todo: skip for now
		return
	}

	// OPTIONS      = /^  ([a-z]+): (.*)$/i.freeze
	optionsRegexp := regexp.MustCompile(`(?i)^ {2}([a-z]+): (.*)$`)

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
	re := regexp.MustCompile(`^\S`)

	return re.MatchString(line)
}

func (parser *gemfileLockfileParser) parseLineBasedOnState(line string) {
	switch parser.state {
	case parserStateDependency:
	case parserStatePlatform:
		break
	case parserStateRuby:
		parser.rubyVersion = strings.TrimSpace(line)
	case parserStateBundledWith:
		parser.bundlerVersion = strings.TrimSpace(line)
	case parserStateSource:
		parser.parseSource(line)
	default:
		log.Fatalf("Unknown supported '%s'\n", parser.state)
	}
}

func (parser *gemfileLockfileParser) parse(contents string) {
	lineMatcher := regexp.MustCompile(`(?:\r?\n)+`)

	lines := lineMatcher.Split(contents, -1)

	for _, line := range lines {
		if isSourceSection(line) {
			// clear the stateful package details,
			// since we're now parsing a new group
			parser.currentGemCommit = ""
			parser.state = parserStateSource
			parser.parseSource(line)

			continue
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
}

func ParseGemfileLock(pathToLockfile string) ([]PackageDetails, error) {
	var parser gemfileLockfileParser

	bytes, err := os.ReadFile(pathToLockfile)

	if err != nil {
		return []PackageDetails{}, fmt.Errorf("could not read %s: %w", pathToLockfile, err)
	}

	parser.parse(string(bytes))

	return parser.dependencies, nil
}
