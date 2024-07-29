package lockfilescalibr

import (
	"bufio"
	"context"
	"fmt"
	"io/fs"
	"log"
	"path/filepath"
	"strings"

	"github.com/google/osv-scanner/internal/cachedregexp"
	"github.com/google/osv-scanner/internal/lockfilescalibr/plugin"
	"github.com/package-url/packageurl-go"
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
	dependencies   []*Inventory
	bundlerVersion string
	rubyVersion    string

	// holds the commit of the gem that is currently being parsed, if found
	currentGemCommit string

	// holds the path of the file being parsed
	location string
}

func (parser *gemfileLockfileParser) addDependency(name string, version string) {
	parser.dependencies = append(parser.dependencies, &Inventory{
		Name:    name,
		Version: version,
		SourceCode: &SourceCodeIdentifier{
			Commit: parser.currentGemCommit,
		},
		Locations: []string{parser.location},
	})
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

func (parser *gemfileLockfileParser) parse(line string) {
	if isSourceSection(line) {
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

type GemfileLockExtractor struct{}

// Name of the extractor
func (e GemfileLockExtractor) Name() string { return "go/gomod" }

// Version of the extractor
func (e GemfileLockExtractor) Version() int { return 0 }

func (e GemfileLockExtractor) Requirements() *plugin.Requirements {
	return &plugin.Requirements{}
}

func (e GemfileLockExtractor) FileRequired(path string, fileInfo fs.FileInfo) bool {
	return filepath.Base(path) == "Gemfile.lock"
}

func (e GemfileLockExtractor) Extract(ctx context.Context, input *ScanInput) ([]*Inventory, error) {
	var parser gemfileLockfileParser
	parser.location = input.Path

	scanner := bufio.NewScanner(input.Reader)

	for scanner.Scan() {
		parser.parse(scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return []*Inventory{}, fmt.Errorf("error while scanning %s: %w", input.Path, err)
	}

	return parser.dependencies, nil
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e GemfileLockExtractor) ToPURL(i *Inventory) (*packageurl.PackageURL, error) {
	return &packageurl.PackageURL{
		Type:    packageurl.TypeGem,
		Name:    i.Name,
		Version: i.Version,
	}, nil
}

// ToCPEs is not applicable as this extractor does not infer CPEs from the Inventory.
func (e GemfileLockExtractor) ToCPEs(i *Inventory) ([]string, error) { return []string{}, nil }

func (e GemfileLockExtractor) Ecosystem(i *Inventory) (string, error) {
	switch i.Extractor.(type) {
	case GemfileLockExtractor:
		return string(BundlerEcosystem), nil
	default:
		return "", ErrWrongExtractor
	}
}

var _ Extractor = GemfileLockExtractor{}
