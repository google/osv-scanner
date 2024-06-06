package lockfile

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/exp/maps"
)

func FindParser(pathToLockfile string, parseAs string) (PackageDetailsParser, string) {
	if parseAs == "" {
		parseAs = filepath.Base(pathToLockfile)
	}

	return parsers[parseAs], parseAs
}

// this is an optimisation and read-only
var parsers = map[string]PackageDetailsParser{
	"buildscript-gradle.lockfile": ParseGradleLock,
	"Cargo.lock":                  ParseCargoLock,
	"composer.lock":               ParseComposerLock,
	"conan.lock":                  ParseConanLock,
	"Gemfile.lock":                ParseGemfileLock,
	"go.mod":                      ParseGoLock,
	"verification-metadata.xml":   ParseGradleVerificationMetadata,
	"gradle.lockfile":             ParseGradleLock,
	"mix.lock":                    ParseMixLock,
	"Pipfile.lock":                ParsePipenvLock,
	"package-lock.json":           ParseNpmLock,
	"packages.lock.json":          ParseNuGetLock,
	"pdm.lock":                    ParsePdmLock,
	"pnpm-lock.yaml":              ParsePnpmLock,
	"poetry.lock":                 ParsePoetryLock,
	"pom.xml":                     ParseMavenLock,
	"pubspec.lock":                ParsePubspecLock,
	"renv.lock":                   ParseRenvLock,
	"requirements.txt":            ParseRequirementsTxt,
	"yarn.lock":                   ParseYarnLock,
}

func ListParsers() []string {
	ps := make([]string, 0, len(parsers))

	for s := range parsers {
		ps = append(ps, s)
	}

	sort.Slice(ps, func(i, j int) bool {
		return strings.ToLower(ps[i]) < strings.ToLower(ps[j])
	})

	return ps
}

var ErrParserNotFound = errors.New("could not determine parser")

type Packages []PackageDetails

func (ps Packages) Ecosystems() []Ecosystem {
	ecosystems := make(map[Ecosystem]struct{})

	for _, pkg := range ps {
		ecosystems[pkg.Ecosystem] = struct{}{}
	}

	slicedEcosystems := maps.Keys(ecosystems)

	sort.Slice(slicedEcosystems, func(i, j int) bool {
		return slicedEcosystems[i] < slicedEcosystems[j]
	})

	return slicedEcosystems
}

type Lockfile struct {
	FilePath string   `json:"filePath"`
	ParsedAs string   `json:"parsedAs"`
	Packages Packages `json:"packages"`
}

func (l Lockfile) String() string {
	lines := make([]string, 0, len(l.Packages))

	for _, details := range l.Packages {
		ecosystem := details.Ecosystem

		if ecosystem == "" {
			ecosystem = "<unknown>"
		}

		ln := fmt.Sprintf("  %s: %s", ecosystem, details.Name)

		if details.Version != "" {
			ln += "@" + details.Version
		}

		if details.Commit != "" {
			ln += " (" + details.Commit + ")"
		}

		lines = append(lines, ln)
	}

	return strings.Join(lines, "\n")
}

// Parse attempts to extract a collection of package details from a lockfile,
// using one of the native parsers.
//
// The parser is selected based on the name of the file, which can be overridden
// with the "parseAs" parameter.
func Parse(pathToLockfile string, parseAs string) (Lockfile, error) {
	parser, parsedAs := FindParser(pathToLockfile, parseAs)

	if parser == nil {
		if parseAs != "" {
			return Lockfile{}, fmt.Errorf("%w, requested %s", ErrParserNotFound, parseAs)
		}

		return Lockfile{}, fmt.Errorf("%w for %s", ErrParserNotFound, pathToLockfile)
	}

	packages, err := parser(pathToLockfile)

	if err != nil && parseAs != "" {
		err = fmt.Errorf("(extracting as %s) %w", parsedAs, err)
	}

	sort.Slice(packages, func(i, j int) bool {
		if packages[i].Name == packages[j].Name {
			return packages[i].Version < packages[j].Version
		}

		return packages[i].Name < packages[j].Name
	})

	return Lockfile{
		FilePath: pathToLockfile,
		ParsedAs: parsedAs,
		Packages: packages,
	}, err
}
