package lockfile

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
)

var lockfileExtractors = map[string]Extractor{}

func registerExtractor(name string, extractor Extractor) {
	if _, ok := lockfileExtractors[name]; ok {
		panic("an extractor is already registered as " + name)
	}

	lockfileExtractors[name] = extractor
}

func FindExtractor(path, extractAs string, enabledParsers map[string]bool) (Extractor, string) {
	if extractAs != "" {
		if enabledParsers[extractAs] {
			return lockfileExtractors[extractAs], extractAs
		}

		return nil, ""
	}

	for name, extractor := range lockfileExtractors {
		isEnabled := enabledParsers[name]
		if isEnabled && extractor.ShouldExtract(path) {
			return extractor, name
		}
	}

	return nil, ""
}

func ListExtractors() []string {
	es := make([]string, 0, len(lockfileExtractors))

	for s := range lockfileExtractors {
		es = append(es, s)
	}

	sort.Slice(es, func(i, j int) bool {
		return strings.ToLower(es[i]) < strings.ToLower(es[j])
	})

	return es
}

var ErrExtractorNotFound = errors.New("could not determine extractor")

func ExtractDeps(f DepFile, extractAs string, enabledParsers map[string]bool) (Lockfile, error) {
	extractor, extractedAs := FindExtractor(f.Path(), extractAs, enabledParsers)

	if extractor == nil {
		if extractAs != "" {
			return Lockfile{}, fmt.Errorf("%w, requested %s", ErrExtractorNotFound, extractAs)
		}

		return Lockfile{}, fmt.Errorf("%w for %s", ErrExtractorNotFound, f.Path())
	}

	packages, err := extractor.Extract(f)

	if err != nil && extractedAs != "" {
		//nolint:all
		err = fmt.Errorf("(extracting as %s) %w", extractedAs, err)
	}

	// Match extracted packages with source file to enrich their details
	if e, ok := extractor.(ExtractorWithMatcher); ok {
		if matchers := e.GetMatchers(); len(matchers) > 0 {
			for _, matcher := range matchers {
				matchError := matchWithFile(f, packages, matcher)
				if matchError != nil {
					_, _ = fmt.Fprintf(os.Stderr, "there was an error matching the source file %s: %s\n", f.Path(), matchError.Error())
				}
			}
		}
	}

	sort.Slice(packages, func(i, j int) bool {
		if packages[i].Name == packages[j].Name {
			return packages[i].Version < packages[j].Version
		}

		return packages[i].Name < packages[j].Name
	})

	parsedLockfile := Lockfile{
		FilePath: f.Path(),
		ParsedAs: extractedAs,
		Packages: packages,
	}

	depFile, err := OpenLocalDepFile(f.Path())
	if err != nil {
		return parsedLockfile, err
	}
	if e, ok := extractor.(ArtifactExtractor); ok {
		artifact, err := e.GetArtifact(depFile)
		if err == nil {
			parsedLockfile.Artifact = artifact
		}
	}

	return parsedLockfile, err
}
