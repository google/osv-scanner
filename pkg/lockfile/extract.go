package lockfile

import (
	"errors"
	"fmt"
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

func FindExtractor(path, extractAs string) (Extractor, string) {
	if extractAs != "" {
		return lockfileExtractors[extractAs], extractAs
	}

	for name, extractor := range lockfileExtractors {
		if extractor.ShouldExtract(path) {
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

func ExtractDeps(f DepFile, extractAs string) (Lockfile, error) {
	extractor, extractedAs := FindExtractor(f.Path(), extractAs)

	if extractor == nil {
		if extractAs != "" {
			return Lockfile{}, fmt.Errorf("%w, requested %s", ErrExtractorNotFound, extractAs)
		}

		return Lockfile{}, fmt.Errorf("%w for %s", ErrExtractorNotFound, f.Path())
	}

	packages, err := extractor.Extract(f)

	if err != nil && extractedAs != "" {
		err = fmt.Errorf("(extracting as %s) %w", extractedAs, err)
	}

	sort.Slice(packages, func(i, j int) bool {
		if packages[i].Name == packages[j].Name {
			return packages[i].Version < packages[j].Version
		}

		return packages[i].Name < packages[j].Name
	})

	return Lockfile{
		FilePath: f.Path(),
		ParsedAs: extractedAs,
		Packages: packages,
	}, err
}
