package lockfile_test

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/google/osv-scanner/pkg/lockfile"
)

type TestDepFile struct {
	io.Reader

	path string
}

func (f TestDepFile) Open(_ string) (lockfile.NestedDepFile, error) {
	return TestDepFile{}, errors.New("file opening is not supported")
}

func (f TestDepFile) Path() string { return f.path }
func (f TestDepFile) Close() error { return nil }

func openTestDepFile(p string) TestDepFile {
	return TestDepFile{strings.NewReader(""), p}
}

var _ lockfile.DepFile = TestDepFile{}
var _ lockfile.NestedDepFile = TestDepFile{}

func TestFindExtractor(t *testing.T) {
	t.Parallel()

	lockfiles := map[string]string{
		"buildscript-gradle.lockfile":      "gradle.lockfile",
		"Cargo.lock":                       "Cargo.lock",
		"composer.lock":                    "composer.lock",
		"Gemfile.lock":                     "Gemfile.lock",
		"go.mod":                           "go.mod",
		"gradle/verification-metadata.xml": "gradle/verification-metadata.xml",
		"gradle.lockfile":                  "gradle.lockfile",
		"mix.lock":                         "mix.lock",
		"pdm.lock":                         "pdm.lock",
		"Pipfile.lock":                     "Pipfile.lock",
		"package-lock.json":                "package-lock.json",
		"packages.lock.json":               "packages.lock.json",
		"pnpm-lock.yaml":                   "pnpm-lock.yaml",
		"poetry.lock":                      "poetry.lock",
		"pom.xml":                          "pom.xml",
		"pubspec.lock":                     "pubspec.lock",
		"renv.lock":                        "renv.lock",
		"requirements.txt":                 "requirements.txt",
		"yarn.lock":                        "yarn.lock",
	}

	for file, extractAs := range lockfiles {
		extractor, extractedAs := lockfile.FindExtractor("/path/to/my/"+file, "")

		if extractor == nil {
			t.Errorf("Expected a extractor to be found for %s but did not", file)
		}

		if extractAs != extractedAs {
			t.Errorf("Expected extractedAs to be %s but got %s instead", file, extractedAs)
		}
	}
}

func TestFindExtractor_ExplicitExtractAs(t *testing.T) {
	t.Parallel()

	extractor, extractedAs := lockfile.FindExtractor("/path/to/my/package-lock.json", "composer.lock")

	if extractor == nil {
		t.Errorf("Expected a extractor to be found for package-lock.json (overridden as composer.lock) but did not")
	}

	if extractedAs != "composer.lock" {
		t.Errorf("Expected extractedAs to be composer.lock but got %s instead", extractedAs)
	}
}

func TestExtractDeps_FindsExpectedExtractor(t *testing.T) {
	t.Parallel()

	lockfiles := []string{
		"buildscript-gradle.lockfile",
		"Cargo.lock",
		"composer.lock",
		"conan.lock",
		"Gemfile.lock",
		"go.mod",
		"gradle.lockfile",
		"gradle/verification-metadata.xml",
		"mix.lock",
		"pdm.lock",
		"Pipfile.lock",
		"package-lock.json",
		"packages.lock.json",
		"pnpm-lock.yaml",
		"poetry.lock",
		"pom.xml",
		"pubspec.lock",
		"renv.lock",
		"requirements.txt",
		"yarn.lock",
	}

	count := 0

	for _, file := range lockfiles {
		_, err := lockfile.ExtractDeps(openTestDepFile("/path/to/my/"+file), "")

		if errors.Is(err, lockfile.ErrExtractorNotFound) {
			t.Errorf("No extractor was found for %s", file)
		}

		count++
	}

	// gradle.lockfile and buildscript-gradle.lockfile use the same parser
	count -= 1

	expectNumberOfParsersCalled(t, count)
}

func TestExtractDeps_ExtractorNotFound(t *testing.T) {
	t.Parallel()

	_, err := lockfile.ExtractDeps(openTestDepFile("/path/to/my/"), "")

	if err == nil {
		t.Errorf("Expected to get an error but did not")
	}

	if !errors.Is(err, lockfile.ErrExtractorNotFound) {
		t.Errorf("Did not get the expected ErrExtractorNotFound error - got %v instead", err)
	}
}

func TestExtractDeps_ExtractorNotFound_WithExplicitExtractAs(t *testing.T) {
	t.Parallel()

	_, err := lockfile.ExtractDeps(openTestDepFile("/path/to/my/"), "unsupported")

	if err == nil {
		t.Errorf("Expected to get an error but did not")
	}

	if !errors.Is(err, lockfile.ErrExtractorNotFound) {
		t.Errorf("Did not get the expected ErrExtractorNotFound error - got %v instead", err)
	}
}

func TestListExtractors(t *testing.T) {
	t.Parallel()

	extractors := lockfile.ListExtractors()

	firstExpected := "Cargo.lock"
	//nolint:ifshort
	lastExpected := "yarn.lock"

	if first := extractors[0]; first != firstExpected {
		t.Errorf("Expected first element to be %s, but got %s", firstExpected, first)
	}

	if last := extractors[len(extractors)-1]; last != lastExpected {
		t.Errorf("Expected last element to be %s, but got %s", lastExpected, last)
	}
}
