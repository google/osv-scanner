package lockfile_test

import (
	"errors"
	"fmt"
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
	return TestDepFile{}, fmt.Errorf("file opening is not supported")
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

	lockfiles := []string{
		"buildscript-gradle.lockfile",
		"Cargo.lock",
		"composer.lock",
		"Gemfile.lock",
		"go.mod",
		"gradle.lockfile",
		"mix.lock",
		"Pipfile.lock",
		"package-lock.json",
		"packages.lock.json",
		"pnpm-lock.yaml",
		"poetry.lock",
		"pom.xml",
		"pubspec.lock",
		"requirements.txt",
		"yarn.lock",
	}

	for _, file := range lockfiles {
		extractor, extractedAs := lockfile.FindExtractor("/path/to/my/"+file, "")

		if extractor == nil {
			t.Errorf("Expected a extractor to be found for %s but did not", file)
		}

		if file != extractedAs {
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
		"mix.lock",
		"Pipfile.lock",
		"package-lock.json",
		"packages.lock.json",
		"pnpm-lock.yaml",
		"poetry.lock",
		"pom.xml",
		"pubspec.lock",
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

func TestListExtractors(t *testing.T) {
	t.Parallel()

	extractors := lockfile.ListExtractors()

	firstExpected := "buildscript-gradle.lockfile"
	//nolint:ifshort
	lastExpected := "yarn.lock"

	if first := extractors[0]; first != firstExpected {
		t.Errorf("Expected first element to be %s, but got %s", firstExpected, first)
	}

	if last := extractors[len(extractors)-1]; last != lastExpected {
		t.Errorf("Expected last element to be %s, but got %s", lastExpected, last)
	}
}
