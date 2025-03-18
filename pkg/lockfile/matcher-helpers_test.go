package lockfile_test

import (
	"github.com/google/osv-scanner/pkg/lockfile"
)

func MockAllMatchers() {
	// package.json
	lockfile.YarnExtractor.Matchers = []lockfile.Matcher{SuccessfulMatcher{}}
	lockfile.PnpmExtractor.Matchers = []lockfile.Matcher{SuccessfulMatcher{}}
	lockfile.NpmExtractor.Matchers = []lockfile.Matcher{SuccessfulMatcher{}}
	// build.gradle
	lockfile.GradleExtractor.Matchers = []lockfile.Matcher{SuccessfulMatcher{}}
	lockfile.GradleVerificationExtractor.Matchers = []lockfile.Matcher{SuccessfulMatcher{}}
	// Pipfile (pipenv)
	lockfile.PipenvExtractor.Matchers = []lockfile.Matcher{SuccessfulMatcher{}}
	// pyproject.toml (poetry)
	lockfile.PoetryExtractor.Matchers = []lockfile.Matcher{SuccessfulMatcher{}}
	// Gemfile (ruby)
	lockfile.GemfileExtractor.Matchers = []lockfile.Matcher{SuccessfulMatcher{}}
	// Composer composer.json
	lockfile.ComposerExtractor.Matchers = []lockfile.Matcher{SuccessfulMatcher{}}
}

type SuccessfulMatcher struct{}

func (m SuccessfulMatcher) GetSourceFile(_ lockfile.DepFile) (lockfile.DepFile, error) {
	return nil, nil
}

func (m SuccessfulMatcher) Match(_ lockfile.DepFile, _ []lockfile.PackageDetails) error {
	return nil
}

var _ lockfile.Matcher = SuccessfulMatcher{}

type FailingMatcher struct {
	Error error
}

func (m FailingMatcher) GetSourceFile(f lockfile.DepFile) (lockfile.DepFile, error) {
	return f, nil
}

func (m FailingMatcher) Match(_ lockfile.DepFile, _ []lockfile.PackageDetails) error {
	return m.Error
}

var _ lockfile.Matcher = FailingMatcher{}
