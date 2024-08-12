package lockfile_test

import (
	"github.com/google/osv-scanner/pkg/lockfile"
)

func MockAllMatchers() {
	// package.json
	lockfile.YarnExtractor.Matcher = SuccessfulMatcher{}
	lockfile.PnpmExtractor.Matcher = SuccessfulMatcher{}
	lockfile.NpmExtractor.Matcher = SuccessfulMatcher{}
	// build.gradle
	lockfile.GradleExtractor.Matcher = SuccessfulMatcher{}
	lockfile.GradleVerificationExtractor.Matcher = SuccessfulMatcher{}
	// Pipfile (pipenv)
	lockfile.PipenvExtractor.Matcher = SuccessfulMatcher{}
	// pyproject.toml (poetry)
	lockfile.PoetryExtractor.Matcher = SuccessfulMatcher{}
	// Gemfile (ruby)
	lockfile.GemfileExtractor.Matcher = SuccessfulMatcher{}
	// NuGet packages.lock.json
	lockfile.NuGetExtractor.Matcher = SuccessfulMatcher{}
	// Composer composer.json
	lockfile.ComposerExtractor.Matcher = SuccessfulMatcher{}
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

func (m FailingMatcher) GetSourceFile(_ lockfile.DepFile) (lockfile.DepFile, error) {
	return nil, nil
}

func (m FailingMatcher) Match(_ lockfile.DepFile, _ []lockfile.PackageDetails) error {
	return m.Error
}

var _ lockfile.Matcher = FailingMatcher{}
