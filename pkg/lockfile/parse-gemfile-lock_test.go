package lockfile_test

import (
	"io/fs"
	"testing"

	"github.com/google/osv-scanner/pkg/lockfile"
)

func TestGemfileLockExtractor_ShouldExtract(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		path string
		want bool
	}{
		{
			name: "",
			path: "",
			want: false,
		},
		{
			name: "",
			path: "Gemfile.lock",
			want: true,
		},
		{
			name: "",
			path: "path/to/my/Gemfile.lock",
			want: true,
		},
		{
			name: "",
			path: "path/to/my/Gemfile.lock/file",
			want: false,
		},
		{
			name: "",
			path: "path/to/my/Gemfile.lock.file",
			want: false,
		},
		{
			name: "",
			path: "path.to.my.Gemfile.lock",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := lockfile.GemfileLockExtractor{}
			got := e.ShouldExtract(tt.path)
			if got != tt.want {
				t.Errorf("Extract() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseGemfileLock_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseGemfileLock("fixtures/bundler/does-not-exist")

	expectErrIs(t, err, fs.ErrNotExist)
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseGemfileLock_NoSpecSection(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseGemfileLock("fixtures/bundler/no-spec-section.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseGemfileLock_NoGemSection(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseGemfileLock("fixtures/bundler/no-gem-section.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseGemfileLock_NoGems(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseGemfileLock("fixtures/bundler/no-gems.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseGemfileLock_OneGem(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseGemfileLock("fixtures/bundler/one-gem.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "ast",
			Version:   "2.4.2",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
	})
}

func TestParseGemfileLock_SomeGems(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseGemfileLock("fixtures/bundler/some-gems.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "coderay",
			Version:   "1.1.3",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "method_source",
			Version:   "1.0.0",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "pry",
			Version:   "0.14.1",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
	})
}

func TestParseGemfileLock_MultipleGems(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseGemfileLock("fixtures/bundler/multiple-gems.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "bundler-audit",
			Version:   "0.9.0.1",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "coderay",
			Version:   "1.1.3",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "dotenv",
			Version:   "2.7.6",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "method_source",
			Version:   "1.0.0",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "pry",
			Version:   "0.14.1",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "thor",
			Version:   "1.2.1",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
	})
}

func TestParseGemfileLock_Rails(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseGemfileLock("fixtures/bundler/rails.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "actioncable",
			Version:   "7.0.2.2",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "actionmailbox",
			Version:   "7.0.2.2",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "actionmailer",
			Version:   "7.0.2.2",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "actionpack",
			Version:   "7.0.2.2",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "actiontext",
			Version:   "7.0.2.2",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "actionview",
			Version:   "7.0.2.2",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "activejob",
			Version:   "7.0.2.2",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "activemodel",
			Version:   "7.0.2.2",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "activerecord",
			Version:   "7.0.2.2",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "activestorage",
			Version:   "7.0.2.2",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "activesupport",
			Version:   "7.0.2.2",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "builder",
			Version:   "3.2.4",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "concurrent-ruby",
			Version:   "1.1.9",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "crass",
			Version:   "1.0.6",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "digest",
			Version:   "3.1.0",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "erubi",
			Version:   "1.10.0",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "globalid",
			Version:   "1.0.0",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "i18n",
			Version:   "1.10.0",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "io-wait",
			Version:   "0.2.1",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "loofah",
			Version:   "2.14.0",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "mail",
			Version:   "2.7.1",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "marcel",
			Version:   "1.0.2",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "method_source",
			Version:   "1.0.0",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "mini_mime",
			Version:   "1.1.2",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "minitest",
			Version:   "5.15.0",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "net-imap",
			Version:   "0.2.3",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "net-pop",
			Version:   "0.1.1",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "net-protocol",
			Version:   "0.1.2",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "net-smtp",
			Version:   "0.3.1",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "nio4r",
			Version:   "2.5.8",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "racc",
			Version:   "1.6.0",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "rack",
			Version:   "2.2.3",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "rack-test",
			Version:   "1.1.0",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "rails",
			Version:   "7.0.2.2",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "rails-dom-testing",
			Version:   "2.0.3",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "rails-html-sanitizer",
			Version:   "1.4.2",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "railties",
			Version:   "7.0.2.2",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "rake",
			Version:   "13.0.6",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "strscan",
			Version:   "3.0.1",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "thor",
			Version:   "1.2.1",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "timeout",
			Version:   "0.2.0",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "tzinfo",
			Version:   "2.0.4",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "websocket-driver",
			Version:   "0.7.5",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "websocket-extensions",
			Version:   "0.1.5",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "zeitwerk",
			Version:   "2.5.4",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "nokogiri",
			Version:   "1.13.3",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
	})
}

func TestParseGemfileLock_Rubocop(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseGemfileLock("fixtures/bundler/rubocop.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "ast",
			Version:   "2.4.2",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "parallel",
			Version:   "1.21.0",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "parser",
			Version:   "3.1.1.0",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "rainbow",
			Version:   "3.1.1",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "regexp_parser",
			Version:   "2.2.1",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "rexml",
			Version:   "3.2.5",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "rubocop",
			Version:   "1.25.1",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "rubocop-ast",
			Version:   "1.16.0",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "ruby-progressbar",
			Version:   "1.11.0",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "unicode-display_width",
			Version:   "2.1.0",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
	})
}

func TestParseGemfileLock_HasLocalGem(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseGemfileLock("fixtures/bundler/has-local-gem.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "backbone-on-rails",
			Version:   "1.2.0.0",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "actionpack",
			Version:   "7.0.2.2",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "actionview",
			Version:   "7.0.2.2",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "activesupport",
			Version:   "7.0.2.2",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "builder",
			Version:   "3.2.4",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "coffee-script",
			Version:   "2.4.1",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "coffee-script-source",
			Version:   "1.12.2",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "concurrent-ruby",
			Version:   "1.1.9",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "crass",
			Version:   "1.0.6",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "eco",
			Version:   "1.0.0",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "ejs",
			Version:   "1.1.1",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "erubi",
			Version:   "1.10.0",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "execjs",
			Version:   "2.8.1",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "i18n",
			Version:   "1.10.0",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "jquery-rails",
			Version:   "4.4.0",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "loofah",
			Version:   "2.14.0",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "method_source",
			Version:   "1.0.0",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "minitest",
			Version:   "5.15.0",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "racc",
			Version:   "1.6.0",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "rack",
			Version:   "2.2.3",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "rack-test",
			Version:   "1.1.0",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "rails-dom-testing",
			Version:   "2.0.3",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "rails-html-sanitizer",
			Version:   "1.4.2",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "railties",
			Version:   "7.0.2.2",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "rake",
			Version:   "13.0.6",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "thor",
			Version:   "1.2.1",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "tzinfo",
			Version:   "2.0.4",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "zeitwerk",
			Version:   "2.5.4",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "nokogiri",
			Version:   "1.13.3",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
		{
			Name:      "eco-source",
			Version:   "1.1.0.rc.1",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
		},
	})
}

func TestParseGemfileLock_HasGitGem(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseGemfileLock("fixtures/bundler/has-git-gem.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "hanami-controller",
			Version:   "2.0.0.alpha1",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
			Commit:    "027dbe2e56397b534e859fc283990cad1b6addd6",
		},
		{
			Name:      "hanami-utils",
			Version:   "2.0.0.alpha1",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
			Commit:    "5904fc9a70683b8749aa2861257d0c8c01eae4aa",
		},
		{
			Name:      "concurrent-ruby",
			Version:   "1.1.7",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
			Commit:    "",
		},
		{
			Name:      "rack",
			Version:   "2.2.3",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
			Commit:    "",
		},
		{
			Name:      "transproc",
			Version:   "1.1.1",
			Ecosystem: lockfile.BundlerEcosystem,
			CompareAs: lockfile.BundlerEcosystem,
			Commit:    "",
		},
	})
}
