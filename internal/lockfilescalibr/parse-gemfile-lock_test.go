package lockfilescalibr_test

import (
	"testing"

	"github.com/google/osv-scanner/internal/lockfilescalibr"
)

func TestGemfileLockExtractor_FileRequired(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		inputConfig ScanInputMockConfig
		want        bool
	}{
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				path: "",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				path: "Gemfile.lock",
			},
			want: true,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				path: "path/to/my/Gemfile.lock",
			},
			want: true,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				path: "path/to/my/Gemfile.lock/file",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				path: "path/to/my/Gemfile.lock.file",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				path: "path.to.my.Gemfile.lock",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := lockfilescalibr.GemfileLockExtractor{}
			got := e.FileRequired(tt.inputConfig.path, GenerateFileInfoMock(t, tt.inputConfig))
			if got != tt.want {
				t.Errorf("FileRequired(%s, FileInfo) got = %v, want %v", tt.inputConfig.path, got, tt.want)
			}
		})
	}
}

func TestGemfileLockExtractor_Extract(t *testing.T) {
	t.Parallel()

	// TODO: Add commit check
	tests := []testTableEntry{
		{
			name: "no spec section",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/bundler/no-spec-section.lock",
			},
			wantInventory: []*lockfilescalibr.Inventory{},
		},
		{
			name: "no gem section",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/bundler/no-gem-section.lock",
			},
			wantInventory: []*lockfilescalibr.Inventory{},
		},
		{
			name: "no gems",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/bundler/no-gems.lock",
			},
			wantInventory: []*lockfilescalibr.Inventory{},
		},
		{
			name: "one gem",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/bundler/one-gem.lock",
			},
			wantInventory: []*lockfilescalibr.Inventory{
				{
					Name:       "ast",
					Version:    "2.4.2",
					Locations:  []string{"fixtures/bundler/one-gem.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
			},
		},
		{
			name: "some gems",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/bundler/some-gems.lock",
			},
			wantInventory: []*lockfilescalibr.Inventory{
				{
					Name:       "coderay",
					Version:    "1.1.3",
					Locations:  []string{"fixtures/bundler/some-gems.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "method_source",
					Version:    "1.0.0",
					Locations:  []string{"fixtures/bundler/some-gems.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "pry",
					Version:    "0.14.1",
					Locations:  []string{"fixtures/bundler/some-gems.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
			},
		},
		{
			name: "multiple gems",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/bundler/multiple-gems.lock",
			},
			wantInventory: []*lockfilescalibr.Inventory{
				{
					Name:       "bundler-audit",
					Version:    "0.9.0.1",
					Locations:  []string{"fixtures/bundler/multiple-gems.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "coderay",
					Version:    "1.1.3",
					Locations:  []string{"fixtures/bundler/multiple-gems.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "dotenv",
					Version:    "2.7.6",
					Locations:  []string{"fixtures/bundler/multiple-gems.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "method_source",
					Version:    "1.0.0",
					Locations:  []string{"fixtures/bundler/multiple-gems.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "pry",
					Version:    "0.14.1",
					Locations:  []string{"fixtures/bundler/multiple-gems.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "thor",
					Version:    "1.2.1",
					Locations:  []string{"fixtures/bundler/multiple-gems.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
			},
		},
		{
			name: "rails",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/bundler/rails.lock",
			},
			wantInventory: []*lockfilescalibr.Inventory{
				{
					Name:       "actioncable",
					Version:    "7.0.2.2",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "actionmailbox",
					Version:    "7.0.2.2",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "actionmailer",
					Version:    "7.0.2.2",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "actionpack",
					Version:    "7.0.2.2",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "actiontext",
					Version:    "7.0.2.2",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "actionview",
					Version:    "7.0.2.2",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "activejob",
					Version:    "7.0.2.2",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "activemodel",
					Version:    "7.0.2.2",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "activerecord",
					Version:    "7.0.2.2",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "activestorage",
					Version:    "7.0.2.2",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "activesupport",
					Version:    "7.0.2.2",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "builder",
					Version:    "3.2.4",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "concurrent-ruby",
					Version:    "1.1.9",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "crass",
					Version:    "1.0.6",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "digest",
					Version:    "3.1.0",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "erubi",
					Version:    "1.10.0",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "globalid",
					Version:    "1.0.0",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "i18n",
					Version:    "1.10.0",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "io-wait",
					Version:    "0.2.1",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "loofah",
					Version:    "2.14.0",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "mail",
					Version:    "2.7.1",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "marcel",
					Version:    "1.0.2",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "method_source",
					Version:    "1.0.0",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "mini_mime",
					Version:    "1.1.2",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "minitest",
					Version:    "5.15.0",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "net-imap",
					Version:    "0.2.3",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "net-pop",
					Version:    "0.1.1",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "net-protocol",
					Version:    "0.1.2",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "net-smtp",
					Version:    "0.3.1",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "nio4r",
					Version:    "2.5.8",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "racc",
					Version:    "1.6.0",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "rack",
					Version:    "2.2.3",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "rack-test",
					Version:    "1.1.0",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "rails",
					Version:    "7.0.2.2",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "rails-dom-testing",
					Version:    "2.0.3",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "rails-html-sanitizer",
					Version:    "1.4.2",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "railties",
					Version:    "7.0.2.2",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "rake",
					Version:    "13.0.6",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "strscan",
					Version:    "3.0.1",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "thor",
					Version:    "1.2.1",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "timeout",
					Version:    "0.2.0",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "tzinfo",
					Version:    "2.0.4",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "websocket-driver",
					Version:    "0.7.5",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "websocket-extensions",
					Version:    "0.1.5",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "zeitwerk",
					Version:    "2.5.4",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "nokogiri",
					Version:    "1.13.3",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
			},
		},
		{
			name: "rubocop",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/bundler/rubocop.lock",
			},
			wantInventory: []*lockfilescalibr.Inventory{
				{
					Name:       "ast",
					Version:    "2.4.2",
					Locations:  []string{"fixtures/bundler/rubocop.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "parallel",
					Version:    "1.21.0",
					Locations:  []string{"fixtures/bundler/rubocop.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "parser",
					Version:    "3.1.1.0",
					Locations:  []string{"fixtures/bundler/rubocop.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "rainbow",
					Version:    "3.1.1",
					Locations:  []string{"fixtures/bundler/rubocop.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "regexp_parser",
					Version:    "2.2.1",
					Locations:  []string{"fixtures/bundler/rubocop.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "rexml",
					Version:    "3.2.5",
					Locations:  []string{"fixtures/bundler/rubocop.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "rubocop",
					Version:    "1.25.1",
					Locations:  []string{"fixtures/bundler/rubocop.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "rubocop-ast",
					Version:    "1.16.0",
					Locations:  []string{"fixtures/bundler/rubocop.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "ruby-progressbar",
					Version:    "1.11.0",
					Locations:  []string{"fixtures/bundler/rubocop.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "unicode-display_width",
					Version:    "2.1.0",
					Locations:  []string{"fixtures/bundler/rubocop.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
			},
		},
		{
			name: "has local gem",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/bundler/has-local-gem.lock",
			},
			wantInventory: []*lockfilescalibr.Inventory{
				{
					Name:       "backbone-on-rails",
					Version:    "1.2.0.0",
					Locations:  []string{"fixtures/bundler/has-local-gem.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "actionpack",
					Version:    "7.0.2.2",
					Locations:  []string{"fixtures/bundler/has-local-gem.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "actionview",
					Version:    "7.0.2.2",
					Locations:  []string{"fixtures/bundler/has-local-gem.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "activesupport",
					Version:    "7.0.2.2",
					Locations:  []string{"fixtures/bundler/has-local-gem.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "builder",
					Version:    "3.2.4",
					Locations:  []string{"fixtures/bundler/has-local-gem.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "coffee-script",
					Version:    "2.4.1",
					Locations:  []string{"fixtures/bundler/has-local-gem.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "coffee-script-source",
					Version:    "1.12.2",
					Locations:  []string{"fixtures/bundler/has-local-gem.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "concurrent-ruby",
					Version:    "1.1.9",
					Locations:  []string{"fixtures/bundler/has-local-gem.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "crass",
					Version:    "1.0.6",
					Locations:  []string{"fixtures/bundler/has-local-gem.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "eco",
					Version:    "1.0.0",
					Locations:  []string{"fixtures/bundler/has-local-gem.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "ejs",
					Version:    "1.1.1",
					Locations:  []string{"fixtures/bundler/has-local-gem.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "erubi",
					Version:    "1.10.0",
					Locations:  []string{"fixtures/bundler/has-local-gem.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "execjs",
					Version:    "2.8.1",
					Locations:  []string{"fixtures/bundler/has-local-gem.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "i18n",
					Version:    "1.10.0",
					Locations:  []string{"fixtures/bundler/has-local-gem.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "jquery-rails",
					Version:    "4.4.0",
					Locations:  []string{"fixtures/bundler/has-local-gem.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "loofah",
					Version:    "2.14.0",
					Locations:  []string{"fixtures/bundler/has-local-gem.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "method_source",
					Version:    "1.0.0",
					Locations:  []string{"fixtures/bundler/has-local-gem.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "minitest",
					Version:    "5.15.0",
					Locations:  []string{"fixtures/bundler/has-local-gem.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "racc",
					Version:    "1.6.0",
					Locations:  []string{"fixtures/bundler/has-local-gem.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "rack",
					Version:    "2.2.3",
					Locations:  []string{"fixtures/bundler/has-local-gem.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "rack-test",
					Version:    "1.1.0",
					Locations:  []string{"fixtures/bundler/has-local-gem.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "rails-dom-testing",
					Version:    "2.0.3",
					Locations:  []string{"fixtures/bundler/has-local-gem.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "rails-html-sanitizer",
					Version:    "1.4.2",
					Locations:  []string{"fixtures/bundler/has-local-gem.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "railties",
					Version:    "7.0.2.2",
					Locations:  []string{"fixtures/bundler/has-local-gem.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "rake",
					Version:    "13.0.6",
					Locations:  []string{"fixtures/bundler/has-local-gem.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "thor",
					Version:    "1.2.1",
					Locations:  []string{"fixtures/bundler/has-local-gem.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "tzinfo",
					Version:    "2.0.4",
					Locations:  []string{"fixtures/bundler/has-local-gem.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "zeitwerk",
					Version:    "2.5.4",
					Locations:  []string{"fixtures/bundler/has-local-gem.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "nokogiri",
					Version:    "1.13.3",
					Locations:  []string{"fixtures/bundler/has-local-gem.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "eco-source",
					Version:    "1.1.0.rc.1",
					Locations:  []string{"fixtures/bundler/has-local-gem.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
			},
		},
		{
			name: "has git gem",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/bundler/has-git-gem.lock",
			},
			wantInventory: []*lockfilescalibr.Inventory{
				{
					Name:      "hanami-controller",
					Version:   "2.0.0.alpha1",
					Locations: []string{"fixtures/bundler/has-git-gem.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{
						Commit: "027dbe2e56397b534e859fc283990cad1b6addd6",
					},
				},
				{
					Name:      "hanami-utils",
					Version:   "2.0.0.alpha1",
					Locations: []string{"fixtures/bundler/has-git-gem.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{
						Commit: "5904fc9a70683b8749aa2861257d0c8c01eae4aa",
					},
				},
				{
					Name:       "concurrent-ruby",
					Version:    "1.1.7",
					Locations:  []string{"fixtures/bundler/has-git-gem.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "rack",
					Version:    "2.2.3",
					Locations:  []string{"fixtures/bundler/has-git-gem.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
				{
					Name:       "transproc",
					Version:    "1.1.1",
					Locations:  []string{"fixtures/bundler/has-git-gem.lock"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := lockfilescalibr.GemfileLockExtractor{}
			_, _ = extractionTester(t, e, tt)
		})
	}
}
