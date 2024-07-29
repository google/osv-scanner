package lockfilescalibr_test

import (
	"testing"

	"github.com/google/osv-scanner/internal/lockfilescalibr"
	"github.com/google/osv-scanner/internal/lockfilescalibr/extractor"
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
				Path: "",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				Path: "Gemfile.lock",
			},
			want: true,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				Path: "path/to/my/Gemfile.lock",
			},
			want: true,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				Path: "path/to/my/Gemfile.lock/file",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				Path: "path/to/my/Gemfile.lock.file",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				Path: "path.to.my.Gemfile.lock",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := lockfilescalibr.GemfileLockExtractor{}
			got := e.FileRequired(tt.inputConfig.Path, GenerateFileInfoMock(t, tt.inputConfig))
			if got != tt.want {
				t.Errorf("FileRequired(%s, FileInfo) got = %v, want %v", tt.inputConfig.Path, got, tt.want)
			}
		})
	}
}

func TestGemfileLockExtractor_Extract(t *testing.T) {
	t.Parallel()

	// TODO: Add commit check
	tests := []TestTableEntry{
		{
			Name: "no spec section",
			InputConfig: ScanInputMockConfig{
				Path: "fixtures/bundler/no-spec-section.lock",
			},
			WantInventory: []*extractor.Inventory{},
		},
		{
			Name: "no gem section",
			InputConfig: ScanInputMockConfig{
				Path: "fixtures/bundler/no-gem-section.lock",
			},
			WantInventory: []*extractor.Inventory{},
		},
		{
			Name: "no gems",
			InputConfig: ScanInputMockConfig{
				Path: "fixtures/bundler/no-gems.lock",
			},
			WantInventory: []*extractor.Inventory{},
		},
		{
			Name: "one gem",
			InputConfig: ScanInputMockConfig{
				Path: "fixtures/bundler/one-gem.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:       "ast",
					Version:    "2.4.2",
					Locations:  []string{"fixtures/bundler/one-gem.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
			},
		},
		{
			Name: "some gems",
			InputConfig: ScanInputMockConfig{
				Path: "fixtures/bundler/some-gems.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:       "coderay",
					Version:    "1.1.3",
					Locations:  []string{"fixtures/bundler/some-gems.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "method_source",
					Version:    "1.0.0",
					Locations:  []string{"fixtures/bundler/some-gems.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "pry",
					Version:    "0.14.1",
					Locations:  []string{"fixtures/bundler/some-gems.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
			},
		},
		{
			Name: "multiple gems",
			InputConfig: ScanInputMockConfig{
				Path: "fixtures/bundler/multiple-gems.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:       "bundler-audit",
					Version:    "0.9.0.1",
					Locations:  []string{"fixtures/bundler/multiple-gems.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "coderay",
					Version:    "1.1.3",
					Locations:  []string{"fixtures/bundler/multiple-gems.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "dotenv",
					Version:    "2.7.6",
					Locations:  []string{"fixtures/bundler/multiple-gems.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "method_source",
					Version:    "1.0.0",
					Locations:  []string{"fixtures/bundler/multiple-gems.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "pry",
					Version:    "0.14.1",
					Locations:  []string{"fixtures/bundler/multiple-gems.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "thor",
					Version:    "1.2.1",
					Locations:  []string{"fixtures/bundler/multiple-gems.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
			},
		},
		{
			Name: "rails",
			InputConfig: ScanInputMockConfig{
				Path: "fixtures/bundler/rails.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:       "actioncable",
					Version:    "7.0.2.2",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "actionmailbox",
					Version:    "7.0.2.2",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "actionmailer",
					Version:    "7.0.2.2",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "actionpack",
					Version:    "7.0.2.2",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "actiontext",
					Version:    "7.0.2.2",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "actionview",
					Version:    "7.0.2.2",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "activejob",
					Version:    "7.0.2.2",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "activemodel",
					Version:    "7.0.2.2",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "activerecord",
					Version:    "7.0.2.2",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "activestorage",
					Version:    "7.0.2.2",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "activesupport",
					Version:    "7.0.2.2",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "builder",
					Version:    "3.2.4",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "concurrent-ruby",
					Version:    "1.1.9",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "crass",
					Version:    "1.0.6",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "digest",
					Version:    "3.1.0",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "erubi",
					Version:    "1.10.0",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "globalid",
					Version:    "1.0.0",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "i18n",
					Version:    "1.10.0",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "io-wait",
					Version:    "0.2.1",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "loofah",
					Version:    "2.14.0",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "mail",
					Version:    "2.7.1",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "marcel",
					Version:    "1.0.2",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "method_source",
					Version:    "1.0.0",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "mini_mime",
					Version:    "1.1.2",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "minitest",
					Version:    "5.15.0",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "net-imap",
					Version:    "0.2.3",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "net-pop",
					Version:    "0.1.1",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "net-protocol",
					Version:    "0.1.2",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "net-smtp",
					Version:    "0.3.1",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "nio4r",
					Version:    "2.5.8",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "racc",
					Version:    "1.6.0",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "rack",
					Version:    "2.2.3",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "rack-test",
					Version:    "1.1.0",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "rails",
					Version:    "7.0.2.2",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "rails-dom-testing",
					Version:    "2.0.3",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "rails-html-sanitizer",
					Version:    "1.4.2",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "railties",
					Version:    "7.0.2.2",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "rake",
					Version:    "13.0.6",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "strscan",
					Version:    "3.0.1",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "thor",
					Version:    "1.2.1",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "timeout",
					Version:    "0.2.0",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "tzinfo",
					Version:    "2.0.4",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "websocket-driver",
					Version:    "0.7.5",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "websocket-extensions",
					Version:    "0.1.5",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "zeitwerk",
					Version:    "2.5.4",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "nokogiri",
					Version:    "1.13.3",
					Locations:  []string{"fixtures/bundler/rails.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
			},
		},
		{
			Name: "rubocop",
			InputConfig: ScanInputMockConfig{
				Path: "fixtures/bundler/rubocop.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:       "ast",
					Version:    "2.4.2",
					Locations:  []string{"fixtures/bundler/rubocop.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "parallel",
					Version:    "1.21.0",
					Locations:  []string{"fixtures/bundler/rubocop.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "parser",
					Version:    "3.1.1.0",
					Locations:  []string{"fixtures/bundler/rubocop.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "rainbow",
					Version:    "3.1.1",
					Locations:  []string{"fixtures/bundler/rubocop.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "regexp_parser",
					Version:    "2.2.1",
					Locations:  []string{"fixtures/bundler/rubocop.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "rexml",
					Version:    "3.2.5",
					Locations:  []string{"fixtures/bundler/rubocop.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "rubocop",
					Version:    "1.25.1",
					Locations:  []string{"fixtures/bundler/rubocop.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "rubocop-ast",
					Version:    "1.16.0",
					Locations:  []string{"fixtures/bundler/rubocop.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "ruby-progressbar",
					Version:    "1.11.0",
					Locations:  []string{"fixtures/bundler/rubocop.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "unicode-display_width",
					Version:    "2.1.0",
					Locations:  []string{"fixtures/bundler/rubocop.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
			},
		},
		{
			Name: "has local gem",
			InputConfig: ScanInputMockConfig{
				Path: "fixtures/bundler/has-local-gem.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:       "backbone-on-rails",
					Version:    "1.2.0.0",
					Locations:  []string{"fixtures/bundler/has-local-gem.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "actionpack",
					Version:    "7.0.2.2",
					Locations:  []string{"fixtures/bundler/has-local-gem.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "actionview",
					Version:    "7.0.2.2",
					Locations:  []string{"fixtures/bundler/has-local-gem.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "activesupport",
					Version:    "7.0.2.2",
					Locations:  []string{"fixtures/bundler/has-local-gem.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "builder",
					Version:    "3.2.4",
					Locations:  []string{"fixtures/bundler/has-local-gem.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "coffee-script",
					Version:    "2.4.1",
					Locations:  []string{"fixtures/bundler/has-local-gem.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "coffee-script-source",
					Version:    "1.12.2",
					Locations:  []string{"fixtures/bundler/has-local-gem.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "concurrent-ruby",
					Version:    "1.1.9",
					Locations:  []string{"fixtures/bundler/has-local-gem.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "crass",
					Version:    "1.0.6",
					Locations:  []string{"fixtures/bundler/has-local-gem.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "eco",
					Version:    "1.0.0",
					Locations:  []string{"fixtures/bundler/has-local-gem.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "ejs",
					Version:    "1.1.1",
					Locations:  []string{"fixtures/bundler/has-local-gem.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "erubi",
					Version:    "1.10.0",
					Locations:  []string{"fixtures/bundler/has-local-gem.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "execjs",
					Version:    "2.8.1",
					Locations:  []string{"fixtures/bundler/has-local-gem.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "i18n",
					Version:    "1.10.0",
					Locations:  []string{"fixtures/bundler/has-local-gem.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "jquery-rails",
					Version:    "4.4.0",
					Locations:  []string{"fixtures/bundler/has-local-gem.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "loofah",
					Version:    "2.14.0",
					Locations:  []string{"fixtures/bundler/has-local-gem.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "method_source",
					Version:    "1.0.0",
					Locations:  []string{"fixtures/bundler/has-local-gem.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "minitest",
					Version:    "5.15.0",
					Locations:  []string{"fixtures/bundler/has-local-gem.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "racc",
					Version:    "1.6.0",
					Locations:  []string{"fixtures/bundler/has-local-gem.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "rack",
					Version:    "2.2.3",
					Locations:  []string{"fixtures/bundler/has-local-gem.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "rack-test",
					Version:    "1.1.0",
					Locations:  []string{"fixtures/bundler/has-local-gem.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "rails-dom-testing",
					Version:    "2.0.3",
					Locations:  []string{"fixtures/bundler/has-local-gem.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "rails-html-sanitizer",
					Version:    "1.4.2",
					Locations:  []string{"fixtures/bundler/has-local-gem.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "railties",
					Version:    "7.0.2.2",
					Locations:  []string{"fixtures/bundler/has-local-gem.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "rake",
					Version:    "13.0.6",
					Locations:  []string{"fixtures/bundler/has-local-gem.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "thor",
					Version:    "1.2.1",
					Locations:  []string{"fixtures/bundler/has-local-gem.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "tzinfo",
					Version:    "2.0.4",
					Locations:  []string{"fixtures/bundler/has-local-gem.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "zeitwerk",
					Version:    "2.5.4",
					Locations:  []string{"fixtures/bundler/has-local-gem.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "nokogiri",
					Version:    "1.13.3",
					Locations:  []string{"fixtures/bundler/has-local-gem.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "eco-source",
					Version:    "1.1.0.rc.1",
					Locations:  []string{"fixtures/bundler/has-local-gem.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
			},
		},
		{
			Name: "has git gem",
			InputConfig: ScanInputMockConfig{
				Path: "fixtures/bundler/has-git-gem.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "hanami-controller",
					Version:   "2.0.0.alpha1",
					Locations: []string{"fixtures/bundler/has-git-gem.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "027dbe2e56397b534e859fc283990cad1b6addd6",
					},
				},
				{
					Name:      "hanami-utils",
					Version:   "2.0.0.alpha1",
					Locations: []string{"fixtures/bundler/has-git-gem.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "5904fc9a70683b8749aa2861257d0c8c01eae4aa",
					},
				},
				{
					Name:       "concurrent-ruby",
					Version:    "1.1.7",
					Locations:  []string{"fixtures/bundler/has-git-gem.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "rack",
					Version:    "2.2.3",
					Locations:  []string{"fixtures/bundler/has-git-gem.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
				{
					Name:       "transproc",
					Version:    "1.1.1",
					Locations:  []string{"fixtures/bundler/has-git-gem.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{},
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			e := lockfilescalibr.GemfileLockExtractor{}
			_, _ = ExtractionTester(t, e, tt)
		})
	}
}
