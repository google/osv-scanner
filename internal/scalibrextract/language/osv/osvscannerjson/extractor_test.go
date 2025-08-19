package osvscannerjson_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/testing/extracttest"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/language/osv/osvscannerjson"
	"github.com/google/osv-scanner/v2/pkg/models"
)

func TestExtractor_Extract(t *testing.T) {
	t.Parallel()

	tests := []extracttest.TestTableEntry{
		{
			Name: "invalid yaml",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/not-json.txt",
			},
			WantErr: extracttest.ContainsErrStr{Str: "could not extract from"},
		},
		{
			Name: "empty",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty.json",
			},
			WantPackages: []*extractor.Package{},
		},
		{
			Name: "one package",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/one-package.json",
			},
			WantPackages: []*extractor.Package{
				{
					Name:      "activesupport",
					Version:   "7.0.7",
					Locations: []string{"testdata/one-package.json"},
					PURLType:  "placeholder",
					Plugins:   []string{"osv/osvscannerjson"},
					Metadata: &osvscannerjson.Metadata{
						Ecosystem: "RubyGems",
						SourceInfo: models.SourceInfo{
							Path: "/path/to/Gemfile.lock",
							Type: "lockfile",
						},
					},
				},
			},
		},
		{
			Name: "one package with commit",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/one-package-commit.json",
			},
			WantPackages: []*extractor.Package{
				{
					Locations: []string{"testdata/one-package-commit.json"},
					PURLType:  "placeholder",
					Plugins:   []string{"osv/osvscannerjson"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "9a6bd55c9d0722cb101fe85a3b22d89e4ff4fe52",
					},
					Metadata: &osvscannerjson.Metadata{
						SourceInfo: models.SourceInfo{
							Path: "/path/to/Gemfile.lock",
							Type: "lockfile",
						},
					},
				},
			},
		},
		{
			Name: "multiple packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/multiple-packages-with-vulns.json",
			},
			WantPackages: []*extractor.Package{
				{
					Name:      "crossbeam-utils",
					Version:   "0.6.6",
					Locations: []string{"testdata/multiple-packages-with-vulns.json"},
					PURLType:  "placeholder",
					Plugins:   []string{"osv/osvscannerjson"},
					Metadata: &osvscannerjson.Metadata{
						Ecosystem: "crates.io",
						SourceInfo: models.SourceInfo{
							Path: "/path/to/Cargo.lock",
							Type: "lockfile",
						},
					},
				},
				{
					Name:      "memoffset",
					Version:   "0.5.6",
					Locations: []string{"testdata/multiple-packages-with-vulns.json"},
					PURLType:  "placeholder",
					Plugins:   []string{"osv/osvscannerjson"},
					Metadata: &osvscannerjson.Metadata{
						Ecosystem: "crates.io",
						SourceInfo: models.SourceInfo{
							Path: "/path/to/Cargo.lock",
							Type: "lockfile",
						},
					},
				},
				{
					Name:      "smallvec",
					Version:   "1.6.0",
					Locations: []string{"testdata/multiple-packages-with-vulns.json"},
					PURLType:  "placeholder",
					Plugins:   []string{"osv/osvscannerjson"},
					Metadata: &osvscannerjson.Metadata{
						Ecosystem: "crates.io",
						SourceInfo: models.SourceInfo{
							Path: "/path/to/Cargo.lock",
							Type: "lockfile",
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			extr := osvscannerjson.Extractor{}

			scanInput := extracttest.GenerateScanInputMock(t, tt.InputConfig)
			defer extracttest.CloseTestScanInput(t, scanInput)

			got, err := extr.Extract(t.Context(), &scanInput)

			if diff := cmp.Diff(tt.WantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("%s.Extract(%q) error diff (-want +got):\n%s", extr.Name(), tt.InputConfig.Path, diff)
				return
			}

			if diff := cmp.Diff(tt.WantPackages, got.Packages, cmpopts.SortSlices(extracttest.PackageCmpLess)); diff != "" {
				t.Errorf("%s.Extract(%q) diff (-want +got):\n%s", extr.Name(), tt.InputConfig.Path, diff)
			}
		})
	}
}
