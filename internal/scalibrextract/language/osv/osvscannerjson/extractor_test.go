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
			Name: "invalid_yaml",
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
			Name: "one_package",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/one-package.json",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "activesupport",
					Version:  "7.0.7",
					Location: extractor.LocationFromPath("testdata/one-package.json"),
					PURLType: "gem",
					Plugins:  []string{"osv/osvscannerjson"},
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
			Name: "one_package_with_commit",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/one-package-commit.json",
			},
			WantPackages: []*extractor.Package{
				{
					Location: extractor.LocationFromPath("testdata/one-package-commit.json"),
					Plugins:  []string{"osv/osvscannerjson"},
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
			Name: "multiple_packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/multiple-packages-with-vulns.json",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "crossbeam-utils",
					Version:  "0.6.6",
					Location: extractor.LocationFromPath("testdata/multiple-packages-with-vulns.json"),
					PURLType: "cargo",
					Plugins:  []string{"osv/osvscannerjson"},
					Metadata: &osvscannerjson.Metadata{
						Ecosystem: "crates.io",
						SourceInfo: models.SourceInfo{
							Path: "/path/to/Cargo.lock",
							Type: "lockfile",
						},
					},
				},
				{
					Name:     "memoffset",
					Version:  "0.5.6",
					Location: extractor.LocationFromPath("testdata/multiple-packages-with-vulns.json"),
					PURLType: "cargo",
					Plugins:  []string{"osv/osvscannerjson"},
					Metadata: &osvscannerjson.Metadata{
						Ecosystem: "crates.io",
						SourceInfo: models.SourceInfo{
							Path: "/path/to/Cargo.lock",
							Type: "lockfile",
						},
					},
				},
				{
					Name:     "smallvec",
					Version:  "1.6.0",
					Location: extractor.LocationFromPath("testdata/multiple-packages-with-vulns.json"),
					PURLType: "cargo",
					Plugins:  []string{"osv/osvscannerjson"},
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

func TestExtractor_Extract_PURLs(t *testing.T) {
	t.Parallel()

	extr := osvscannerjson.Extractor{}

	scanInput := extracttest.GenerateScanInputMock(t, extracttest.ScanInputMockConfig{
		Path: "testdata/multiple-ecosystems.json",
	})
	defer extracttest.CloseTestScanInput(t, scanInput)

	got, err := extr.Extract(t.Context(), &scanInput)
	if err != nil {
		t.Fatalf("%s.Extract() unexpected error: %v", extr.Name(), err)
	}

	gotPURLs := make([]string, 0, len(got.Packages))
	for _, pkg := range got.Packages {
		p := pkg.PURL()
		if p == nil {
			gotPURLs = append(gotPURLs, "<nil> ("+pkg.Name+")")

			continue
		}
		gotPURLs = append(gotPURLs, p.String())
	}

	wantPURLs := []string{
		"pkg:bitnami/nginx@1.25.3",
		"pkg:composer/symfony/http-kernel@6.3.0",
		"<nil> (drupal/simple_sitemap)",
		"pkg:conan/zlib@1.3.1",
		"pkg:cran/readxl@1.4.3",
		"pkg:dhi/python@3.12.1",
		"pkg:github/actions/checkout@4.1.0",
		"pkg:golang/github.com/gin-gonic/gin@1.9.1",
		"pkg:hackage/aeson@2.2.1.0",
		"pkg:hex/phoenix@1.7.10",
		"pkg:julia/HTTP@1.10.0",
		"pkg:npm/lodash@4.17.20",
		"pkg:opam/ocamlfind@1.9.6",
		"pkg:pypi/requests@2.25.1",
		// matches what scalibr produces when scanning a Package.resolved directly
		"pkg:swift/github.com%2Fapple%2Fswift-nio@2.62.0",
	}

	if diff := cmp.Diff(wantPURLs, gotPURLs); diff != "" {
		t.Errorf("%s.Extract() PURLs diff (-want +got):\n%s", extr.Name(), diff)
	}
}
