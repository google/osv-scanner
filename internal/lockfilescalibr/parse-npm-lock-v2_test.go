package lockfilescalibr_test

import (
	"testing"

	"github.com/google/osv-scanner/internal/lockfilescalibr"
	"github.com/google/osv-scanner/internal/lockfilescalibr/extractor"
)

func TestNPMLockExtractor_Extract_V2(t *testing.T) {
	t.Parallel()

	tests := []TestTableEntry{
		{
			Name: "invalid json",
			InputConfig: ScanInputMockConfig{
				Path: "fixtures/npm/not-json.txt",
			},
			WantErrContaining: "could not extract from",
		},
		{
			Name: "no packages",
			InputConfig: ScanInputMockConfig{
				Path: "fixtures/npm/empty.v2.json",
			},
			WantInventory: []*extractor.Inventory{},
		},
		{
			Name: "one package",
			InputConfig: ScanInputMockConfig{
				Path: "fixtures/npm/one-package.v2.json",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "wrappy",
					Version:   "1.0.2",
					Locations: []string{"fixtures/npm/one-package.v2.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "one package dev",
			InputConfig: ScanInputMockConfig{
				Path: "fixtures/npm/one-package-dev.v2.json",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "wrappy",
					Version:   "1.0.2",
					Locations: []string{"fixtures/npm/one-package-dev.v2.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
			},
		},
		{
			Name: "two packages",
			InputConfig: ScanInputMockConfig{
				Path: "fixtures/npm/two-packages.v2.json",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "wrappy",
					Version:   "1.0.2",
					Locations: []string{"fixtures/npm/two-packages.v2.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "supports-color",
					Version:   "5.5.0",
					Locations: []string{"fixtures/npm/two-packages.v2.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "scoped packages",
			InputConfig: ScanInputMockConfig{
				Path: "fixtures/npm/scoped-packages.v2.json",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "wrappy",
					Version:   "1.0.2",
					Locations: []string{"fixtures/npm/scoped-packages.v2.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "@babel/code-frame",
					Version:   "7.0.0",
					Locations: []string{"fixtures/npm/scoped-packages.v2.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "nested dependencies",
			InputConfig: ScanInputMockConfig{
				Path: "fixtures/npm/nested-dependencies.v2.json",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "postcss",
					Version:   "6.0.23",
					Locations: []string{"fixtures/npm/nested-dependencies.v2.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "postcss",
					Version:   "7.0.16",
					Locations: []string{"fixtures/npm/nested-dependencies.v2.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "postcss-calc",
					Version:   "7.0.1",
					Locations: []string{"fixtures/npm/nested-dependencies.v2.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "supports-color",
					Version:   "6.1.0",
					Locations: []string{"fixtures/npm/nested-dependencies.v2.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "supports-color",
					Version:   "5.5.0",
					Locations: []string{"fixtures/npm/nested-dependencies.v2.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "nested dependencies dup",
			InputConfig: ScanInputMockConfig{
				Path: "fixtures/npm/nested-dependencies-dup.v2.json",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "supports-color",
					Version:   "6.1.0",
					Locations: []string{"fixtures/npm/nested-dependencies-dup.v2.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "supports-color",
					Version:   "2.0.0",
					Locations: []string{"fixtures/npm/nested-dependencies-dup.v2.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "commits",
			InputConfig: ScanInputMockConfig{
				Path: "fixtures/npm/commits.v2.json",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "@segment/analytics.js-integration-facebook-pixel",
					Version:   "2.4.1",
					Locations: []string{"fixtures/npm/commits.v2.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "3b1bb80b302c2e552685dc8a029797ec832ea7c9",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "ansi-styles",
					Version:   "1.0.0",
					Locations: []string{"fixtures/npm/commits.v2.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "babel-preset-php",
					Version:   "1.1.1",
					Locations: []string{"fixtures/npm/commits.v2.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "c5a7ba5e0ad98b8db1cb8ce105403dd4b768cced",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
				{
					Name:      "is-number-1",
					Version:   "3.0.0",
					Locations: []string{"fixtures/npm/commits.v2.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "af885e2e890b9ef0875edd2b117305119ee5bdc5",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
				{
					Name:      "is-number-1",
					Version:   "3.0.0",
					Locations: []string{"fixtures/npm/commits.v2.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "be5935f8d2595bcd97b05718ef1eeae08d812e10",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
				{
					Name:      "is-number-2",
					Version:   "2.0.0",
					Locations: []string{"fixtures/npm/commits.v2.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "d5ac0584ee9ae7bd9288220a39780f155b9ad4c8",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
				{
					Name:      "is-number-2",
					Version:   "2.0.0",
					Locations: []string{"fixtures/npm/commits.v2.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "82dcc8e914dabd9305ab9ae580709a7825e824f5",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
				{
					Name:      "is-number-3",
					Version:   "2.0.0",
					Locations: []string{"fixtures/npm/commits.v2.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "d5ac0584ee9ae7bd9288220a39780f155b9ad4c8",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
				{
					Name:      "is-number-3",
					Version:   "3.0.0",
					Locations: []string{"fixtures/npm/commits.v2.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "82ae8802978da40d7f1be5ad5943c9e550ab2c89",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
				{
					Name:      "is-number-4",
					Version:   "3.0.0",
					Locations: []string{"fixtures/npm/commits.v2.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "af885e2e890b9ef0875edd2b117305119ee5bdc5",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
				{
					Name:      "is-number-5",
					Version:   "3.0.0",
					Locations: []string{"fixtures/npm/commits.v2.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "af885e2e890b9ef0875edd2b117305119ee5bdc5",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
				{
					Name:      "postcss-calc",
					Version:   "7.0.1",
					Locations: []string{"fixtures/npm/commits.v2.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "raven-js",
					Version:   "",
					Locations: []string{"fixtures/npm/commits.v2.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "c2b377e7a254264fd4a1fe328e4e3cfc9e245570",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "slick-carousel",
					Version:   "1.7.1",
					Locations: []string{"fixtures/npm/commits.v2.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "280b560161b751ba226d50c7db1e0a14a78c2de0",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
			},
		},
		{
			Name: "files",
			InputConfig: ScanInputMockConfig{
				Path: "fixtures/npm/files.v2.json",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "etag",
					Version:   "1.8.0",
					Locations: []string{"fixtures/npm/files.v2.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
				{
					Name:      "abbrev",
					Version:   "1.0.9",
					Locations: []string{"fixtures/npm/files.v2.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
				{
					Name:      "abbrev",
					Version:   "2.3.4",
					Locations: []string{"fixtures/npm/files.v2.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
			},
		},
		{
			Name: "alias",
			InputConfig: ScanInputMockConfig{
				Path: "fixtures/npm/alias.v2.json",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "@babel/code-frame",
					Version:   "7.0.0",
					Locations: []string{"fixtures/npm/alias.v2.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "string-width",
					Version:   "4.2.0",
					Locations: []string{"fixtures/npm/alias.v2.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "string-width",
					Version:   "5.1.2",
					Locations: []string{"fixtures/npm/alias.v2.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "optional package",
			InputConfig: ScanInputMockConfig{
				Path: "fixtures/npm/optional-package.v2.json",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "wrappy",
					Version:   "1.0.2",
					Locations: []string{"fixtures/npm/optional-package.v2.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"optional"},
					},
				},
				{
					Name:      "supports-color",
					Version:   "5.5.0",
					Locations: []string{"fixtures/npm/optional-package.v2.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"dev", "optional"},
					},
				},
			},
		},
		{
			Name: "same package different groups",
			InputConfig: ScanInputMockConfig{
				Path: "fixtures/npm/same-package-different-groups.v2.json",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "eslint",
					Version:   "1.2.3",
					Locations: []string{"fixtures/npm/same-package-different-groups.v2.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
				{
					Name:      "table",
					Version:   "1.0.0",
					Locations: []string{"fixtures/npm/same-package-different-groups.v2.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "ajv",
					Version:   "5.5.2",
					Locations: []string{"fixtures/npm/same-package-different-groups.v2.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			e := lockfilescalibr.NpmLockExtractor{}
			_, _ = ExtractionTester(t, e, tt)
		})
	}
}
