package lockfilescalibr_test

import (
	"testing"

	"github.com/google/osv-scanner/internal/lockfilescalibr"
	"github.com/google/osv-scanner/internal/lockfilescalibr/extractor"
	"github.com/google/osv-scanner/internal/lockfilescalibr/othermetadata"
	"github.com/google/osv-scanner/internal/lockfilescalibr/sharedtesthelpers"
)

func TestNPMLockExtractor_Extract_V1(t *testing.T) {
	t.Parallel()

	tests := []sharedtesthelpers.TestTableEntry{
		{
			Name: "invalid json",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "fixtures/npm/not-json.txt",
			},
			WantErrContaining: "could not extract from",
		},
		{
			Name: "no packages",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "fixtures/npm/empty.v1.json",
			},
			WantInventory: []*extractor.Inventory{},
		},
		{
			Name: "one package",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "fixtures/npm/one-package.v1.json",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:       "wrappy",
					Version:    "1.0.2",
					Locations:  []string{"fixtures/npm/one-package.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "one package dev",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "fixtures/npm/one-package-dev.v1.json",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:       "wrappy",
					Version:    "1.0.2",
					Locations:  []string{"fixtures/npm/one-package-dev.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
			},
		},
		{
			Name: "two packages",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "fixtures/npm/two-packages.v1.json",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:       "wrappy",
					Version:    "1.0.2",
					Locations:  []string{"fixtures/npm/two-packages.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "supports-color",
					Version:    "5.5.0",
					Locations:  []string{"fixtures/npm/two-packages.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "scoped packages",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "fixtures/npm/scoped-packages.v1.json",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:       "wrappy",
					Version:    "1.0.2",
					Locations:  []string{"fixtures/npm/scoped-packages.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "@babel/code-frame",
					Version:    "7.0.0",
					Locations:  []string{"fixtures/npm/scoped-packages.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "nested dependencies",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "fixtures/npm/nested-dependencies.v1.json",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:       "postcss",
					Version:    "6.0.23",
					Locations:  []string{"fixtures/npm/nested-dependencies.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "postcss",
					Version:    "7.0.16",
					Locations:  []string{"fixtures/npm/nested-dependencies.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "postcss-calc",
					Version:    "7.0.1",
					Locations:  []string{"fixtures/npm/nested-dependencies.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "supports-color",
					Version:    "6.1.0",
					Locations:  []string{"fixtures/npm/nested-dependencies.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "supports-color",
					Version:    "5.5.0",
					Locations:  []string{"fixtures/npm/nested-dependencies.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "nested dependencies dup",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "fixtures/npm/nested-dependencies-dup.v1.json",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:       "supports-color",
					Version:    "2.0.0",
					Locations:  []string{"fixtures/npm/nested-dependencies-dup.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "postcss-normalize-display-values",
					Version:    "4.0.2",
					Locations:  []string{"fixtures/npm/nested-dependencies-dup.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "postcss-normalize-timing-functions",
					Version:    "4.0.2",
					Locations:  []string{"fixtures/npm/nested-dependencies-dup.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "postcss-normalize-string",
					Version:    "4.0.2",
					Locations:  []string{"fixtures/npm/nested-dependencies-dup.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "postcss-normalize-whitespace",
					Version:    "4.0.2",
					Locations:  []string{"fixtures/npm/nested-dependencies-dup.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "supports-color",
					Version:    "6.1.0",
					Locations:  []string{"fixtures/npm/nested-dependencies-dup.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "cssnano-preset-default",
					Version:    "4.0.7",
					Locations:  []string{"fixtures/npm/nested-dependencies-dup.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "postcss-merge-longhand",
					Version:    "4.0.11",
					Locations:  []string{"fixtures/npm/nested-dependencies-dup.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "postcss-discard-overridden",
					Version:    "4.0.1",
					Locations:  []string{"fixtures/npm/nested-dependencies-dup.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "postcss-reduce-transforms",
					Version:    "4.0.2",
					Locations:  []string{"fixtures/npm/nested-dependencies-dup.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "postcss-svgo",
					Version:    "4.0.2",
					Locations:  []string{"fixtures/npm/nested-dependencies-dup.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "postcss-ordered-values",
					Version:    "4.1.2",
					Locations:  []string{"fixtures/npm/nested-dependencies-dup.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "postcss-minify-selectors",
					Version:    "4.0.2",
					Locations:  []string{"fixtures/npm/nested-dependencies-dup.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "babel-code-frame",
					Version:    "6.26.0",
					Locations:  []string{"fixtures/npm/nested-dependencies-dup.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "css-declaration-sorter",
					Version:    "4.0.1",
					Locations:  []string{"fixtures/npm/nested-dependencies-dup.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "postcss-normalize-url",
					Version:    "4.0.1",
					Locations:  []string{"fixtures/npm/nested-dependencies-dup.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "postcss-minify-params",
					Version:    "4.0.2",
					Locations:  []string{"fixtures/npm/nested-dependencies-dup.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "supports-color",
					Version:    "5.5.0",
					Locations:  []string{"fixtures/npm/nested-dependencies-dup.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "postcss-colormin",
					Version:    "4.0.3",
					Locations:  []string{"fixtures/npm/nested-dependencies-dup.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "autoprefixer",
					Version:    "9.5.1",
					Locations:  []string{"fixtures/npm/nested-dependencies-dup.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "postcss-normalize-charset",
					Version:    "4.0.1",
					Locations:  []string{"fixtures/npm/nested-dependencies-dup.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "postcss-unique-selectors",
					Version:    "4.0.1",
					Locations:  []string{"fixtures/npm/nested-dependencies-dup.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "postcss-reduce-initial",
					Version:    "4.0.3",
					Locations:  []string{"fixtures/npm/nested-dependencies-dup.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "postcss-normalize-positions",
					Version:    "4.0.2",
					Locations:  []string{"fixtures/npm/nested-dependencies-dup.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "postcss-discard-duplicates",
					Version:    "4.0.2",
					Locations:  []string{"fixtures/npm/nested-dependencies-dup.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "postcss-loader",
					Version:    "3.0.0",
					Locations:  []string{"fixtures/npm/nested-dependencies-dup.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "cssnano",
					Version:    "4.1.10",
					Locations:  []string{"fixtures/npm/nested-dependencies-dup.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "postcss-discard-empty",
					Version:    "4.0.1",
					Locations:  []string{"fixtures/npm/nested-dependencies-dup.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "postcss-normalize-repeat-style",
					Version:    "4.0.2",
					Locations:  []string{"fixtures/npm/nested-dependencies-dup.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "postcss-convert-values",
					Version:    "4.0.1",
					Locations:  []string{"fixtures/npm/nested-dependencies-dup.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "friendly-errors-webpack-plugin",
					Version:    "1.7.0",
					Locations:  []string{"fixtures/npm/nested-dependencies-dup.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "@vue/component-compiler-utils",
					Version:    "2.6.0",
					Locations:  []string{"fixtures/npm/nested-dependencies-dup.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "postcss-merge-rules",
					Version:    "4.0.3",
					Locations:  []string{"fixtures/npm/nested-dependencies-dup.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "postcss-normalize-unicode",
					Version:    "4.0.1",
					Locations:  []string{"fixtures/npm/nested-dependencies-dup.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "postcss-minify-font-values",
					Version:    "4.0.2",
					Locations:  []string{"fixtures/npm/nested-dependencies-dup.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "postcss-minify-gradients",
					Version:    "4.0.2",
					Locations:  []string{"fixtures/npm/nested-dependencies-dup.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "cssnano-util-raw-cache",
					Version:    "4.0.1",
					Locations:  []string{"fixtures/npm/nested-dependencies-dup.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "postcss-calc",
					Version:    "7.0.1",
					Locations:  []string{"fixtures/npm/nested-dependencies-dup.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "postcss-discard-comments",
					Version:    "4.0.2",
					Locations:  []string{"fixtures/npm/nested-dependencies-dup.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "commits",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "fixtures/npm/commits.v1.json",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "@segment/analytics.js-integration-facebook-pixel",
					Version:   "",
					Locations: []string{"fixtures/npm/commits.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "3b1bb80b302c2e552685dc8a029797ec832ea7c9",
					},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "ansi-styles",
					Version:    "1.0.0",
					Locations:  []string{"fixtures/npm/commits.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "babel-preset-php",
					Version:   "",
					Locations: []string{"fixtures/npm/commits.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "c5a7ba5e0ad98b8db1cb8ce105403dd4b768cced",
					},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "is-number-1",
					Version:   "",
					Locations: []string{"fixtures/npm/commits.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "af885e2e890b9ef0875edd2b117305119ee5bdc5",
					},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
				{
					Name:      "is-number-1",
					Version:   "",
					Locations: []string{"fixtures/npm/commits.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "be5935f8d2595bcd97b05718ef1eeae08d812e10",
					},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
				{
					Name:      "is-number-2",
					Version:   "",
					Locations: []string{"fixtures/npm/commits.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "d5ac0584ee9ae7bd9288220a39780f155b9ad4c8",
					},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "is-number-2",
					Version:   "",
					Locations: []string{"fixtures/npm/commits.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "82dcc8e914dabd9305ab9ae580709a7825e824f5",
					},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "is-number-3",
					Version:   "",
					Locations: []string{"fixtures/npm/commits.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "d5ac0584ee9ae7bd9288220a39780f155b9ad4c8",
					},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
				{
					Name:      "is-number-3",
					Version:   "",
					Locations: []string{"fixtures/npm/commits.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "82ae8802978da40d7f1be5ad5943c9e550ab2c89",
					},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
				{
					Name:      "is-number-4",
					Version:   "",
					Locations: []string{"fixtures/npm/commits.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "af885e2e890b9ef0875edd2b117305119ee5bdc5",
					},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
				{
					Name:      "is-number-5",
					Version:   "",
					Locations: []string{"fixtures/npm/commits.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "af885e2e890b9ef0875edd2b117305119ee5bdc5",
					},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
				{
					Name:      "is-number-6",
					Version:   "",
					Locations: []string{"fixtures/npm/commits.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "af885e2e890b9ef0875edd2b117305119ee5bdc5",
					},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
				{
					Name:       "postcss-calc",
					Version:    "7.0.1",
					Locations:  []string{"fixtures/npm/commits.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "raven-js",
					Version:   "",
					Locations: []string{"fixtures/npm/commits.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "c2b377e7a254264fd4a1fe328e4e3cfc9e245570",
					},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "slick-carousel",
					Version:   "",
					Locations: []string{"fixtures/npm/commits.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "280b560161b751ba226d50c7db1e0a14a78c2de0",
					},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
			},
		},
		{
			Name: "files",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "fixtures/npm/files.v1.json",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:       "lodash",
					Version:    "1.3.1",
					Locations:  []string{"fixtures/npm/files.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "other_package",
					Version:    "",
					Locations:  []string{"fixtures/npm/files.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "alias",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "fixtures/npm/alias.v1.json",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:       "@babel/code-frame",
					Version:    "7.0.0",
					Locations:  []string{"fixtures/npm/alias.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "string-width",
					Version:    "4.2.0",
					Locations:  []string{"fixtures/npm/alias.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "string-width",
					Version:    "5.1.2",
					Locations:  []string{"fixtures/npm/alias.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "optional package",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "fixtures/npm/optional-package.v1.json",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:       "wrappy",
					Version:    "1.0.2",
					Locations:  []string{"fixtures/npm/optional-package.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"dev", "optional"},
					},
				},
				{
					Name:       "supports-color",
					Version:    "5.5.0",
					Locations:  []string{"fixtures/npm/optional-package.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"optional"},
					},
				},
			},
		},
		{
			Name: "same package different groups",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "fixtures/npm/same-package-different-groups.v1.json",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:       "eslint",
					Version:    "1.2.3",
					Locations:  []string{"fixtures/npm/same-package-different-groups.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
				{
					Name:       "table",
					Version:    "1.0.0",
					Locations:  []string{"fixtures/npm/same-package-different-groups.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "ajv",
					Version:    "5.5.2",
					Locations:  []string{"fixtures/npm/same-package-different-groups.v1.json"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
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
			_, _ = sharedtesthelpers.ExtractionTester(t, e, tt)
		})
	}
}
