package conanlock_test

import (
	"testing"

	"github.com/google/osv-scanner/internal/lockfilescalibr/extractor"
	"github.com/google/osv-scanner/internal/lockfilescalibr/language/cpp/conanlock"
	"github.com/google/osv-scanner/internal/lockfilescalibr/othermetadata"
	"github.com/google/osv-scanner/internal/lockfilescalibr/sharedtesthelpers"
)

func TestExtractor_Extract_v1(t *testing.T) {
	t.Parallel()

	tests := []sharedtesthelpers.TestTableEntry{
		{
			Name: "invalid json",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "testdata/not-json.txt",
			},
			WantErrContaining: "could not extract from",
		},
		{
			Name: "no packages",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "testdata/empty.v1.json",
			},
			WantInventory: []*extractor.Inventory{},
		},
		{
			Name: "one package",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "testdata/one-package.v1.json",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "zlib",
					Version:   "1.2.11",
					Locations: []string{"testdata/one-package.v1.json"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "no name",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "testdata/no-name.v1.json",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "zlib",
					Version:   "1.2.11",
					Locations: []string{"testdata/no-name.v1.json"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "two packages",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "testdata/two-packages.v1.json",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "zlib",
					Version:   "1.2.11",
					Locations: []string{"testdata/two-packages.v1.json"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "bzip2",
					Version:   "1.0.8",
					Locations: []string{"testdata/two-packages.v1.json"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "nested dependencies",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "testdata/nested-dependencies.v1.json",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "zlib",
					Version:   "1.2.13",
					Locations: []string{"testdata/nested-dependencies.v1.json"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "bzip2",
					Version:   "1.0.8",
					Locations: []string{"testdata/nested-dependencies.v1.json"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "freetype",
					Version:   "2.12.1",
					Locations: []string{"testdata/nested-dependencies.v1.json"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "libpng",
					Version:   "1.6.39",
					Locations: []string{"testdata/nested-dependencies.v1.json"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "brotli",
					Version:   "1.0.9",
					Locations: []string{"testdata/nested-dependencies.v1.json"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "one package dev",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "testdata/one-package-dev.v1.json",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "ninja",
					Version:   "1.11.1",
					Locations: []string{"testdata/one-package-dev.v1.json"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "old format00",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "testdata/old-format-0.0.json",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "zlib",
					Version:   "1.2.11",
					Locations: []string{"testdata/old-format-0.0.json"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "old format01",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "testdata/old-format-0.1.json",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "zlib",
					Version:   "1.2.11",
					Locations: []string{"testdata/old-format-0.1.json"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "old format02",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "testdata/old-format-0.2.json",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "zlib",
					Version:   "1.2.11",
					Locations: []string{"testdata/old-format-0.2.json"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "old format03",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "testdata/old-format-0.3.json",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "zlib",
					Version:   "1.2.11",
					Locations: []string{"testdata/old-format-0.3.json"},
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
			e := conanlock.Extractor{}
			_, _ = sharedtesthelpers.ExtractionTester(t, e, tt)
		})
	}
}