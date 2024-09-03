package conanlock_test

import (
	"testing"

	"github.com/google/osv-scanner/internal/lockfilescalibr/extractor"
	"github.com/google/osv-scanner/internal/lockfilescalibr/language/cpp/conanlock"
	"github.com/google/osv-scanner/internal/lockfilescalibr/othermetadata"
	"github.com/google/osv-scanner/internal/lockfilescalibr/sharedtesthelpers"
)

func TestExtractor_Extract_v2(t *testing.T) {
	t.Parallel()
	tests := []sharedtesthelpers.TestTableEntry{
		{
			Name:          "no packages",
			inputPath:     "testdata/empty.v2.json",
			WantInventory: []*extractor.Inventory{},
		},
		{
			Name:      "one package",
			inputPath: "testdata/one-package.v2.json",
			WantInventory: []*extractor.Inventory{
				{
					Name:      "zlib",
					Version:   "1.2.11",
					Locations: []string{"testdata/one-package.v2.json"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"requires"},
					},
				},
			},
		},
		{
			Name:      "no name",
			inputPath: "testdata/no-name.v2.json",
			WantInventory: []*extractor.Inventory{
				{
					Name:      "zlib",
					Version:   "1.2.11",
					Locations: []string{"testdata/no-name.v2.json"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"requires"},
					},
				},
			},
		},
		{
			Name:      "two packages",
			inputPath: "testdata/two-packages.v2.json",
			WantInventory: []*extractor.Inventory{
				{
					Name:      "zlib",
					Version:   "1.2.11",
					Locations: []string{"testdata/two-packages.v2.json"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"requires"},
					},
				},
				{
					Name:      "bzip2",
					Version:   "1.0.8",
					Locations: []string{"testdata/two-packages.v2.json"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"requires"},
					},
				},
			},
		},
		{
			Name:      "nested dependencies",
			inputPath: "testdata/nested-dependencies.v2.json",
			WantInventory: []*extractor.Inventory{
				{
					Name:      "zlib",
					Version:   "1.2.13",
					Locations: []string{"testdata/nested-dependencies.v2.json"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"requires"},
					},
				},
				{
					Name:      "bzip2",
					Version:   "1.0.8",
					Locations: []string{"testdata/nested-dependencies.v2.json"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"requires"},
					},
				},
				{
					Name:      "freetype",
					Version:   "2.12.1",
					Locations: []string{"testdata/nested-dependencies.v2.json"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"requires"},
					},
				},
				{
					Name:      "libpng",
					Version:   "1.6.39",
					Locations: []string{"testdata/nested-dependencies.v2.json"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"requires"},
					},
				},
				{
					Name:      "brotli",
					Version:   "1.0.9",
					Locations: []string{"testdata/nested-dependencies.v2.json"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"requires"},
					},
				},
			},
		},
		{
			Name:      "one package dev",
			inputPath: "testdata/one-package-dev.v2.json",
			WantInventory: []*extractor.Inventory{
				{
					Name:      "ninja",
					Version:   "1.11.1",
					Locations: []string{"testdata/one-package-dev.v2.json"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"build-requires"},
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
