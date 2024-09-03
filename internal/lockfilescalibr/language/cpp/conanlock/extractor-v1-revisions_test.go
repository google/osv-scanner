package conanlock_test

import (
	"testing"

	"github.com/google/osv-scanner/internal/lockfilescalibr/extractor"
	"github.com/google/osv-scanner/internal/lockfilescalibr/language/cpp/conanlock"
	"github.com/google/osv-scanner/internal/lockfilescalibr/othermetadata"
	"github.com/google/osv-scanner/internal/lockfilescalibr/sharedtesthelpers"
)

func TestExtractor_Extract_v1_revisions(t *testing.T) {
	t.Parallel()

	tests := []sharedtesthelpers.TestTableEntry{
		{
			Name:          "no packages",
			inputPath:     "testdata/empty.v1.revisions.json",
			WantInventory: []*extractor.Inventory{},
		},
		{
			Name:      "one package",
			inputPath: "testdata/one-package.v1.revisions.json",
			WantInventory: []*extractor.Inventory{
				{
					Name:      "zlib",
					Version:   "1.2.11",
					Locations: []string{"testdata/one-package.v1.revisions.json"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name:      "no name",
			inputPath: "testdata/no-name.v1.revisions.json",
			WantInventory: []*extractor.Inventory{
				{
					Name:      "zlib",
					Version:   "1.2.11",
					Locations: []string{"testdata/no-name.v1.revisions.json"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name:      "two packages",
			inputPath: "testdata/two-packages.v1.revisions.json",
			WantInventory: []*extractor.Inventory{
				{
					Name:      "zlib",
					Version:   "1.2.11",
					Locations: []string{"testdata/two-packages.v1.revisions.json"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "bzip2",
					Version:   "1.0.8",
					Locations: []string{"testdata/two-packages.v1.revisions.json"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name:      "nested dependencies",
			inputPath: "testdata/nested-dependencies.v1.revisions.json",
			WantInventory: []*extractor.Inventory{
				{
					Name:      "zlib",
					Version:   "1.2.13",
					Locations: []string{"testdata/nested-dependencies.v1.revisions.json"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "bzip2",
					Version:   "1.0.8",
					Locations: []string{"testdata/nested-dependencies.v1.revisions.json"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "freetype",
					Version:   "2.12.1",
					Locations: []string{"testdata/nested-dependencies.v1.revisions.json"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "libpng",
					Version:   "1.6.39",
					Locations: []string{"testdata/nested-dependencies.v1.revisions.json"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "brotli",
					Version:   "1.0.9",
					Locations: []string{"testdata/nested-dependencies.v1.revisions.json"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name:      "one package dev",
			inputPath: "testdata/one-package-dev.v1.revisions.json",
			WantInventory: []*extractor.Inventory{
				{
					Name:      "ninja",
					Version:   "1.11.1",
					Locations: []string{"testdata/one-package-dev.v1.revisions.json"},
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
