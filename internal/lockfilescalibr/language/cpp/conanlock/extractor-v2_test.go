package conanlock_test

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scanner/internal/lockfilescalibr/extractor"
	"github.com/google/osv-scanner/internal/lockfilescalibr/extracttest"
	"github.com/google/osv-scanner/internal/lockfilescalibr/language/cpp/conanlock"
	"github.com/google/osv-scanner/internal/lockfilescalibr/othermetadata"
)

func TestExtractor_Extract_v2(t *testing.T) {
	t.Parallel()
	tests := []extracttest.TestTableEntry{
		{
			Name: "no packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty.v2.json",
			},
			WantInventory: []*extractor.Inventory{},
		},
		{
			Name: "one package",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/one-package.v2.json",
			},
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
			Name: "no name",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/no-name.v2.json",
			},
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
			Name: "two packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/two-packages.v2.json",
			},
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
			Name: "nested dependencies",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/nested-dependencies.v2.json",
			},
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
			Name: "one package dev",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/one-package-dev.v2.json",
			},
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
			extr := conanlock.Extractor{}

			scanInput := extracttest.GenerateScanInputMock(t, tt.InputConfig)
			defer extracttest.CloseTestScanInput(t, scanInput)

			got, err := extr.Extract(context.Background(), &scanInput)

			if diff := cmp.Diff(tt.WantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("%s.Extract(%q) error diff (-want +got):\n%s", extr.Name(), tt.InputConfig.Path, diff)
				return
			}

			if diff := cmp.Diff(tt.WantInventory, got, cmpopts.SortSlices(extracttest.InventoryCmpLess)); diff != "" {
				t.Errorf("%s.Extract(%q) diff (-want +got):\n%s", extr.Name(), tt.InputConfig.Path, diff)
			}
		})
	}
}
