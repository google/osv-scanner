package renvlock_test

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scanner/internal/lockfilescalibr/extractor"
	"github.com/google/osv-scanner/internal/lockfilescalibr/extracttest"
	"github.com/google/osv-scanner/internal/lockfilescalibr/language/r/renvlock"
)

func TestExtractor_Extract(t *testing.T) {
	t.Parallel()

	tests := []extracttest.TestTableEntry{
		{
			Name: "invalid json",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/not-json.txt",
			},
			WantErrContaining: "could not extract from",
		},
		{
			Name: "no packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty.lock",
			},
			WantInventory: []*extractor.Inventory{},
		},
		{
			Name: "one package",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/one-package.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "morning",
					Version:   "0.1.0",
					Locations: []string{"testdata/one-package.lock"},
				},
			},
		},
		{
			Name: "two packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/two-packages.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "markdown",
					Version:   "1.0",
					Locations: []string{"testdata/two-packages.lock"},
				},
				{
					Name:      "mime",
					Version:   "0.7",
					Locations: []string{"testdata/two-packages.lock"},
				},
			},
		},
		{
			Name: "with mixed sources",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/with-mixed-sources.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "markdown",
					Version:   "1.0",
					Locations: []string{"testdata/with-mixed-sources.lock"},
				},
			},
		},
		{
			Name: "with bioconductor",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/with-bioconductor.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "BH",
					Version:   "1.75.0-0",
					Locations: []string{"testdata/with-bioconductor.lock"},
				},
			},
		},
		{
			Name: "without repository",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/without-repository.lock",
			},
			WantInventory: []*extractor.Inventory{},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			extr := renvlock.Extractor{}

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
