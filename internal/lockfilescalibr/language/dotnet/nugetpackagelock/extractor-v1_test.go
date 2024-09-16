package nugetpackagelock_test

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scanner/internal/lockfilescalibr/extractor"
	"github.com/google/osv-scanner/internal/lockfilescalibr/extracttest"
	"github.com/google/osv-scanner/internal/lockfilescalibr/language/dotnet/nugetpackagelock"
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
				Path: "testdata/empty.v1.json",
			},
			WantInventory: []*extractor.Inventory{},
		},
		{
			Name: "one framework_ one package",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/one-framework-one-package.v1.json",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "Test.Core",
					Version:   "6.0.5",
					Locations: []string{"testdata/one-framework-one-package.v1.json"},
				},
			},
		},
		{
			Name: "one framework_ two packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/one-framework-two-packages.v1.json",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "Test.Core",
					Version:   "6.0.5",
					Locations: []string{"testdata/one-framework-two-packages.v1.json"},
				},
				{
					Name:      "Test.System",
					Version:   "0.13.0-beta4",
					Locations: []string{"testdata/one-framework-two-packages.v1.json"},
				},
			},
		},
		{
			Name: "two frameworks_ mixed packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/two-frameworks-mixed-packages.v1.json",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "Test.Core",
					Version:   "6.0.5",
					Locations: []string{"testdata/two-frameworks-mixed-packages.v1.json"},
				},
				{
					Name:      "Test.System",
					Version:   "0.13.0-beta4",
					Locations: []string{"testdata/two-frameworks-mixed-packages.v1.json"},
				},
				{
					Name:      "Test.System",
					Version:   "2.15.0",
					Locations: []string{"testdata/two-frameworks-mixed-packages.v1.json"},
				},
			},
		},
		{
			Name: "two frameworks_ different packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/two-frameworks-different-packages.v1.json",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "Test.Core",
					Version:   "6.0.5",
					Locations: []string{"testdata/two-frameworks-different-packages.v1.json"},
				},
				{
					Name:      "Test.System",
					Version:   "0.13.0-beta4",
					Locations: []string{"testdata/two-frameworks-different-packages.v1.json"},
				},
			},
		},
		{
			Name: "two frameworks_ duplicate packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/two-frameworks-duplicate-packages.v1.json",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "Test.Core",
					Version:   "6.0.5",
					Locations: []string{"testdata/two-frameworks-duplicate-packages.v1.json"},
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			extr := nugetpackagelock.Extractor{}

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
