package lockfilescalibr_test

import (
	"testing"

	"github.com/google/osv-scanner/internal/lockfilescalibr"
	"github.com/google/osv-scanner/internal/lockfilescalibr/extractor"
	"github.com/google/osv-scanner/internal/lockfilescalibr/sharedtesthelpers"
)

func TestNuGetLockExtractor_Extract(t *testing.T) {
	t.Parallel()

	tests := []sharedtesthelpers.TestTableEntry{
		{
			Name: "invalid json",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "fixtures/nuget/not-json.txt",
			},
			WantErrContaining: "could not extract from",
		},
		{
			Name: "no packages",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "fixtures/nuget/empty.v1.json",
			},
			WantInventory: []*extractor.Inventory{},
		},
		{
			Name: "one framework_ one package",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "fixtures/nuget/one-framework-one-package.v1.json",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "Test.Core",
					Version:   "6.0.5",
					Locations: []string{"fixtures/nuget/one-framework-one-package.v1.json"},
				},
			},
		},
		{
			Name: "one framework_ two packages",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "fixtures/nuget/one-framework-two-packages.v1.json",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "Test.Core",
					Version:   "6.0.5",
					Locations: []string{"fixtures/nuget/one-framework-two-packages.v1.json"},
				},
				{
					Name:      "Test.System",
					Version:   "0.13.0-beta4",
					Locations: []string{"fixtures/nuget/one-framework-two-packages.v1.json"},
				},
			},
		},
		{
			Name: "two frameworks_ mixed packages",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "fixtures/nuget/two-frameworks-mixed-packages.v1.json",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "Test.Core",
					Version:   "6.0.5",
					Locations: []string{"fixtures/nuget/two-frameworks-mixed-packages.v1.json"},
				},
				{
					Name:      "Test.System",
					Version:   "0.13.0-beta4",
					Locations: []string{"fixtures/nuget/two-frameworks-mixed-packages.v1.json"},
				},
				{
					Name:      "Test.System",
					Version:   "2.15.0",
					Locations: []string{"fixtures/nuget/two-frameworks-mixed-packages.v1.json"},
				},
			},
		},
		{
			Name: "two frameworks_ different packages",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "fixtures/nuget/two-frameworks-different-packages.v1.json",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "Test.Core",
					Version:   "6.0.5",
					Locations: []string{"fixtures/nuget/two-frameworks-different-packages.v1.json"},
				},
				{
					Name:      "Test.System",
					Version:   "0.13.0-beta4",
					Locations: []string{"fixtures/nuget/two-frameworks-different-packages.v1.json"},
				},
			},
		},
		{
			Name: "two frameworks_ duplicate packages",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "fixtures/nuget/two-frameworks-duplicate-packages.v1.json",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "Test.Core",
					Version:   "6.0.5",
					Locations: []string{"fixtures/nuget/two-frameworks-duplicate-packages.v1.json"},
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			e := lockfilescalibr.NuGetLockExtractor{}
			_, _ = sharedtesthelpers.ExtractionTester(t, e, tt)
		})
	}
}
