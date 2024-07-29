package lockfilescalibr_test

import (
	"testing"

	"github.com/google/osv-scanner/internal/lockfilescalibr"
	"github.com/google/osv-scanner/internal/lockfilescalibr/extractor"
	"github.com/google/osv-scanner/internal/lockfilescalibr/sharedtesthelpers"
)

func TestRenvLockExtractor_Extract(t *testing.T) {
	t.Parallel()

	tests := []sharedtesthelpers.TestTableEntry{
		{
			Name: "invalid json",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "fixtures/renv/not-json.txt",
			},
			WantErrContaining: "could not extract from",
		},
		{
			Name: "no packages",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "fixtures/renv/empty.lock",
			},
			WantInventory: []*extractor.Inventory{},
		},
		{
			Name: "one package",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "fixtures/renv/one-package.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "morning",
					Version:   "0.1.0",
					Locations: []string{"fixtures/renv/one-package.lock"},
				},
			},
		},
		{
			Name: "two packages",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "fixtures/renv/two-packages.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "markdown",
					Version:   "1.0",
					Locations: []string{"fixtures/renv/two-packages.lock"},
				},
				{
					Name:      "mime",
					Version:   "0.7",
					Locations: []string{"fixtures/renv/two-packages.lock"},
				},
			},
		},
		{
			Name: "with mixed sources",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "fixtures/renv/with-mixed-sources.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "markdown",
					Version:   "1.0",
					Locations: []string{"fixtures/renv/with-mixed-sources.lock"},
				},
			},
		},
		{
			Name: "with bioconductor",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "fixtures/renv/with-bioconductor.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "BH",
					Version:   "1.75.0-0",
					Locations: []string{"fixtures/renv/with-bioconductor.lock"},
				},
			},
		},
		{
			Name: "without repository",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "fixtures/renv/without-repository.lock",
			},
			WantInventory: []*extractor.Inventory{},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			e := lockfilescalibr.RenvLockExtractor{}
			_, _ = sharedtesthelpers.ExtractionTester(t, e, tt)
		})
	}
}
