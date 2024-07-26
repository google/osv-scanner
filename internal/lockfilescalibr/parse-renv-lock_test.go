package lockfilescalibr_test

import (
	"testing"

	"github.com/google/osv-scanner/internal/lockfilescalibr"
)

func TestRenvLockExtractor_Extract(t *testing.T) {
	t.Parallel()

	tests := []testTableEntry{
		{
			name: "invalid json",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/renv/not-json.txt",
			},
			wantErrContaining: "could not extract from",
		},
		{
			name: "no packages",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/renv/empty.lock",
			},
			wantInventory: []*lockfilescalibr.Inventory{},
		},
		{
			name: "one package",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/renv/one-package.lock",
			},
			wantInventory: []*lockfilescalibr.Inventory{
				{
					Name:      "morning",
					Version:   "0.1.0",
					Locations: []string{"fixtures/renv/one-package.lock"},
				},
			},
		},
		{
			name: "two packages",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/renv/two-packages.lock",
			},
			wantInventory: []*lockfilescalibr.Inventory{
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
			name: "with mixed sources",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/renv/with-mixed-sources.lock",
			},
			wantInventory: []*lockfilescalibr.Inventory{
				{
					Name:      "markdown",
					Version:   "1.0",
					Locations: []string{"fixtures/renv/with-mixed-sources.lock"},
				},
			},
		},
		{
			name: "with bioconductor",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/renv/with-bioconductor.lock",
			},
			wantInventory: []*lockfilescalibr.Inventory{
				{
					Name:      "BH",
					Version:   "1.75.0-0",
					Locations: []string{"fixtures/renv/with-bioconductor.lock"},
				},
			},
		},
		{
			name: "without repository",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/renv/without-repository.lock",
			},
			wantInventory: []*lockfilescalibr.Inventory{},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := lockfilescalibr.RenvLockExtractor{}
			_, _ = extractionTester(t, e, tt)
		})
	}
}
