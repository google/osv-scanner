package lockfile_test

import (
	"testing"

	"github.com/google/osv-scanner/pkg/lockfile"
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
			wantInventory: []*lockfile.Inventory{},
		},
		{
			name: "one package",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/renv/one-package.lock",
			},
			wantInventory: []*lockfile.Inventory{
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
			wantInventory: []*lockfile.Inventory{
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
			wantInventory: []*lockfile.Inventory{
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
			wantInventory: []*lockfile.Inventory{
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
			wantInventory: []*lockfile.Inventory{},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := lockfile.RenvLockExtractor{}
			_, _ = extractionTester(t, e, tt)
		})
	}
}
