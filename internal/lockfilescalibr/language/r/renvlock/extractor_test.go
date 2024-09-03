package renvlock_test

import (
	"testing"

	"github.com/google/osv-scanner/internal/lockfilescalibr/extractor"
	"github.com/google/osv-scanner/internal/lockfilescalibr/language/r/renvlock"
	"github.com/google/osv-scanner/internal/lockfilescalibr/sharedtesthelpers"
)

func TestExtractor_Extract(t *testing.T) {
	t.Parallel()

	tests := []sharedtesthelpers.TestTableEntry{
		{
			Name:              "invalid json",
			inputPath:         "testdata/not-json.txt",
			WantErrContaining: "could not extract from",
		},
		{
			Name:          "no packages",
			inputPath:     "testdata/empty.lock",
			WantInventory: []*extractor.Inventory{},
		},
		{
			Name:      "one package",
			inputPath: "testdata/one-package.lock",
			WantInventory: []*extractor.Inventory{
				{
					Name:      "morning",
					Version:   "0.1.0",
					Locations: []string{"testdata/one-package.lock"},
				},
			},
		},
		{
			Name:      "two packages",
			inputPath: "testdata/two-packages.lock",
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
			Name:      "with mixed sources",
			inputPath: "testdata/with-mixed-sources.lock",
			WantInventory: []*extractor.Inventory{
				{
					Name:      "markdown",
					Version:   "1.0",
					Locations: []string{"testdata/with-mixed-sources.lock"},
				},
			},
		},
		{
			Name:      "with bioconductor",
			inputPath: "testdata/with-bioconductor.lock",
			WantInventory: []*extractor.Inventory{
				{
					Name:      "BH",
					Version:   "1.75.0-0",
					Locations: []string{"testdata/with-bioconductor.lock"},
				},
			},
		},
		{
			Name:          "without repository",
			inputPath:     "testdata/without-repository.lock",
			WantInventory: []*extractor.Inventory{},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			e := renvlock.Extractor{}
			_, _ = sharedtesthelpers.ExtractionTester(t, e, tt)
		})
	}
}
