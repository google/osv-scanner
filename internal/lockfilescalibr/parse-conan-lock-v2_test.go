package lockfilescalibr_test

import (
	"testing"

	"github.com/google/osv-scanner/internal/lockfilescalibr"
	"github.com/google/osv-scanner/internal/lockfilescalibr/extractor"
)

func TestConanLockExtractor_Extract_v2(t *testing.T) {
	t.Parallel()
	tests := []testTableEntry{
		{
			name: "no packages",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/conan/empty.v2.json",
			},
			wantInventory: []*extractor.Inventory{},
		},
		{
			name: "one package",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/conan/one-package.v2.json",
			},
			wantInventory: []*extractor.Inventory{
				{
					Name:      "zlib",
					Version:   "1.2.11",
					Locations: []string{"fixtures/conan/one-package.v2.json"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"requires"},
					},
				},
			},
		},
		{
			name: "no name",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/conan/no-name.v2.json",
			},
			wantInventory: []*extractor.Inventory{
				{
					Name:      "zlib",
					Version:   "1.2.11",
					Locations: []string{"fixtures/conan/no-name.v2.json"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"requires"},
					},
				},
			},
		},
		{
			name: "two packages",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/conan/two-packages.v2.json",
			},
			wantInventory: []*extractor.Inventory{
				{
					Name:      "zlib",
					Version:   "1.2.11",
					Locations: []string{"fixtures/conan/two-packages.v2.json"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"requires"},
					},
				},
				{
					Name:      "bzip2",
					Version:   "1.0.8",
					Locations: []string{"fixtures/conan/two-packages.v2.json"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"requires"},
					},
				},
			},
		},
		{
			name: "nested dependencies",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/conan/nested-dependencies.v2.json",
			},
			wantInventory: []*extractor.Inventory{
				{
					Name:      "zlib",
					Version:   "1.2.13",
					Locations: []string{"fixtures/conan/nested-dependencies.v2.json"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"requires"},
					},
				},
				{
					Name:      "bzip2",
					Version:   "1.0.8",
					Locations: []string{"fixtures/conan/nested-dependencies.v2.json"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"requires"},
					},
				},
				{
					Name:      "freetype",
					Version:   "2.12.1",
					Locations: []string{"fixtures/conan/nested-dependencies.v2.json"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"requires"},
					},
				},
				{
					Name:      "libpng",
					Version:   "1.6.39",
					Locations: []string{"fixtures/conan/nested-dependencies.v2.json"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"requires"},
					},
				},
				{
					Name:      "brotli",
					Version:   "1.0.9",
					Locations: []string{"fixtures/conan/nested-dependencies.v2.json"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"requires"},
					},
				},
			},
		},
		{
			name: "one package dev",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/conan/one-package-dev.v2.json",
			},
			wantInventory: []*extractor.Inventory{
				{
					Name:      "ninja",
					Version:   "1.11.1",
					Locations: []string{"fixtures/conan/one-package-dev.v2.json"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"build-requires"},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := lockfilescalibr.ConanLockExtractor{}
			_, _ = extractionTester(t, e, tt)
		})
	}
}
