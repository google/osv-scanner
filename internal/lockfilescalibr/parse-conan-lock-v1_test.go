package lockfilescalibr_test

import (
	"testing"

	"github.com/google/osv-scanner/internal/lockfilescalibr"
	"github.com/google/osv-scanner/internal/lockfilescalibr/extractor"
)

func TestConanLockExtractor_Extract_v1(t *testing.T) {
	t.Parallel()

	tests := []testTableEntry{
		{
			name: "invalid json",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/conan/not-json.txt",
			},
			wantErrContaining: "could not extract from",
		},
		{
			name: "no packages",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/conan/empty.v1.json",
			},
			wantInventory: []*extractor.Inventory{},
		},
		{
			name: "one package",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/conan/one-package.v1.json",
			},
			wantInventory: []*extractor.Inventory{
				{
					Name:      "zlib",
					Version:   "1.2.11",
					Locations: []string{"fixtures/conan/one-package.v1.json"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			name: "no name",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/conan/no-name.v1.json",
			},
			wantInventory: []*extractor.Inventory{
				{
					Name:      "zlib",
					Version:   "1.2.11",
					Locations: []string{"fixtures/conan/no-name.v1.json"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			name: "two packages",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/conan/two-packages.v1.json",
			},
			wantInventory: []*extractor.Inventory{
				{
					Name:      "zlib",
					Version:   "1.2.11",
					Locations: []string{"fixtures/conan/two-packages.v1.json"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "bzip2",
					Version:   "1.0.8",
					Locations: []string{"fixtures/conan/two-packages.v1.json"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			name: "nested dependencies",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/conan/nested-dependencies.v1.json",
			},
			wantInventory: []*extractor.Inventory{
				{
					Name:      "zlib",
					Version:   "1.2.13",
					Locations: []string{"fixtures/conan/nested-dependencies.v1.json"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "bzip2",
					Version:   "1.0.8",
					Locations: []string{"fixtures/conan/nested-dependencies.v1.json"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "freetype",
					Version:   "2.12.1",
					Locations: []string{"fixtures/conan/nested-dependencies.v1.json"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "libpng",
					Version:   "1.6.39",
					Locations: []string{"fixtures/conan/nested-dependencies.v1.json"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "brotli",
					Version:   "1.0.9",
					Locations: []string{"fixtures/conan/nested-dependencies.v1.json"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			name: "one package dev",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/conan/one-package-dev.v1.json",
			},
			wantInventory: []*extractor.Inventory{
				{
					Name:      "ninja",
					Version:   "1.11.1",
					Locations: []string{"fixtures/conan/one-package-dev.v1.json"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			name: "old format00",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/conan/old-format-0.0.json",
			},
			wantInventory: []*extractor.Inventory{
				{
					Name:      "zlib",
					Version:   "1.2.11",
					Locations: []string{"fixtures/conan/old-format-0.0.json"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			name: "old format01",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/conan/old-format-0.1.json",
			},
			wantInventory: []*extractor.Inventory{
				{
					Name:      "zlib",
					Version:   "1.2.11",
					Locations: []string{"fixtures/conan/old-format-0.1.json"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			name: "old format02",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/conan/old-format-0.2.json",
			},
			wantInventory: []*extractor.Inventory{
				{
					Name:      "zlib",
					Version:   "1.2.11",
					Locations: []string{"fixtures/conan/old-format-0.2.json"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			name: "old format03",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/conan/old-format-0.3.json",
			},
			wantInventory: []*extractor.Inventory{
				{
					Name:      "zlib",
					Version:   "1.2.11",
					Locations: []string{"fixtures/conan/old-format-0.3.json"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
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
