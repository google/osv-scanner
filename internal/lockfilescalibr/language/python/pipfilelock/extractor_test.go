package pipfilelock_test

import (
	"testing"

	"github.com/google/osv-scanner/internal/lockfilescalibr/extractor"
	"github.com/google/osv-scanner/internal/lockfilescalibr/language/python/pipfilelock"
	"github.com/google/osv-scanner/internal/lockfilescalibr/othermetadata"
	"github.com/google/osv-scanner/internal/lockfilescalibr/sharedtesthelpers"
)

func TestExtractor_FileRequired(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		inputPath string
		want      bool
	}{
		{
			name:      "",
			inputPath: "",
			want:      false,
		},
		{
			name:      "",
			inputPath: "Pipfile.lock",
			want:      true,
		},
		{
			name:      "",
			inputPath: "path/to/my/Pipfile.lock",
			want:      true,
		},
		{
			name:      "",
			inputPath: "path/to/my/Pipfile.lock/file",
			want:      false,
		},
		{
			name:      "",
			inputPath: "path/to/my/Pipfile.lock.file",
			want:      false,
		},
		{
			name:      "",
			inputPath: "path.to.my.Pipfile.lock",
			want:      false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := pipfilelock.Extractor{}
			got := e.FileRequired(tt.inputPath, nil)
			if got != tt.want {
				t.Errorf("FileRequired(%s, FileInfo) got = %v, want %v", tt.inputPath, got, tt.want)
			}
		})
	}
}

func TestExtractor_Extract(t *testing.T) {
	t.Parallel()

	tests := []sharedtesthelpers.TestTableEntry{
		{
			Name: "invalid json",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "testdata/not-json.txt",
			},
			WantErrContaining: "could not extract from",
		},
		{
			Name: "no packages",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "testdata/empty.json",
			},
			WantInventory: []*extractor.Inventory{},
		},
		{
			Name: "one package",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "testdata/one-package.json",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "markupsafe",
					Version:   "2.1.1",
					Locations: []string{"testdata/one-package.json"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "one package dev",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "testdata/one-package-dev.json",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "markupsafe",
					Version:   "2.1.1",
					Locations: []string{"testdata/one-package-dev.json"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
			},
		},
		{
			Name: "two packages",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "testdata/two-packages.json",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "itsdangerous",
					Version:   "2.1.2",
					Locations: []string{"testdata/two-packages.json"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "markupsafe",
					Version:   "2.1.1",
					Locations: []string{"testdata/two-packages.json"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
			},
		},
		{
			Name: "two packages alt",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "testdata/two-packages-alt.json",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "itsdangerous",
					Version:   "2.1.2",
					Locations: []string{"testdata/two-packages-alt.json"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "markupsafe",
					Version:   "2.1.1",
					Locations: []string{"testdata/two-packages-alt.json"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "multiple packages",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "testdata/multiple-packages.json",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "itsdangerous",
					Version:   "2.1.2",
					Locations: []string{"testdata/multiple-packages.json"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "pluggy",
					Version:   "1.0.1",
					Locations: []string{"testdata/multiple-packages.json"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "pluggy",
					Version:   "1.0.0",
					Locations: []string{"testdata/multiple-packages.json"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
				{
					Name:      "markupsafe",
					Version:   "2.1.1",
					Locations: []string{"testdata/multiple-packages.json"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "package without version",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "testdata/no-version.json",
			},
			WantInventory: []*extractor.Inventory{},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			e := pipfilelock.Extractor{}
			_, _ = sharedtesthelpers.ExtractionTester(t, e, tt)
		})
	}
}
