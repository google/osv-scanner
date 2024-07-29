package lockfilescalibr_test

import (
	"testing"

	"github.com/google/osv-scanner/internal/lockfilescalibr"
	"github.com/google/osv-scanner/internal/lockfilescalibr/extractor"
)

func TestPipenvLockExtractor_FileRequired(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		inputConfig ScanInputMockConfig
		want        bool
	}{
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				Path: "",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				Path: "Pipfile.lock",
			},
			want: true,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				Path: "path/to/my/Pipfile.lock",
			},
			want: true,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				Path: "path/to/my/Pipfile.lock/file",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				Path: "path/to/my/Pipfile.lock.file",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				Path: "path.to.my.Pipfile.lock",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := lockfilescalibr.PipenvLockExtractor{}
			got := e.FileRequired(tt.inputConfig.Path, GenerateFileInfoMock(t, tt.inputConfig))
			if got != tt.want {
				t.Errorf("FileRequired(%s, FileInfo) got = %v, want %v", tt.inputConfig.Path, got, tt.want)
			}
		})
	}
}

func TestPipenvLockExtractor_Extract(t *testing.T) {
	t.Parallel()

	tests := []TestTableEntry{
		{
			Name: "invalid json",
			InputConfig: ScanInputMockConfig{
				Path: "fixtures/pipenv/not-json.txt",
			},
			WantErrContaining: "could not extract from",
		},
		{
			Name: "no packages",
			InputConfig: ScanInputMockConfig{
				Path: "fixtures/pipenv/empty.json",
			},
			WantInventory: []*extractor.Inventory{},
		},
		{
			Name: "one package",
			InputConfig: ScanInputMockConfig{
				Path: "fixtures/pipenv/one-package.json",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "markupsafe",
					Version:   "2.1.1",
					Locations: []string{"fixtures/pipenv/one-package.json"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "one package dev",
			InputConfig: ScanInputMockConfig{
				Path: "fixtures/pipenv/one-package-dev.json",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "markupsafe",
					Version:   "2.1.1",
					Locations: []string{"fixtures/pipenv/one-package-dev.json"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
			},
		},
		{
			Name: "two packages",
			InputConfig: ScanInputMockConfig{
				Path: "fixtures/pipenv/two-packages.json",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "itsdangerous",
					Version:   "2.1.2",
					Locations: []string{"fixtures/pipenv/two-packages.json"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "markupsafe",
					Version:   "2.1.1",
					Locations: []string{"fixtures/pipenv/two-packages.json"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
			},
		},
		{
			Name: "two packages alt",
			InputConfig: ScanInputMockConfig{
				Path: "fixtures/pipenv/two-packages-alt.json",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "itsdangerous",
					Version:   "2.1.2",
					Locations: []string{"fixtures/pipenv/two-packages-alt.json"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "markupsafe",
					Version:   "2.1.1",
					Locations: []string{"fixtures/pipenv/two-packages-alt.json"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "multiple packages",
			InputConfig: ScanInputMockConfig{
				Path: "fixtures/pipenv/multiple-packages.json",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "itsdangerous",
					Version:   "2.1.2",
					Locations: []string{"fixtures/pipenv/multiple-packages.json"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "pluggy",
					Version:   "1.0.1",
					Locations: []string{"fixtures/pipenv/multiple-packages.json"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "pluggy",
					Version:   "1.0.0",
					Locations: []string{"fixtures/pipenv/multiple-packages.json"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
				{
					Name:      "markupsafe",
					Version:   "2.1.1",
					Locations: []string{"fixtures/pipenv/multiple-packages.json"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "package without version",
			InputConfig: ScanInputMockConfig{
				Path: "fixtures/pipenv/no-version.json",
			},
			WantInventory: []*extractor.Inventory{},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			e := lockfilescalibr.PipenvLockExtractor{}
			_, _ = ExtractionTester(t, e, tt)
		})
	}
}
