package lockfilescalibr_test

import (
	"testing"

	"github.com/google/osv-scanner/internal/lockfilescalibr"
	"github.com/google/osv-scanner/internal/lockfilescalibr/extractor"
)

func TestPoetryLockExtractor_FileRequired(t *testing.T) {
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
				Path: "poetry.lock",
			},
			want: true,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				Path: "path/to/my/poetry.lock",
			},
			want: true,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				Path: "path/to/my/poetry.lock/file",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				Path: "path/to/my/poetry.lock.file",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				Path: "path.to.my.poetry.lock",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := lockfilescalibr.PoetryLockExtractor{}
			got := e.FileRequired(tt.inputConfig.Path, GenerateFileInfoMock(t, tt.inputConfig))
			if got != tt.want {
				t.Errorf("FileRequired(%s, FileInfo) got = %v, want %v", tt.inputConfig.Path, got, tt.want)
			}
		})
	}
}

func TestPoetryLockExtractor_Extract(t *testing.T) {
	t.Parallel()
	tests := []TestTableEntry{
		{
			Name: "invalid toml",
			InputConfig: ScanInputMockConfig{
				Path: "fixtures/poetry/not-toml.txt",
			},
			WantErrContaining: "could not extract from",
		},
		{
			Name: "no packages",
			InputConfig: ScanInputMockConfig{
				Path: "fixtures/poetry/empty.lock",
			},
			WantInventory: []*extractor.Inventory{},
		},
		{
			Name: "one package",
			InputConfig: ScanInputMockConfig{
				Path: "fixtures/poetry/one-package.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "numpy",
					Version:   "1.23.3",
					Locations: []string{"fixtures/poetry/one-package.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "two packages",
			InputConfig: ScanInputMockConfig{
				Path: "fixtures/poetry/two-packages.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "proto-plus",
					Version:   "1.22.0",
					Locations: []string{"fixtures/poetry/two-packages.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "protobuf",
					Version:   "4.21.5",
					Locations: []string{"fixtures/poetry/two-packages.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "package with metadata",
			InputConfig: ScanInputMockConfig{
				Path: "fixtures/poetry/one-package-with-metadata.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "emoji",
					Version:   "2.0.0",
					Locations: []string{"fixtures/poetry/one-package-with-metadata.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "package with git source",
			InputConfig: ScanInputMockConfig{
				Path: "fixtures/poetry/source-git.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "ike",
					Version:   "0.2.0",
					Locations: []string{"fixtures/poetry/source-git.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "cd66602cd29f61a2d2e7fb995fef1e61708c034d",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "package with legacy source",
			InputConfig: ScanInputMockConfig{
				Path: "fixtures/poetry/source-legacy.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "appdirs",
					Version:   "1.4.4",
					Locations: []string{"fixtures/poetry/source-legacy.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "optional package",
			InputConfig: ScanInputMockConfig{
				Path: "fixtures/poetry/optional-package.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "numpy",
					Version:   "1.23.3",
					Locations: []string{"fixtures/poetry/optional-package.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"optional"},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			e := lockfilescalibr.PoetryLockExtractor{}
			_, _ = ExtractionTester(t, e, tt)
		})
	}
}
