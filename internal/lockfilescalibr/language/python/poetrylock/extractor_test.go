package poetrylock_test

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scanner/internal/lockfilescalibr/extractor"
	"github.com/google/osv-scanner/internal/lockfilescalibr/extracttest"
	"github.com/google/osv-scanner/internal/lockfilescalibr/language/python/poetrylock"
	"github.com/google/osv-scanner/internal/lockfilescalibr/othermetadata"
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
			inputPath: "poetry.lock",
			want:      true,
		},
		{
			name:      "",
			inputPath: "path/to/my/poetry.lock",
			want:      true,
		},
		{
			name:      "",
			inputPath: "path/to/my/poetry.lock/file",
			want:      false,
		},
		{
			name:      "",
			inputPath: "path/to/my/poetry.lock.file",
			want:      false,
		},
		{
			name:      "",
			inputPath: "path.to.my.poetry.lock",
			want:      false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := poetrylock.Extractor{}
			got := e.FileRequired(tt.inputPath, nil)
			if got != tt.want {
				t.Errorf("FileRequired(%s, FileInfo) got = %v, want %v", tt.inputPath, got, tt.want)
			}
		})
	}
}

func TestExtractor_Extract(t *testing.T) {
	t.Parallel()
	tests := []extracttest.TestTableEntry{
		{
			Name: "invalid toml",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/not-toml.txt",
			},
			WantErr: extracttest.ContainsErrStr{Str: "could not extract from"},
		},
		{
			Name: "no packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty.lock",
			},
			WantInventory: []*extractor.Inventory{},
		},
		{
			Name: "one package",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/one-package.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "numpy",
					Version:   "1.23.3",
					Locations: []string{"testdata/one-package.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "two packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/two-packages.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "proto-plus",
					Version:   "1.22.0",
					Locations: []string{"testdata/two-packages.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "protobuf",
					Version:   "4.21.5",
					Locations: []string{"testdata/two-packages.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "package with metadata",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/one-package-with-metadata.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "emoji",
					Version:   "2.0.0",
					Locations: []string{"testdata/one-package-with-metadata.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "package with git source",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/source-git.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "ike",
					Version:   "0.2.0",
					Locations: []string{"testdata/source-git.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "cd66602cd29f61a2d2e7fb995fef1e61708c034d",
					},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "package with legacy source",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/source-legacy.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "appdirs",
					Version:   "1.4.4",
					Locations: []string{"testdata/source-legacy.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "optional package",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/optional-package.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "numpy",
					Version:   "1.23.3",
					Locations: []string{"testdata/optional-package.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: othermetadata.DepGroupMetadata{
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
			extr := poetrylock.Extractor{}

			scanInput := extracttest.GenerateScanInputMock(t, tt.InputConfig)
			defer extracttest.CloseTestScanInput(t, scanInput)

			got, err := extr.Extract(context.Background(), &scanInput)

			if diff := cmp.Diff(tt.WantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("%s.Extract(%q) error diff (-want +got):\n%s", extr.Name(), tt.InputConfig.Path, diff)
				return
			}

			if diff := cmp.Diff(tt.WantInventory, got, cmpopts.SortSlices(extracttest.InventoryCmpLess)); diff != "" {
				t.Errorf("%s.Extract(%q) diff (-want +got):\n%s", extr.Name(), tt.InputConfig.Path, diff)
			}
		})
	}
}
