package pdmlock_test

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scanner/internal/lockfilescalibr/extractor"
	"github.com/google/osv-scanner/internal/lockfilescalibr/extracttest"
	"github.com/google/osv-scanner/internal/lockfilescalibr/language/python/pdmlock"
	"github.com/google/osv-scanner/internal/lockfilescalibr/othermetadata"
)

func TestPdmExtractor_FileRequired(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		inputPath string
		want      bool
	}{
		{
			name:      "empty",
			inputPath: "",
			want:      false,
		},
		{
			name:      "plain",
			inputPath: "pdm.lock",
			want:      true,
		},
		{
			name:      "absolute",
			inputPath: "/path/to/pdm.lock",
			want:      true,
		},
		{
			name:      "relative",
			inputPath: "../../pdm.lock",
			want:      true,
		},
		{
			name:      "in-path",
			inputPath: "/path/with/pdm.lock/in/middle",
			want:      false,
		},
		{
			name:      "invalid-suffix",
			inputPath: "pdm.lock.file",
			want:      false,
		},
		{
			name:      "invalid-prefix",
			inputPath: "project.name.pdm.lock",
			want:      false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := pdmlock.Extractor{}
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
				Path: "testdata/empty.toml",
			},
			WantInventory: []*extractor.Inventory{},
		},
		{
			Name: "single package",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/single-package.toml",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "toml",
					Version:   "0.10.2",
					Locations: []string{"testdata/single-package.toml"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "two packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/two-packages.toml",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "toml",
					Version:   "0.10.2",
					Locations: []string{"testdata/two-packages.toml"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "six",
					Version:   "1.16.0",
					Locations: []string{"testdata/two-packages.toml"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "package with dev dependencies",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/dev-dependency.toml",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "toml",
					Version:   "0.10.2",
					Locations: []string{"testdata/dev-dependency.toml"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "pyroute2",
					Version:   "0.7.11",
					Locations: []string{"testdata/dev-dependency.toml"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
				{
					Name:      "win-inet-pton",
					Version:   "1.1.0",
					Locations: []string{"testdata/dev-dependency.toml"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
			},
		},
		{
			Name: "package with optional dependency",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/optional-dependency.toml",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "toml",
					Version:   "0.10.2",
					Locations: []string{"testdata/optional-dependency.toml"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "pyroute2",
					Version:   "0.7.11",
					Locations: []string{"testdata/optional-dependency.toml"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"optional"},
					},
				},
				{
					Name:      "win-inet-pton",
					Version:   "1.1.0",
					Locations: []string{"testdata/optional-dependency.toml"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"optional"},
					},
				},
			},
		},
		{
			Name: "package with git dependency",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/git-dependency.toml",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "toml",
					Version:   "0.10.2",
					Locations: []string{"testdata/git-dependency.toml"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "65bab7582ce14c55cdeec2244c65ea23039c9e6f",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			extr := pdmlock.Extractor{}

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
