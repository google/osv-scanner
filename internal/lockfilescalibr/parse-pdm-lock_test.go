package lockfilescalibr_test

import (
	"testing"

	"github.com/google/osv-scanner/internal/lockfilescalibr"
	"github.com/google/osv-scanner/internal/lockfilescalibr/extractor"
	"github.com/google/osv-scanner/internal/lockfilescalibr/sharedtesthelpers"
)

func TestPdmExtractor_FileRequired(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		inputConfig sharedtesthelpers.ScanInputMockConfig
		want        bool
	}{
		{
			name: "empty",
			inputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "",
			},
			want: false,
		},
		{
			name: "plain",
			inputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "pdm.lock",
			},
			want: true,
		},
		{
			name: "absolute",
			inputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "/path/to/pdm.lock",
			},
			want: true,
		},
		{
			name: "relative",
			inputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "../../pdm.lock",
			},
			want: true,
		},
		{
			name: "in-path",
			inputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "/path/with/pdm.lock/in/middle",
			},
			want: false,
		},
		{
			name: "invalid-suffix",
			inputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "pdm.lock.file",
			},
			want: false,
		},
		{
			name: "invalid-prefix",
			inputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "project.name.pdm.lock",
			},
			want: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := lockfilescalibr.PdmLockExtractor{}
			got := e.FileRequired(tt.inputConfig.Path, sharedtesthelpers.GenerateFileInfoMock(t, tt.inputConfig))
			if got != tt.want {
				t.Errorf("FileRequired(%s, FileInfo) got = %v, want %v", tt.inputConfig.Path, got, tt.want)
			}
		})
	}
}

func TestPdmLockExtractor_Extract(t *testing.T) {
	t.Parallel()

	tests := []sharedtesthelpers.TestTableEntry{
		{
			Name: "invalid toml",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "fixtures/pdm/not-toml.txt",
			},
			WantErrContaining: "could not extract from",
		},
		{
			Name: "no packages",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "fixtures/pdm/empty.toml",
			},
			WantInventory: []*extractor.Inventory{},
		},
		{
			Name: "single package",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "fixtures/pdm/single-package.toml",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "toml",
					Version:   "0.10.2",
					Locations: []string{"fixtures/pdm/single-package.toml"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "two packages",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "fixtures/pdm/two-packages.toml",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "toml",
					Version:   "0.10.2",
					Locations: []string{"fixtures/pdm/two-packages.toml"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "six",
					Version:   "1.16.0",
					Locations: []string{"fixtures/pdm/two-packages.toml"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "package with dev dependencies",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "fixtures/pdm/dev-dependency.toml",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "toml",
					Version:   "0.10.2",
					Locations: []string{"fixtures/pdm/dev-dependency.toml"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "pyroute2",
					Version:   "0.7.11",
					Locations: []string{"fixtures/pdm/dev-dependency.toml"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
				{
					Name:      "win-inet-pton",
					Version:   "1.1.0",
					Locations: []string{"fixtures/pdm/dev-dependency.toml"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
			},
		},
		{
			Name: "package with optional dependency",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "fixtures/pdm/optional-dependency.toml",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "toml",
					Version:   "0.10.2",
					Locations: []string{"fixtures/pdm/optional-dependency.toml"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "pyroute2",
					Version:   "0.7.11",
					Locations: []string{"fixtures/pdm/optional-dependency.toml"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"optional"},
					},
				},
				{
					Name:      "win-inet-pton",
					Version:   "1.1.0",
					Locations: []string{"fixtures/pdm/optional-dependency.toml"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"optional"},
					},
				},
			},
		},
		{
			Name: "package with git dependency",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "fixtures/pdm/git-dependency.toml",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "toml",
					Version:   "0.10.2",
					Locations: []string{"fixtures/pdm/git-dependency.toml"},
					Metadata: lockfilescalibr.DepGroupMetadata{
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
			e := lockfilescalibr.PdmLockExtractor{}
			_, _ = sharedtesthelpers.ExtractionTester(t, e, tt)
		})
	}
}
