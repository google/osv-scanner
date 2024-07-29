package lockfilescalibr_test

import (
	"testing"

	"github.com/google/osv-scanner/internal/lockfilescalibr"
	"github.com/google/osv-scanner/internal/lockfilescalibr/extractor"
)

func TestPdmExtractor_FileRequired(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		inputConfig ScanInputMockConfig
		want        bool
	}{
		{
			name: "empty",
			inputConfig: ScanInputMockConfig{
				path: "",
			},
			want: false,
		},
		{
			name: "plain",
			inputConfig: ScanInputMockConfig{
				path: "pdm.lock",
			},
			want: true,
		},
		{
			name: "absolute",
			inputConfig: ScanInputMockConfig{
				path: "/path/to/pdm.lock",
			},
			want: true,
		},
		{
			name: "relative",
			inputConfig: ScanInputMockConfig{
				path: "../../pdm.lock",
			},
			want: true,
		},
		{
			name: "in-path",
			inputConfig: ScanInputMockConfig{
				path: "/path/with/pdm.lock/in/middle",
			},
			want: false,
		},
		{
			name: "invalid-suffix",
			inputConfig: ScanInputMockConfig{
				path: "pdm.lock.file",
			},
			want: false,
		},
		{
			name: "invalid-prefix",
			inputConfig: ScanInputMockConfig{
				path: "project.name.pdm.lock",
			},
			want: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := lockfilescalibr.PdmLockExtractor{}
			got := e.FileRequired(tt.inputConfig.path, GenerateFileInfoMock(t, tt.inputConfig))
			if got != tt.want {
				t.Errorf("FileRequired(%s, FileInfo) got = %v, want %v", tt.inputConfig.path, got, tt.want)
			}
		})
	}
}

func TestPdmLockExtractor_Extract(t *testing.T) {
	t.Parallel()

	tests := []testTableEntry{
		{
			name: "invalid toml",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pdm/not-toml.txt",
			},
			wantErrContaining: "could not extract from",
		},
		{
			name: "no packages",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pdm/empty.toml",
			},
			wantInventory: []*extractor.Inventory{},
		},
		{
			name: "single package",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pdm/single-package.toml",
			},
			wantInventory: []*extractor.Inventory{
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
			name: "two packages",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pdm/two-packages.toml",
			},
			wantInventory: []*extractor.Inventory{
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
			name: "package with dev dependencies",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pdm/dev-dependency.toml",
			},
			wantInventory: []*extractor.Inventory{
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
			name: "package with optional dependency",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pdm/optional-dependency.toml",
			},
			wantInventory: []*extractor.Inventory{
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
			name: "package with git dependency",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pdm/git-dependency.toml",
			},
			wantInventory: []*extractor.Inventory{
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
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := lockfilescalibr.PdmLockExtractor{}
			_, _ = extractionTester(t, e, tt)
		})
	}
}
