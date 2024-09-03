package pdmlock_test

import (
	"testing"

	"github.com/google/osv-scanner/internal/lockfilescalibr/extractor"
	"github.com/google/osv-scanner/internal/lockfilescalibr/language/python/pdmlock"
	"github.com/google/osv-scanner/internal/lockfilescalibr/othermetadata"
	"github.com/google/osv-scanner/internal/lockfilescalibr/sharedtesthelpers"
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
			got := e.FileRequired(tt.inputPath, sharedtesthelpers.GenerateFileInfoMock(t, tt.inputConfig))
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
			Name:              "invalid toml",
			inputPath:         "testdata/not-toml.txt",
			WantErrContaining: "could not extract from",
		},
		{
			Name:          "no packages",
			inputPath:     "testdata/empty.toml",
			WantInventory: []*extractor.Inventory{},
		},
		{
			Name:      "single package",
			inputPath: "testdata/single-package.toml",
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
			Name:      "two packages",
			inputPath: "testdata/two-packages.toml",
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
			Name:      "package with dev dependencies",
			inputPath: "testdata/dev-dependency.toml",
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
			Name:      "package with optional dependency",
			inputPath: "testdata/optional-dependency.toml",
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
			Name:      "package with git dependency",
			inputPath: "testdata/git-dependency.toml",
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
			e := pdmlock.Extractor{}
			_, _ = sharedtesthelpers.ExtractionTester(t, e, tt)
		})
	}
}
