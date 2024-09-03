package gomod_test

import (
	"testing"

	"github.com/google/osv-scanner/internal/lockfilescalibr/extractor"
	"github.com/google/osv-scanner/internal/lockfilescalibr/language/go/gomod"
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
			inputPath: "go.mod",
			want:      true,
		},
		{
			name:      "",
			inputPath: "path/to/my/go.mod",
			want:      true,
		},
		{
			name:      "",
			inputPath: "path/to/my/go.mod/file",
			want:      false,
		},
		{
			name:      "",
			inputPath: "path/to/my/go.mod.file",
			want:      false,
		},
		{
			name:      "",
			inputPath: "path.to.my.go.mod",
			want:      false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := gomod.Extractor{}
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
			Name:              "invalid",
			inputPath:         "testdata/not-go-mod.txt",
			WantInventory:     []*extractor.Inventory{},
			WantErrContaining: "could not extract from",
		},
		{
			Name:          "no packages",
			inputPath:     "testdata/empty.mod",
			WantInventory: []*extractor.Inventory{},
		},
		{
			Name:      "one package",
			inputPath: "testdata/one-package.mod",
			WantInventory: []*extractor.Inventory{
				{
					Name:      "github.com/BurntSushi/toml",
					Version:   "1.0.0",
					Locations: []string{"testdata/one-package.mod"},
				},
			},
		},
		{
			Name:      "two packages",
			inputPath: "testdata/two-packages.mod",
			WantInventory: []*extractor.Inventory{
				{
					Name:      "github.com/BurntSushi/toml",
					Version:   "1.0.0",
					Locations: []string{"testdata/two-packages.mod"},
				},
				{
					Name:      "gopkg.in/yaml.v2",
					Version:   "2.4.0",
					Locations: []string{"testdata/two-packages.mod"},
				},
				{
					Name:      "stdlib",
					Version:   "1.17",
					Locations: []string{"testdata/two-packages.mod"},
				},
			},
		},
		{
			Name:      "indirect packages",
			inputPath: "testdata/indirect-packages.mod",
			WantInventory: []*extractor.Inventory{
				{
					Name:      "github.com/BurntSushi/toml",
					Version:   "1.0.0",
					Locations: []string{"testdata/indirect-packages.mod"},
				},
				{
					Name:      "gopkg.in/yaml.v2",
					Version:   "2.4.0",
					Locations: []string{"testdata/indirect-packages.mod"},
				},
				{
					Name:      "github.com/mattn/go-colorable",
					Version:   "0.1.9",
					Locations: []string{"testdata/indirect-packages.mod"},
				},
				{
					Name:      "github.com/mattn/go-isatty",
					Version:   "0.0.14",
					Locations: []string{"testdata/indirect-packages.mod"},
				},
				{
					Name:      "golang.org/x/sys",
					Version:   "0.0.0-20210630005230-0f9fa26af87c",
					Locations: []string{"testdata/indirect-packages.mod"},
				},
				{
					Name:      "stdlib",
					Version:   "1.17",
					Locations: []string{"testdata/indirect-packages.mod"},
				},
			},
		},
		{
			Name:      "replacements_ one",
			inputPath: "testdata/replace-one.mod",
			WantInventory: []*extractor.Inventory{
				{
					Name:      "example.com/fork/net",
					Version:   "1.4.5",
					Locations: []string{"testdata/replace-one.mod"},
				},
			},
		},
		{
			Name:      "replacements_ mixed",
			inputPath: "testdata/replace-mixed.mod",
			WantInventory: []*extractor.Inventory{
				{
					Name:      "example.com/fork/net",
					Version:   "1.4.5",
					Locations: []string{"testdata/replace-mixed.mod"},
				},
				{
					Name:      "golang.org/x/net",
					Version:   "0.5.6",
					Locations: []string{"testdata/replace-mixed.mod"},
				},
			},
		},
		{
			Name:      "replacements_ local",
			inputPath: "testdata/replace-local.mod",
			WantInventory: []*extractor.Inventory{
				{
					Name:      "./fork/net",
					Version:   "",
					Locations: []string{"testdata/replace-local.mod"},
				},
				{
					Name:      "github.com/BurntSushi/toml",
					Version:   "1.0.0",
					Locations: []string{"testdata/replace-local.mod"},
				},
			},
		},
		{
			Name:      "replacements_ different",
			inputPath: "testdata/replace-different.mod",
			WantInventory: []*extractor.Inventory{
				{
					Name:      "example.com/fork/foe",
					Version:   "1.4.5",
					Locations: []string{"testdata/replace-different.mod"},
				},
				{
					Name:      "example.com/fork/foe",
					Version:   "1.4.2",
					Locations: []string{"testdata/replace-different.mod"},
				},
			},
		},
		{
			Name:      "replacements_ not required",
			inputPath: "testdata/replace-not-required.mod",
			WantInventory: []*extractor.Inventory{
				{
					Name:      "golang.org/x/net",
					Version:   "0.5.6",
					Locations: []string{"testdata/replace-not-required.mod"},
				},
				{
					Name:      "github.com/BurntSushi/toml",
					Version:   "1.0.0",
					Locations: []string{"testdata/replace-not-required.mod"},
				},
			},
		},
		{
			Name:      "replacements_ no version",
			inputPath: "testdata/replace-no-version.mod",
			WantInventory: []*extractor.Inventory{
				{
					Name:      "example.com/fork/net",
					Version:   "1.4.5",
					Locations: []string{"testdata/replace-no-version.mod"},
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			e := gomod.Extractor{}
			_, _ = sharedtesthelpers.ExtractionTester(t, e, tt)
		})
	}
}
