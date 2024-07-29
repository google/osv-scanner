package lockfilescalibr_test

import (
	"testing"

	"github.com/google/osv-scanner/internal/lockfilescalibr"
	"github.com/google/osv-scanner/internal/lockfilescalibr/extractor"
	"github.com/google/osv-scanner/internal/lockfilescalibr/sharedtesthelpers"
)

func TestGoLockExtractor_FileRequired(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		inputConfig sharedtesthelpers.ScanInputMockConfig
		want        bool
	}{
		{
			name: "",
			inputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "go.mod",
			},
			want: true,
		},
		{
			name: "",
			inputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "path/to/my/go.mod",
			},
			want: true,
		},
		{
			name: "",
			inputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "path/to/my/go.mod/file",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "path/to/my/go.mod.file",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "path.to.my.go.mod",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := lockfilescalibr.GoLockExtractor{}
			got := e.FileRequired(tt.inputConfig.Path, sharedtesthelpers.GenerateFileInfoMock(t, tt.inputConfig))
			if got != tt.want {
				t.Errorf("FileRequired(%s, FileInfo) got = %v, want %v", tt.inputConfig.Path, got, tt.want)
			}
		})
	}
}

func TestGoLockExtractor_Extract(t *testing.T) {
	t.Parallel()

	tests := []sharedtesthelpers.TestTableEntry{
		{
			Name: "invalid",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "fixtures/go/not-go-mod.txt",
			},
			WantInventory:     []*extractor.Inventory{},
			WantErrContaining: "could not extract from",
		},
		{
			Name: "no packages",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "fixtures/go/empty.mod",
			},
			WantInventory: []*extractor.Inventory{},
		},
		{
			Name: "one package",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "fixtures/go/one-package.mod",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "github.com/BurntSushi/toml",
					Version:   "1.0.0",
					Locations: []string{"fixtures/go/one-package.mod"},
				},
			},
		},
		{
			Name: "two packages",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "fixtures/go/two-packages.mod",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "github.com/BurntSushi/toml",
					Version:   "1.0.0",
					Locations: []string{"fixtures/go/two-packages.mod"},
				},
				{
					Name:      "gopkg.in/yaml.v2",
					Version:   "2.4.0",
					Locations: []string{"fixtures/go/two-packages.mod"},
				},
				{
					Name:      "stdlib",
					Version:   "1.17",
					Locations: []string{"fixtures/go/two-packages.mod"},
				},
			},
		},
		{
			Name: "indirect packages",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "fixtures/go/indirect-packages.mod",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "github.com/BurntSushi/toml",
					Version:   "1.0.0",
					Locations: []string{"fixtures/go/indirect-packages.mod"},
				},
				{
					Name:      "gopkg.in/yaml.v2",
					Version:   "2.4.0",
					Locations: []string{"fixtures/go/indirect-packages.mod"},
				},
				{
					Name:      "github.com/mattn/go-colorable",
					Version:   "0.1.9",
					Locations: []string{"fixtures/go/indirect-packages.mod"},
				},
				{
					Name:      "github.com/mattn/go-isatty",
					Version:   "0.0.14",
					Locations: []string{"fixtures/go/indirect-packages.mod"},
				},
				{
					Name:      "golang.org/x/sys",
					Version:   "0.0.0-20210630005230-0f9fa26af87c",
					Locations: []string{"fixtures/go/indirect-packages.mod"},
				},
				{
					Name:      "stdlib",
					Version:   "1.17",
					Locations: []string{"fixtures/go/indirect-packages.mod"},
				},
			},
		},
		{
			Name: "replacements_ one",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "fixtures/go/replace-one.mod",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "example.com/fork/net",
					Version:   "1.4.5",
					Locations: []string{"fixtures/go/replace-one.mod"},
				},
			},
		},
		{
			Name: "replacements_ mixed",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "fixtures/go/replace-mixed.mod",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "example.com/fork/net",
					Version:   "1.4.5",
					Locations: []string{"fixtures/go/replace-mixed.mod"},
				},
				{
					Name:      "golang.org/x/net",
					Version:   "0.5.6",
					Locations: []string{"fixtures/go/replace-mixed.mod"},
				},
			},
		},
		{
			Name: "replacements_ local",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "fixtures/go/replace-local.mod",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "./fork/net",
					Version:   "",
					Locations: []string{"fixtures/go/replace-local.mod"},
				},
				{
					Name:      "github.com/BurntSushi/toml",
					Version:   "1.0.0",
					Locations: []string{"fixtures/go/replace-local.mod"},
				},
			},
		},
		{
			Name: "replacements_ different",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "fixtures/go/replace-different.mod",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "example.com/fork/foe",
					Version:   "1.4.5",
					Locations: []string{"fixtures/go/replace-different.mod"},
				},
				{
					Name:      "example.com/fork/foe",
					Version:   "1.4.2",
					Locations: []string{"fixtures/go/replace-different.mod"},
				},
			},
		},
		{
			Name: "replacements_ not required",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "fixtures/go/replace-not-required.mod",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "golang.org/x/net",
					Version:   "0.5.6",
					Locations: []string{"fixtures/go/replace-not-required.mod"},
				},
				{
					Name:      "github.com/BurntSushi/toml",
					Version:   "1.0.0",
					Locations: []string{"fixtures/go/replace-not-required.mod"},
				},
			},
		},
		{
			Name: "replacements_ no version",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "fixtures/go/replace-no-version.mod",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "example.com/fork/net",
					Version:   "1.4.5",
					Locations: []string{"fixtures/go/replace-no-version.mod"},
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			e := lockfilescalibr.GoLockExtractor{}
			_, _ = sharedtesthelpers.ExtractionTester(t, e, tt)
		})
	}
}
