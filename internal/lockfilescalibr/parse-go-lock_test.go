package lockfilescalibr_test

import (
	"testing"

	"github.com/google/osv-scanner/internal/lockfilescalibr"
	"github.com/google/osv-scanner/internal/lockfilescalibr/extractor"
)

func TestGoLockExtractor_FileRequired(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		inputConfig ScanInputMockConfig
		want        bool
	}{
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				path: "",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				path: "go.mod",
			},
			want: true,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				path: "path/to/my/go.mod",
			},
			want: true,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				path: "path/to/my/go.mod/file",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				path: "path/to/my/go.mod.file",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				path: "path.to.my.go.mod",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := lockfilescalibr.GoLockExtractor{}
			got := e.FileRequired(tt.inputConfig.path, GenerateFileInfoMock(t, tt.inputConfig))
			if got != tt.want {
				t.Errorf("FileRequired(%s, FileInfo) got = %v, want %v", tt.inputConfig.path, got, tt.want)
			}
		})
	}
}

func TestGoLockExtractor_Extract(t *testing.T) {
	t.Parallel()

	tests := []testTableEntry{
		{
			name: "invalid",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/go/not-go-mod.txt",
			},
			wantInventory:     []*extractor.Inventory{},
			wantErrContaining: "could not extract from",
		},
		{
			name: "no packages",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/go/empty.mod",
			},
			wantInventory: []*extractor.Inventory{},
		},
		{
			name: "one package",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/go/one-package.mod",
			},
			wantInventory: []*extractor.Inventory{
				{
					Name:      "github.com/BurntSushi/toml",
					Version:   "1.0.0",
					Locations: []string{"fixtures/go/one-package.mod"},
				},
			},
		},
		{
			name: "two packages",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/go/two-packages.mod",
			},
			wantInventory: []*extractor.Inventory{
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
			name: "indirect packages",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/go/indirect-packages.mod",
			},
			wantInventory: []*extractor.Inventory{
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
			name: "replacements_ one",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/go/replace-one.mod",
			},
			wantInventory: []*extractor.Inventory{
				{
					Name:      "example.com/fork/net",
					Version:   "1.4.5",
					Locations: []string{"fixtures/go/replace-one.mod"},
				},
			},
		},
		{
			name: "replacements_ mixed",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/go/replace-mixed.mod",
			},
			wantInventory: []*extractor.Inventory{
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
			name: "replacements_ local",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/go/replace-local.mod",
			},
			wantInventory: []*extractor.Inventory{
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
			name: "replacements_ different",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/go/replace-different.mod",
			},
			wantInventory: []*extractor.Inventory{
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
			name: "replacements_ not required",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/go/replace-not-required.mod",
			},
			wantInventory: []*extractor.Inventory{
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
			name: "replacements_ no version",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/go/replace-no-version.mod",
			},
			wantInventory: []*extractor.Inventory{
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
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := lockfilescalibr.GoLockExtractor{}
			_, _ = extractionTester(t, e, tt)
		})
	}
}
