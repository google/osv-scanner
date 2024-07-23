package lockfile_test

import (
	"context"
	"testing"

	"github.com/google/osv-scanner/pkg/lockfile"
)

func TestGoLockExtractor_ShouldExtract(t *testing.T) {
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
	for i, tt := range tests {
		tt := tt
		i := i
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := lockfile.GoLockExtractor{}
			got := e.FileRequired(tt.inputConfig.path, GenerateFileInfoMock(t, tt.inputConfig))
			if got != tt.want {
				t.Errorf("[#%02d] FileRequired(%s, FileInfo) got = %v, want %v", i, tt.inputConfig.path, got, tt.want)
			}
		})
	}
}

func TestExtractGoLock(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		inputConfig       ScanInputMockConfig
		wantInventory     []*lockfile.Inventory
		wantErrIs         error
		wantErrContaining string
	}{

		{
			name: "file does not exist",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/go/does-not-exist",
			},
			wantInventory: []*lockfile.Inventory{},
		},

		{
			name: "invalid",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/go/not-go-mod.txt",
			},
			wantInventory: []*lockfile.Inventory{},
		},

		{
			name: "no packages",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/go/empty.mod",
			},
			wantInventory: []*lockfile.Inventory{},
		},

		{
			name: "one package",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/go/one-package.mod",
			},
			wantInventory: []*lockfile.Inventory{

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
			wantInventory: []*lockfile.Inventory{

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
			wantInventory: []*lockfile.Inventory{

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
			wantInventory: []*lockfile.Inventory{

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
			wantInventory: []*lockfile.Inventory{

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
			wantInventory: []*lockfile.Inventory{

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
			wantInventory: []*lockfile.Inventory{

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
			wantInventory: []*lockfile.Inventory{

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
			wantInventory: []*lockfile.Inventory{

				{
					Name:      "example.com/fork/net",
					Version:   "1.4.5",
					Locations: []string{"fixtures/go/replace-no-version.mod"},
				},
			},
		},
	}

	for i, tt := range tests {
		tt := tt
		i := i
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := lockfile.CargoLockExtractor{}
			wrapper := GenerateScanInputMock(t, tt.inputConfig)
			got, err := e.Extract(context.Background(), &wrapper.ScanInput)
			wrapper.Close()
			if tt.wantErrIs != nil {
				expectErrIs(t, err, tt.wantErrIs)
			}
			if tt.wantErrContaining != "" {
				expectErrContaining(t, err, tt.wantErrContaining)
			}
			FillExtractorField(got, e)
			FillExtractorField(tt.wantInventory, e)
			expectPackages(t, got, tt.wantInventory)
			if t.Failed() {
				t.Errorf("failed running [%d]: %s", i, tt.name)
			}
		})
	}
}

// func TestParseGoLock_FileDoesNotExist(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfile.ParseGoLock("fixtures/go/does-not-exist")

// 	expectErrIs(t, err, fs.ErrNotExist)
// 	expectPackages(t, packages, []lockfile.PackageDetails{})
// }

// func TestParseGoLock_Invalid(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfile.ParseGoLock("fixtures/go/not-go-mod.txt")

// 	expectErrContaining(t, err, "could not extract from")
// 	expectPackages(t, packages, []lockfile.PackageDetails{})
// }

// func TestParseGoLock_NoPackages(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfile.ParseGoLock("fixtures/go/empty.mod")

// 	if err != nil {
// 		t.Errorf("Got unexpected error: %v", err)
// 	}

// 	expectPackages(t, packages, []lockfile.PackageDetails{})
// }

// func TestParseGoLock_OnePackage(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfile.ParseGoLock("fixtures/go/one-package.mod")

// 	if err != nil {
// 		t.Errorf("Got unexpected error: %v", err)
// 	}

// 	expectPackages(t, packages, []lockfile.PackageDetails{
// 		{
// 			Name:      "github.com/BurntSushi/toml",
// 			Version:   "1.0.0",
// 			Ecosystem: lockfile.GoEcosystem,
// 			CompareAs: lockfile.GoEcosystem,
// 		},
// 	})
// }

// func TestParseGoLock_TwoPackages(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfile.ParseGoLock("fixtures/go/two-packages.mod")

// 	if err != nil {
// 		t.Errorf("Got unexpected error: %v", err)
// 	}

// 	expectPackages(t, packages, []lockfile.PackageDetails{
// 		{
// 			Name:      "github.com/BurntSushi/toml",
// 			Version:   "1.0.0",
// 			Ecosystem: lockfile.GoEcosystem,
// 			CompareAs: lockfile.GoEcosystem,
// 		},
// 		{
// 			Name:      "gopkg.in/yaml.v2",
// 			Version:   "2.4.0",
// 			Ecosystem: lockfile.GoEcosystem,
// 			CompareAs: lockfile.GoEcosystem,
// 		},
// 		{
// 			Name:      "stdlib",
// 			Version:   "1.17",
// 			Ecosystem: lockfile.GoEcosystem,
// 			CompareAs: lockfile.GoEcosystem,
// 		},
// 	})
// }

// func TestParseGoLock_IndirectPackages(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfile.ParseGoLock("fixtures/go/indirect-packages.mod")

// 	if err != nil {
// 		t.Errorf("Got unexpected error: %v", err)
// 	}

// 	expectPackages(t, packages, []lockfile.PackageDetails{
// 		{
// 			Name:      "github.com/BurntSushi/toml",
// 			Version:   "1.0.0",
// 			Ecosystem: lockfile.GoEcosystem,
// 			CompareAs: lockfile.GoEcosystem,
// 		},
// 		{
// 			Name:      "gopkg.in/yaml.v2",
// 			Version:   "2.4.0",
// 			Ecosystem: lockfile.GoEcosystem,
// 			CompareAs: lockfile.GoEcosystem,
// 		},
// 		{
// 			Name:      "github.com/mattn/go-colorable",
// 			Version:   "0.1.9",
// 			Ecosystem: lockfile.GoEcosystem,
// 			CompareAs: lockfile.GoEcosystem,
// 		},
// 		{
// 			Name:      "github.com/mattn/go-isatty",
// 			Version:   "0.0.14",
// 			Ecosystem: lockfile.GoEcosystem,
// 			CompareAs: lockfile.GoEcosystem,
// 		},
// 		{
// 			Name:      "golang.org/x/sys",
// 			Version:   "0.0.0-20210630005230-0f9fa26af87c",
// 			Ecosystem: lockfile.GoEcosystem,
// 			CompareAs: lockfile.GoEcosystem,
// 		},
// 		{
// 			Name:      "stdlib",
// 			Version:   "1.17",
// 			Ecosystem: lockfile.GoEcosystem,
// 			CompareAs: lockfile.GoEcosystem,
// 		},
// 	})
// }

// func TestParseGoLock_Replacements_One(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfile.ParseGoLock("fixtures/go/replace-one.mod")

// 	if err != nil {
// 		t.Errorf("Got unexpected error: %v", err)
// 	}

// 	expectPackages(t, packages, []lockfile.PackageDetails{
// 		{
// 			Name:      "example.com/fork/net",
// 			Version:   "1.4.5",
// 			Ecosystem: lockfile.GoEcosystem,
// 			CompareAs: lockfile.GoEcosystem,
// 		},
// 	})
// }

// func TestParseGoLock_Replacements_Mixed(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfile.ParseGoLock("fixtures/go/replace-mixed.mod")

// 	if err != nil {
// 		t.Errorf("Got unexpected error: %v", err)
// 	}

// 	expectPackages(t, packages, []lockfile.PackageDetails{
// 		{
// 			Name:      "example.com/fork/net",
// 			Version:   "1.4.5",
// 			Ecosystem: lockfile.GoEcosystem,
// 			CompareAs: lockfile.GoEcosystem,
// 		},
// 		{
// 			Name:      "golang.org/x/net",
// 			Version:   "0.5.6",
// 			Ecosystem: lockfile.GoEcosystem,
// 			CompareAs: lockfile.GoEcosystem,
// 		},
// 	})
// }

// func TestParseGoLock_Replacements_Local(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfile.ParseGoLock("fixtures/go/replace-local.mod")

// 	if err != nil {
// 		t.Errorf("Got unexpected error: %v", err)
// 	}

// 	expectPackages(t, packages, []lockfile.PackageDetails{
// 		{
// 			Name:      "./fork/net",
// 			Version:   "",
// 			Ecosystem: lockfile.GoEcosystem,
// 			CompareAs: lockfile.GoEcosystem,
// 		},
// 		{
// 			Name:      "github.com/BurntSushi/toml",
// 			Version:   "1.0.0",
// 			Ecosystem: lockfile.GoEcosystem,
// 			CompareAs: lockfile.GoEcosystem,
// 		},
// 	})
// }

// func TestParseGoLock_Replacements_Different(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfile.ParseGoLock("fixtures/go/replace-different.mod")

// 	if err != nil {
// 		t.Errorf("Got unexpected error: %v", err)
// 	}

// 	expectPackages(t, packages, []lockfile.PackageDetails{
// 		{
// 			Name:      "example.com/fork/foe",
// 			Version:   "1.4.5",
// 			Ecosystem: lockfile.GoEcosystem,
// 			CompareAs: lockfile.GoEcosystem,
// 		},
// 		{
// 			Name:      "example.com/fork/foe",
// 			Version:   "1.4.2",
// 			Ecosystem: lockfile.GoEcosystem,
// 			CompareAs: lockfile.GoEcosystem,
// 		},
// 	})
// }

// func TestParseGoLock_Replacements_NotRequired(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfile.ParseGoLock("fixtures/go/replace-not-required.mod")

// 	if err != nil {
// 		t.Errorf("Got unexpected error: %v", err)
// 	}

// 	expectPackages(t, packages, []lockfile.PackageDetails{
// 		{
// 			Name:      "golang.org/x/net",
// 			Version:   "0.5.6",
// 			Ecosystem: lockfile.GoEcosystem,
// 			CompareAs: lockfile.GoEcosystem,
// 		},
// 		{
// 			Name:      "github.com/BurntSushi/toml",
// 			Version:   "1.0.0",
// 			Ecosystem: lockfile.GoEcosystem,
// 			CompareAs: lockfile.GoEcosystem,
// 		},
// 	})
// }

// func TestParseGoLock_Replacements_NoVersion(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfile.ParseGoLock("fixtures/go/replace-no-version.mod")

// 	if err != nil {
// 		t.Errorf("Got unexpected error: %v", err)
// 	}

// 	expectPackages(t, packages, []lockfile.PackageDetails{
// 		{
// 			Name:      "example.com/fork/net",
// 			Version:   "1.4.5",
// 			Ecosystem: lockfile.GoEcosystem,
// 			CompareAs: lockfile.GoEcosystem,
// 		},
// 	})
// }
