package lockfile_test

import (
	"github.com/google/osv-scanner/pkg/models"
	"io/fs"
	"testing"

	"github.com/google/osv-scanner/pkg/lockfile"
)

func TestGoLockExtractor_ShouldExtract(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		path string
		want bool
	}{
		{
			name: "",
			path: "",
			want: false,
		},
		{
			name: "",
			path: "go.mod",
			want: true,
		},
		{
			name: "",
			path: "path/to/my/go.mod",
			want: true,
		},
		{
			name: "",
			path: "path/to/my/go.mod/file",
			want: false,
		},
		{
			name: "",
			path: "path/to/my/go.mod.file",
			want: false,
		},
		{
			name: "",
			path: "path.to.my.go.mod",
			want: false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := lockfile.GoLockExtractor{}
			got := e.ShouldExtract(tt.path)
			if got != tt.want {
				t.Errorf("Extract() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseGoLock_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseGoLock("fixtures/go/does-not-exist")

	expectErrIs(t, err, fs.ErrNotExist)
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseGoLock_Invalid(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseGoLock("fixtures/go/not-go-mod.txt")

	expectErrContaining(t, err, "could not extract from")
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseGoLock_NoPackages(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseGoLock("fixtures/go/empty.mod")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseGoLock_OnePackage(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseGoLock("fixtures/go/one-package.mod")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "github.com/BurntSushi/toml",
			Version:   "1.0.0",
			Ecosystem: lockfile.GoEcosystem,
			CompareAs: lockfile.GoEcosystem,
			Start:     models.FilePosition{Line: 4, Column: 2},
			End:       models.FilePosition{Line: 4, Column: 35},
		},
	})
}

func TestParseGoLock_TwoPackages(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseGoLock("fixtures/go/two-packages.mod")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "github.com/BurntSushi/toml",
			Version:   "1.0.0",
			Ecosystem: lockfile.GoEcosystem,
			CompareAs: lockfile.GoEcosystem,
			Start:     models.FilePosition{Line: 6, Column: 2},
			End:       models.FilePosition{Line: 6, Column: 35},
		},
		{
			Name:      "gopkg.in/yaml.v2",
			Version:   "2.4.0",
			Ecosystem: lockfile.GoEcosystem,
			CompareAs: lockfile.GoEcosystem,
			Start:     models.FilePosition{Line: 7, Column: 2},
			End:       models.FilePosition{Line: 7, Column: 25},
		},
		{
			Name:      "stdlib",
			Version:   "1.17.0",
			Ecosystem: lockfile.GoEcosystem,
			CompareAs: lockfile.GoEcosystem,
		},
	})
}

func TestParseGoLock_IndirectPackages(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseGoLock("fixtures/go/indirect-packages.mod")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "github.com/BurntSushi/toml",
			Version:   "1.0.0",
			Ecosystem: lockfile.GoEcosystem,
			CompareAs: lockfile.GoEcosystem,
			Start:     models.FilePosition{Line: 6, Column: 2},
			End:       models.FilePosition{Line: 6, Column: 35},
		},
		{
			Name:      "gopkg.in/yaml.v2",
			Version:   "2.4.0",
			Ecosystem: lockfile.GoEcosystem,
			CompareAs: lockfile.GoEcosystem,
			Start:     models.FilePosition{Line: 7, Column: 2},
			End:       models.FilePosition{Line: 7, Column: 25},
		},
		{
			Name:      "github.com/mattn/go-colorable",
			Version:   "0.1.9",
			Ecosystem: lockfile.GoEcosystem,
			CompareAs: lockfile.GoEcosystem,
			Start:     models.FilePosition{Line: 11, Column: 2},
			End:       models.FilePosition{Line: 11, Column: 38},
		},
		{
			Name:      "github.com/mattn/go-isatty",
			Version:   "0.0.14",
			Ecosystem: lockfile.GoEcosystem,
			CompareAs: lockfile.GoEcosystem,
			Start:     models.FilePosition{Line: 12, Column: 2},
			End:       models.FilePosition{Line: 12, Column: 36},
		},
		{
			Name:      "golang.org/x/sys",
			Version:   "0.0.0-20210630005230-0f9fa26af87c",
			Ecosystem: lockfile.GoEcosystem,
			CompareAs: lockfile.GoEcosystem,
			Start:     models.FilePosition{Line: 13, Column: 2},
			End:       models.FilePosition{Line: 13, Column: 53},
		},
		{
			Name:      "stdlib",
			Version:   "1.17.0",
			Ecosystem: lockfile.GoEcosystem,
			CompareAs: lockfile.GoEcosystem,
		},
	})
}

func TestParseGoLock_Replacements_One(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseGoLock("fixtures/go/replace-one.mod")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "example.com/fork/net",
			Version:   "1.4.5",
			Ecosystem: lockfile.GoEcosystem,
			CompareAs: lockfile.GoEcosystem,
			Start:     models.FilePosition{Line: 5, Column: 1},
			End:       models.FilePosition{Line: 5, Column: 63},
		},
	})
}

func TestParseGoLock_Replacements_Mixed(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseGoLock("fixtures/go/replace-mixed.mod")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "example.com/fork/net",
			Version:   "1.4.5",
			Ecosystem: lockfile.GoEcosystem,
			CompareAs: lockfile.GoEcosystem,
			Start:     models.FilePosition{Line: 7, Column: 5},
			End:       models.FilePosition{Line: 7, Column: 59},
		},
		{
			Name:      "golang.org/x/net",
			Version:   "0.5.6",
			Ecosystem: lockfile.GoEcosystem,
			CompareAs: lockfile.GoEcosystem,
			Start:     models.FilePosition{Line: 3, Column: 5},
			End:       models.FilePosition{Line: 3, Column: 28},
		},
	})
}

func TestParseGoLock_Replacements_Local(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseGoLock("fixtures/go/replace-local.mod")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "./fork/net",
			Version:   "",
			Ecosystem: lockfile.GoEcosystem,
			CompareAs: lockfile.GoEcosystem,
			Start:     models.FilePosition{Line: 7, Column: 5},
			End:       models.FilePosition{Line: 7, Column: 42},
		},
		{
			Name:      "github.com/BurntSushi/toml",
			Version:   "1.0.0",
			Ecosystem: lockfile.GoEcosystem,
			CompareAs: lockfile.GoEcosystem,
			Start:     models.FilePosition{Line: 3, Column: 5},
			End:       models.FilePosition{Line: 3, Column: 38},
		},
	})
}

func TestParseGoLock_Replacements_Different(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseGoLock("fixtures/go/replace-different.mod")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "example.com/fork/foe",
			Version:   "1.4.5",
			Ecosystem: lockfile.GoEcosystem,
			CompareAs: lockfile.GoEcosystem,
			Start:     models.FilePosition{Line: 7, Column: 5},
			End:       models.FilePosition{Line: 7, Column: 59},
		},
		{
			Name:      "example.com/fork/foe",
			Version:   "1.4.2",
			Ecosystem: lockfile.GoEcosystem,
			CompareAs: lockfile.GoEcosystem,
			Start:     models.FilePosition{Line: 8, Column: 5},
			End:       models.FilePosition{Line: 8, Column: 59},
		},
	})
}

func TestParseGoLock_Replacements_NotRequired(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseGoLock("fixtures/go/replace-not-required.mod")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "golang.org/x/net",
			Version:   "0.5.6",
			Ecosystem: lockfile.GoEcosystem,
			CompareAs: lockfile.GoEcosystem,
			Start:     models.FilePosition{Line: 2, Column: 5},
			End:       models.FilePosition{Line: 2, Column: 28},
		},
		{
			Name:      "github.com/BurntSushi/toml",
			Version:   "1.0.0",
			Ecosystem: lockfile.GoEcosystem,
			CompareAs: lockfile.GoEcosystem,
			Start:     models.FilePosition{Line: 3, Column: 5},
			End:       models.FilePosition{Line: 3, Column: 38},
		},
	})
}

func TestParseGoLock_Replacements_NoVersion(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseGoLock("fixtures/go/replace-no-version.mod")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "example.com/fork/net",
			Version:   "1.4.5",
			Ecosystem: lockfile.GoEcosystem,
			CompareAs: lockfile.GoEcosystem,
			Start:     models.FilePosition{Line: 7, Column: 5},
			End:       models.FilePosition{Line: 7, Column: 52},
		},
	})
}
