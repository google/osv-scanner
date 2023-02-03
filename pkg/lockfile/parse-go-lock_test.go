package lockfile_test

import (
	"testing"

	"github.com/google/osv-scanner/pkg/lockfile"
)

func TestParseGoLock_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseGoLock("fixtures/go/does-not-exist")

	expectErrContaining(t, err, "could not read")
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseGoLock_Invalid(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseGoLock("fixtures/go/not-go-mod.txt")

	expectErrContaining(t, err, "could not parse")
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseGoLockWithDiagnostics(t *testing.T) {
	t.Parallel()

	testParserWithDiagnostics(t, lockfile.ParseGoLockWithDiagnostics, []testParserWithDiagnosticsTest{
		// no packages
		{
			name: "",
			file: "fixtures/go/empty.mod",
			want: []lockfile.PackageDetails{},
			diag: lockfile.Diagnostics{},
		},
		// one package
		{
			name: "",
			file: "fixtures/go/one-package.mod",
			want: []lockfile.PackageDetails{
				{
					Name:      "github.com/BurntSushi/toml",
					Version:   "1.0.0",
					Ecosystem: lockfile.GoEcosystem,
					CompareAs: lockfile.GoEcosystem,
				},
			},
			diag: lockfile.Diagnostics{},
		},
		// two packages
		{
			name: "",
			file: "fixtures/go/two-packages.mod",
			want: []lockfile.PackageDetails{
				{
					Name:      "github.com/BurntSushi/toml",
					Version:   "1.0.0",
					Ecosystem: lockfile.GoEcosystem,
					CompareAs: lockfile.GoEcosystem,
				},
				{
					Name:      "gopkg.in/yaml.v2",
					Version:   "2.4.0",
					Ecosystem: lockfile.GoEcosystem,
					CompareAs: lockfile.GoEcosystem,
				},
			},
			diag: lockfile.Diagnostics{},
		},
		// indirect packages
		{
			name: "",
			file: "fixtures/go/indirect-packages.mod",
			want: []lockfile.PackageDetails{
				{
					Name:      "github.com/BurntSushi/toml",
					Version:   "1.0.0",
					Ecosystem: lockfile.GoEcosystem,
					CompareAs: lockfile.GoEcosystem,
				},
				{
					Name:      "gopkg.in/yaml.v2",
					Version:   "2.4.0",
					Ecosystem: lockfile.GoEcosystem,
					CompareAs: lockfile.GoEcosystem,
				},
				{
					Name:      "github.com/mattn/go-colorable",
					Version:   "0.1.9",
					Ecosystem: lockfile.GoEcosystem,
					CompareAs: lockfile.GoEcosystem,
				},
				{
					Name:      "github.com/mattn/go-isatty",
					Version:   "0.0.14",
					Ecosystem: lockfile.GoEcosystem,
					CompareAs: lockfile.GoEcosystem,
				},
				{
					Name:      "golang.org/x/sys",
					Version:   "0.0.0-20210630005230-0f9fa26af87c",
					Ecosystem: lockfile.GoEcosystem,
					CompareAs: lockfile.GoEcosystem,
				},
			},
			diag: lockfile.Diagnostics{},
		},
		// replacements, one
		{
			name: "",
			file: "fixtures/go/replace-one.mod",
			want: []lockfile.PackageDetails{
				{
					Name:      "example.com/fork/net",
					Version:   "1.4.5",
					Ecosystem: lockfile.GoEcosystem,
					CompareAs: lockfile.GoEcosystem,
				},
			},
			diag: lockfile.Diagnostics{},
		},
		// replacements, mixed
		{
			name: "",
			file: "fixtures/go/replace-mixed.mod",
			want: []lockfile.PackageDetails{
				{
					Name:      "example.com/fork/net",
					Version:   "1.4.5",
					Ecosystem: lockfile.GoEcosystem,
					CompareAs: lockfile.GoEcosystem,
				},
				{
					Name:      "golang.org/x/net",
					Version:   "0.5.6",
					Ecosystem: lockfile.GoEcosystem,
					CompareAs: lockfile.GoEcosystem,
				},
			},
			diag: lockfile.Diagnostics{},
		},
		// replacements, local
		{
			name: "",
			file: "fixtures/go/replace-local.mod",
			want: []lockfile.PackageDetails{
				{
					Name:      "./fork/net",
					Version:   "",
					Ecosystem: lockfile.GoEcosystem,
					CompareAs: lockfile.GoEcosystem,
				},
				{
					Name:      "github.com/BurntSushi/toml",
					Version:   "1.0.0",
					Ecosystem: lockfile.GoEcosystem,
					CompareAs: lockfile.GoEcosystem,
				},
			},
			diag: lockfile.Diagnostics{},
		},
		// replacements different
		{
			name: "",
			file: "fixtures/go/replace-different.mod",
			want: []lockfile.PackageDetails{
				{
					Name:      "example.com/fork/foe",
					Version:   "1.4.5",
					Ecosystem: lockfile.GoEcosystem,
					CompareAs: lockfile.GoEcosystem,
				},
				{
					Name:      "example.com/fork/foe",
					Version:   "1.4.2",
					Ecosystem: lockfile.GoEcosystem,
					CompareAs: lockfile.GoEcosystem,
				},
			},
			diag: lockfile.Diagnostics{},
		},
		// replacements, not required
		{
			name: "",
			file: "fixtures/go/replace-not-required.mod",
			want: []lockfile.PackageDetails{
				{
					Name:      "golang.org/x/net",
					Version:   "0.5.6",
					Ecosystem: lockfile.GoEcosystem,
					CompareAs: lockfile.GoEcosystem,
				},
				{
					Name:      "github.com/BurntSushi/toml",
					Version:   "1.0.0",
					Ecosystem: lockfile.GoEcosystem,
					CompareAs: lockfile.GoEcosystem,
				},
			},
			diag: lockfile.Diagnostics{},
		},
		// replacements, no version
		{
			name: "",
			file: "fixtures/go/replace-no-version.mod",
			want: []lockfile.PackageDetails{
				{
					Name:      "example.com/fork/net",
					Version:   "1.4.5",
					Ecosystem: lockfile.GoEcosystem,
					CompareAs: lockfile.GoEcosystem,
				},
			},
			diag: lockfile.Diagnostics{},
		},
	})
}
