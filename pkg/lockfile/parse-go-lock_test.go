package lockfile_test

import (
	"github.com/google/osv.dev/tools/osv-scanner/pkg/lockfile"
	"testing"
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
		},
		{
			Name:      "gopkg.in/yaml.v2",
			Version:   "2.4.0",
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
	})
}
