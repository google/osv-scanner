package lockfile_test

import (
	"testing"

	"github.com/google/osv-scanner/pkg/lockfile"
)

func TestParseRpmDB_SQLite_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseRpmDB("fixtures/rpm/does-not-exist")

	expectErrContaining(t, err, "could not open")
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseRpmDB_SQLite_EmptyFile(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseRpmDB("fixtures/rpm/empty-rpmdb")

	expectErrContaining(t, err, "could not open")
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseRpmDB_SQLite_NotAnRpmDb(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseRpmDB("fixtures/rpm/not-an-rpmdb")

	expectErrContaining(t, err, "could not open")
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

// Berkeley DB (rpm < v4.16)
func TestParseRpmDB_BDB_Single(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseRpmDB("fixtures/rpm/Packages")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "htop",
			Version:   "3.2.1",
			Ecosystem: lockfile.RedHatEcosystem,
			CompareAs: lockfile.RedHatEcosystem,
		},
	})
}

func TestParseRpmDB_SQLite_Single(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseRpmDB("fixtures/rpm/rpmdb.sqlite")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "htop",
			Version:   "3.2.1",
			Ecosystem: lockfile.RedHatEcosystem,
			CompareAs: lockfile.RedHatEcosystem,
		},
	})
}
