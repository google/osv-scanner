package lockfile_test

import (
	"testing"

	"github.com/google/osv-scanner/pkg/lockfile"
)

// Berkeley DB (rpm < v4.16)
func TestRpmDb_BDB_Single(t *testing.T) {
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

func TestRpmDb_SQLite_Single(t *testing.T) {
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
