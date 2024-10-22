package lockfile_test

import (
	"io/fs"
	"testing"

	"github.com/google/osv-scanner/pkg/lockfile"
)

func TestParseDpkgStatus_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseDpkgStatus("fixtures/dpkg/does-not-exist")

	expectErrIs(t, err, fs.ErrNotExist)
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseDpkgStatus_Empty(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseDpkgStatus("fixtures/dpkg/empty_status")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseDpkgStatus_NotAStatus(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseDpkgStatus("fixtures/dpkg/not_status")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseDpkgStatus_Malformed(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseDpkgStatus("fixtures/dpkg/malformed_status")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "bash",
			Version:   "",
			Ecosystem: lockfile.DebianEcosystem,
			CompareAs: lockfile.DebianEcosystem,
		},
		{
			Name:      "util-linux",
			Version:   "2.36.1-8+deb11u1",
			Ecosystem: lockfile.DebianEcosystem,
			CompareAs: lockfile.DebianEcosystem,
		},
	})
}

func TestParseDpkgStatus_Single(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseDpkgStatus("fixtures/dpkg/single_status")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "sudo",
			Version:   "1.8.27-1+deb10u1",
			Ecosystem: lockfile.DebianEcosystem,
			CompareAs: lockfile.DebianEcosystem,
		},
	})
}

func TestParseDpkgStatus_Shuffled(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseDpkgStatus("fixtures/dpkg/shuffled_status")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "glibc",
			Version:   "2.31-13+deb11u5",
			Ecosystem: lockfile.DebianEcosystem,
			CompareAs: lockfile.DebianEcosystem,
		},
	})
}

func TestParseDpkgStatus_Multiple(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseDpkgStatus("fixtures/dpkg/multiple_status")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "bash",
			Version:   "5.1-2+deb11u1",
			Ecosystem: lockfile.DebianEcosystem + ":12",
			CompareAs: lockfile.DebianEcosystem,
		},
		{
			Name:      "util-linux",
			Version:   "2.36.1-8+deb11u1",
			Ecosystem: lockfile.DebianEcosystem + ":12",
			CompareAs: lockfile.DebianEcosystem,
		},
		{
			Name:      "glibc",
			Version:   "2.31-13+deb11u5",
			Ecosystem: lockfile.DebianEcosystem + ":12",
			CompareAs: lockfile.DebianEcosystem,
		},
		{
			Name:      "base-files",
			Version:   "12.4+deb12u5",
			Ecosystem: lockfile.DebianEcosystem + ":12",
			CompareAs: lockfile.DebianEcosystem,
		},
	})
}

func TestParseDpkgStatus_Source_Ver_Override(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseDpkgStatus("fixtures/dpkg/source_ver_override_status")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "lvm2",
			Version:   "2.02.176-4.1ubuntu3",
			Ecosystem: lockfile.DebianEcosystem,
			CompareAs: lockfile.DebianEcosystem,
		},
	})
}
