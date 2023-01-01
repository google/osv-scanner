package lockfile_test

import (
	"github.com/google/osv-scanner/pkg/lockfile"
	"testing"
)

func TestParseApkInstalled_Empty(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseApkInstalled("fixtures/apk/installed_empty")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseApkInstalled_Single(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseApkInstalled("fixtures/apk/installed_single")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "apk-tools",
			Version:   "2.12.10-r1",
			Ecosystem: lockfile.AlpineEcosystem,
			CompareAs: lockfile.AlpineEcosystem,
		},
	})
}

func TestParseApkInstalled_Multiple(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseApkInstalled("fixtures/apk/installed_multiple")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "alpine-baselayout-data",
			Version:   "3.4.0-r0",
			Ecosystem: lockfile.AlpineEcosystem,
			CompareAs: lockfile.AlpineEcosystem,
		},
		{
			Name:      "musl",
			Version:   "1.2.3-r4",
			Ecosystem: lockfile.AlpineEcosystem,
			CompareAs: lockfile.AlpineEcosystem,
		},
		{
			Name:      "busybox",
			Version:   "1.35.0-r29",
			Ecosystem: lockfile.AlpineEcosystem,
			CompareAs: lockfile.AlpineEcosystem,
		},
	})
}
