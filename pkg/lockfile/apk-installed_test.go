package lockfile_test

import (
	"io/fs"
	"testing"

	"github.com/google/osv-scanner/pkg/lockfile"
)

const alpineEcosystem = lockfile.AlpineEcosystem + ":" + lockfile.AlpineFallbackVersion

func TestParseApkInstalled_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseApkInstalled("fixtures/apk/does-not-exist")

	expectErrIs(t, err, fs.ErrNotExist)
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseApkInstalled_Empty(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseApkInstalled("fixtures/apk/empty_installed")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseApkInstalled_NotAnInstalled(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseApkInstalled("fixtures/apk/not_installed")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseApkInstalled_Malformed(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseApkInstalled("fixtures/apk/malformed_installed")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "busybox",
			Version:   "",
			Commit:    "1dbf7a793afae640ea643a055b6dd4f430ac116b",
			Ecosystem: alpineEcosystem,
			CompareAs: lockfile.AlpineEcosystem,
		},
	})
}

func TestParseApkInstalled_Single(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseApkInstalled("fixtures/apk/single_installed")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "apk-tools",
			Version:   "2.12.10-r1",
			Commit:    "0188f510baadbae393472103427b9c1875117136",
			Ecosystem: alpineEcosystem,
			CompareAs: lockfile.AlpineEcosystem,
		},
	})
}

func TestParseApkInstalled_Shuffled(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseApkInstalled("fixtures/apk/shuffled_installed")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "apk-tools",
			Version:   "2.12.10-r1",
			Commit:    "0188f510baadbae393472103427b9c1875117136",
			Ecosystem: alpineEcosystem,
			CompareAs: lockfile.AlpineEcosystem,
		},
	})
}

func TestParseApkInstalled_Multiple(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseApkInstalled("fixtures/apk/multiple_installed")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "alpine-baselayout-data",
			Version:   "3.4.0-r0",
			Commit:    "bd965a7ebf7fd8f07d7a0cc0d7375bf3e4eb9b24",
			Ecosystem: alpineEcosystem,
			CompareAs: lockfile.AlpineEcosystem,
		},
		{
			Name:      "musl",
			Version:   "1.2.3-r4",
			Commit:    "f93af038c3de7146121c2ea8124ba5ce29b4b058",
			Ecosystem: alpineEcosystem,
			CompareAs: lockfile.AlpineEcosystem,
		},
		{
			Name:      "busybox",
			Version:   "1.35.0-r29",
			Commit:    "1dbf7a793afae640ea643a055b6dd4f430ac116b",
			Ecosystem: alpineEcosystem,
			CompareAs: lockfile.AlpineEcosystem,
		},
	})
}
