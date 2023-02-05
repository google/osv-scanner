package lockfile_test

import (
	"github.com/google/osv-scanner/pkg/lockfile"
	"testing"
)

func TestParseNuGetLock_InvalidVersion(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseNuGetLock("fixtures/nuget/empty.v0.json")

	expectErrContaining(t, err, "unsupported lock file version")
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseNuGetLockFile_InvalidVersion(t *testing.T) {
	t.Parallel()

	packages, diag, err := lockfile.ParseNuGetLockFile("fixtures/nuget/empty.v0.json")

	expectErrContaining(t, err, "unsupported lock file version")
	expectPackages(t, packages, []lockfile.PackageDetails{})
	expectDiagnostics(t, diag, lockfile.Diagnostics{})
}
