package lockfile_test

import (
	"testing"

	"github.com/google/osv-scanner/pkg/lockfile"
)

func TestNuGetLockExtractor_ShouldExtract(t *testing.T) {
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
			path: "packages.lock.json",
			want: true,
		},
		{
			name: "",
			path: "path/to/my/packages.lock.json",
			want: true,
		},
		{
			name: "",
			path: "path/to/my/packages.lock.json/file",
			want: false,
		},
		{
			name: "",
			path: "path/to/my/packages.lock.json.file",
			want: false,
		},
		{
			name: "",
			path: "path.to.my.packages.lock.json",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := lockfile.NuGetLockExtractor{}
			got := e.ShouldExtract(tt.path)
			if got != tt.want {
				t.Errorf("Extract() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseNuGetLock_InvalidVersion(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseNuGetLock("fixtures/nuget/empty.v0.json")

	expectErrContaining(t, err, "unsupported lock file version 0")
	expectPackages(t, packages, []lockfile.PackageDetails{})
}
