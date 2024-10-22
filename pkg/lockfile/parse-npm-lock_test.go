package lockfile_test

import (
	"testing"

	"github.com/google/osv-scanner/pkg/lockfile"
)

func TestNpmLockExtractor_ShouldExtract(t *testing.T) {
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
			path: "package-lock.json",
			want: true,
		},
		{
			name: "",
			path: "path/to/my/package-lock.json",
			want: true,
		},
		{
			name: "",
			path: "path/to/my/package-lock.json/file",
			want: false,
		},
		{
			name: "",
			path: "path/to/my/package-lock.json.file",
			want: false,
		},
		{
			name: "",
			path: "path.to.my.package-lock.json",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := lockfile.NpmLockExtractor{}
			got := e.ShouldExtract(tt.path)
			if got != tt.want {
				t.Errorf("Extract() got = %v, want %v", got, tt.want)
			}
		})
	}
}
