package lockfile_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/osv-scanner/pkg/lockfile"
)

func createTestDirWithNodeModulesDir(t *testing.T) (string, func()) {
	t.Helper()

	testDir, cleanupTestDir := createTestDir(t)

	if err := os.Mkdir(filepath.Join(testDir, "node_modules"), 0750); err != nil {
		cleanupTestDir()
		t.Fatalf("could not create node_modules directory: %v", err)
	}

	return testDir, cleanupTestDir
}

func testParsingNodeModules(t *testing.T, fixture string) ([]lockfile.PackageDetails, error) {
	t.Helper()

	testDir, cleanupTestDir := createTestDirWithNodeModulesDir(t)
	defer cleanupTestDir()

	file := copyFile(t, fixture, filepath.Join(testDir, "node_modules", ".package-lock.json"))

	f, err := lockfile.OpenLocalDepFile(file)

	if err != nil {
		t.Fatalf("could not open file %v", err)
	}

	defer f.Close()

	return lockfile.NodeModulesExtractor{}.Extract(f)
}

func TestNodeModulesExtractor_ShouldExtract(t *testing.T) {
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
			want: false,
		},
		{
			name: "",
			path: "path/to/my/package-lock.json",
			want: false,
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
			path: ".package-lock.json",
			want: false,
		},
		{
			name: "",
			path: "node_modules/.package-lock.json",
			want: true,
		},
		{
			name: "",
			path: "path/to/my/node_modules/.package-lock.json",
			want: true,
		},
		{
			name: "",
			path: "path/to/my/node_modules/.package-lock.json/file",
			want: false,
		},
		{
			name: "",
			path: "path/to/my/node_modules/.package-lock.json.file",
			want: false,
		},
		{
			name: "",
			path: "path.to.my.node_modules.package-lock.json",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := lockfile.NodeModulesExtractor{}
			got := e.ShouldExtract(tt.path)
			if got != tt.want {
				t.Errorf("Extract() got = %v, want %v", got, tt.want)
			}
		})
	}
}
