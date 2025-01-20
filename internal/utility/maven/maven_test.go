package maven_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/osv-scanner/internal/utility/maven"
)

func TestParentPOMPath(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get current directory: %v", err)
	}
	tests := []struct {
		currentPath, relativePath string
		want                      string
	}{
		// fixtures
		// |- maven
		// |  |- my-app
		// |  |  |- pom.xml
		// |  |- parent
		// |  |  |- pom.xml
		// |- pom.xml
		{
			// Parent path is specified correctly.
			currentPath:  filepath.Join(dir, "fixtures", "my-app", "pom.xml"),
			relativePath: "../parent/pom.xml",
			want:         filepath.Join(dir, "fixtures", "parent", "pom.xml"),
		},
		{
			// Wrong file name is specified in relative path.
			currentPath:  filepath.Join(dir, "fixtures", "my-app", "pom.xml"),
			relativePath: "../parent/abc.xml",
			want:         "",
		},
		{
			// Wrong directory is specified in relative path.
			currentPath:  filepath.Join(dir, "fixtures", "my-app", "pom.xml"),
			relativePath: "../not-found/pom.xml",
			want:         "",
		},
		{
			// Only directory is specified.
			currentPath:  filepath.Join(dir, "fixtures", "my-app", "pom.xml"),
			relativePath: "../parent",
			want:         filepath.Join(dir, "fixtures", "parent", "pom.xml"),
		},
		{
			// Parent relative path is default to '../pom.xml'.
			currentPath:  filepath.Join(dir, "fixtures", "my-app", "pom.xml"),
			relativePath: "",
			want:         filepath.Join(dir, "fixtures", "pom.xml"),
		},
		{
			// No pom.xml is found even in the default path.
			currentPath:  filepath.Join(dir, "fixtures", "pom.xml"),
			relativePath: "",
			want:         "",
		},
	}
	for _, tt := range tests {
		got := maven.ParentPOMPath(tt.currentPath, tt.relativePath)
		if got != tt.want {
			t.Errorf("parentPOMPath(%s, %s): got %s, want %s", tt.currentPath, tt.relativePath, got, tt.want)
		}
	}
}
