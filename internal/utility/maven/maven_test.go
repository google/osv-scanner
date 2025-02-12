package maven_test

import (
	"path/filepath"
	"testing"

	"github.com/google/osv-scanner/v2/internal/utility/maven"
)

func TestParentPOMPath(t *testing.T) {
	t.Parallel()
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
			currentPath:  filepath.Join("fixtures", "my-app", "pom.xml"),
			relativePath: "../parent/pom.xml",
			want:         filepath.Join("fixtures", "parent", "pom.xml"),
		},
		{
			// Wrong file name is specified in relative path.
			currentPath:  filepath.Join("fixtures", "my-app", "pom.xml"),
			relativePath: "../parent/abc.xml",
			want:         "",
		},
		{
			// Wrong directory is specified in relative path.
			currentPath:  filepath.Join("fixtures", "my-app", "pom.xml"),
			relativePath: "../not-found/pom.xml",
			want:         "",
		},
		{
			// Only directory is specified.
			currentPath:  filepath.Join("fixtures", "my-app", "pom.xml"),
			relativePath: "../parent",
			want:         filepath.Join("fixtures", "parent", "pom.xml"),
		},
		{
			// Parent relative path is default to '../pom.xml'.
			currentPath:  filepath.Join("fixtures", "my-app", "pom.xml"),
			relativePath: "",
			want:         filepath.Join("fixtures", "pom.xml"),
		},
		{
			// No pom.xml is found even in the default path.
			currentPath:  filepath.Join("fixtures", "pom.xml"),
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
