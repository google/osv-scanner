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
			t.Errorf("ParentPOMPath(%s, %s): got %s, want %s", tt.currentPath, tt.relativePath, got, tt.want)
		}
	}
}

/*
func TestCompareVersions(t *testing.T) {
	t.Parallel()

	versionKey := func(name string, version string) resolve.Version {
		return resolve.Version{
			VersionKey: resolve.VersionKey{
				PackageKey: resolve.PackageKey{
					System: resolve.Maven,
					Name:   name,
				},
				Version: version,
			},
		}
	}

	tests := []struct {
		a, b resolve.Version
		want int
	}{
		{
			versionKey("abc:xyz", "1.2.3"),
			versionKey("abc:xyz", "2.3.4"),
			-1,
		},
		{
			versionKey("com.google.guava:guava", "1.2.3"),
			versionKey("com.google.guava:guava", "2.3.4"),
			-1,
		},
		{
			versionKey("com.google.guava:guava", "1.2.3-jre"),
			versionKey("com.google.guava:guava", "2.3.4-jre"),
			-1,
		},
		{
			versionKey("com.google.guava:guava", "1.2.3-android"),
			versionKey("com.google.guava:guava", "2.3.4-android"),
			-1,
		},
		{
			// android flavours are always ordered earlier
			versionKey("com.google.guava:guava", "1.2.3"),
			versionKey("com.google.guava:guava", "2.3.4-android"),
			1,
		},
		{
			// jre flavours are always ordered later
			versionKey("com.google.guava:guava", "1.2.3-jre"),
			versionKey("com.google.guava:guava", "2.3.4"),
			1,
		},
		{
			versionKey("com.google.guava:guava", "1.2.3-jre"),
			versionKey("com.google.guava:guava", "2.3.4-android"),
			1,
		},
		{
			versionKey("abc:xyz", "1.2.3"),
			versionKey("abc:xyz", "2.3.4"),
			-1,
		},
	}
	for _, tt := range tests {
		got := maven.CompareVersions(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("CompareVersions(%v, %v): got %b, want %b", tt.a, tt.b, got, tt.want)
		}
	}
}
*/
