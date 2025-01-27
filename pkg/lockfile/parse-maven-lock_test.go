package lockfile_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/google/osv-scanner/pkg/models"

	"github.com/google/osv-scanner/pkg/lockfile"
)

func TestMavenLockExtractor_ShouldExtract(t *testing.T) {
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
			path: "pom.xml",
			want: true,
		},
		{
			name: "",
			path: "path/to/my/pom.xml",
			want: true,
		},
		{
			name: "",
			path: "path/to/my/pom.xml/file",
			want: false,
		},
		{
			name: "",
			path: "path/to/my/pom.xml.file",
			want: false,
		},
		{
			name: "",
			path: "path.to.my.pom.xml",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := lockfile.MavenLockExtractor{}
			got := e.ShouldExtract(tt.path)
			if got != tt.want {
				t.Errorf("Extract() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseMavenLock_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseMavenLock(filepath.FromSlash("fixtures/maven/does-not-exist"))

	expectErrIs(t, err, fs.ErrNotExist)
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseMavenLock_Invalid(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseMavenLock(filepath.FromSlash("fixtures/maven/not-pom.txt"))

	expectErrContaining(t, err, "could not extract from")
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseMavenLock_InvalidSyntax(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseMavenLock(filepath.FromSlash("fixtures/maven/invalid-syntax.xml"))

	expectErrContaining(t, err, "XML syntax error")
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseMavenLock_NoPackages(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseMavenLock(filepath.FromSlash("fixtures/maven/empty.xml"))
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseMavenLock_ShouldRemoveComments(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/maven/with-comment.xml"))
	packages, err := lockfile.ParseMavenLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "org.apache.maven:maven-artifact",
			Version:        "1.0.0",
			PackageManager: models.Maven,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 3, End: 15},
				Column:   models.Position{Start: 5, End: 18},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 8, End: 9},
				Column:   models.Position{Start: 10, End: 22},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 13, End: 13},
				Column:   models.Position{Start: 45, End: 50},
				Filename: path,
			},
			IsDirect: true,
		},
	})
}

func TestParseMavenLock_ShouldTrim(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/maven/with-spaces-and-tabs.xml"))
	packages, err := lockfile.ParseMavenLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "org.apache.maven:maven-artifact",
			Version:        "1.0.0",
			PackageManager: models.Maven,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 9, End: 18},
				Column:   models.Position{Start: 5, End: 18},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 14, End: 14},
				Column:   models.Position{Start: 10, End: 24},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 16, End: 16},
				Column:   models.Position{Start: 19, End: 24},
				Filename: path,
			},
			IsDirect: true,
		},
		{
			Name:           "org.apache.maven:maven-artifact2",
			Version:        "3.0",
			PackageManager: models.Maven,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 19, End: 28},
				Column:   models.Position{Start: 5, End: 18},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 24, End: 24},
				Column:   models.Position{Start: 9, End: 24},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 4, End: 4},
				Column:   models.Position{Start: 9, End: 12},
				Filename: path,
			},
			IsDirect: true,
		},
		{
			Name:           "org.apache.maven:maven-artifact3",
			Version:        "1.0.0",
			PackageManager: models.Maven,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 29, End: 36},
				Column:   models.Position{Start: 5, End: 18},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 34, End: 34},
				Column:   models.Position{Start: 1, End: 16},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 49, End: 49},
				Column:   models.Position{Start: 20, End: 25},
				Filename: path,
			},
			IsDirect: true,
		},
	})
}

func TestParseMavenLock_OnePackage(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/maven/one-package.xml"))
	packages, err := lockfile.ParseMavenLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "org.apache.maven:maven-artifact",
			Version:        "1.0.0",
			PackageManager: models.Maven,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 7, End: 11},
				Column:   models.Position{Start: 5, End: 18},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 9, End: 9},
				Column:   models.Position{Start: 19, End: 33},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 10, End: 10},
				Column:   models.Position{Start: 16, End: 21},
				Filename: path,
			},
			IsDirect: true,
		},
	})
}

func TestParseMavenLock_OnePackageWithMultipleVersionVariable(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/maven/multiple-version-variables.xml"))
	packages, err := lockfile.ParseMavenLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "org.apache.maven:maven-artifact",
			Version:        "1.0.0-SNAPSHOT",
			PackageManager: models.Maven,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 9, End: 13},
				Column:   models.Position{Start: 5, End: 18},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 11, End: 11},
				Column:   models.Position{Start: 19, End: 33},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 12, End: 12},
				Column:   models.Position{Start: 16, End: 40},
				Filename: path,
			},
			IsDirect: true,
		},
	})
}

func TestParseMavenLock_TwoPackageWithMixedVersionDefinition(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/maven/two-packages-mixed-version.xml"))
	packages, err := lockfile.ParseMavenLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "io.netty:netty-all",
			Version:        "4.1.42.3.0",
			PackageManager: models.Maven,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 7, End: 11},
				Column:   models.Position{Start: 5, End: 18},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 9, End: 9},
				Column:   models.Position{Start: 19, End: 28},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 10, End: 10},
				Column:   models.Position{Start: 16, End: 38},
				Filename: path,
			},
			IsDirect: true,
		},
		{
			Name:           "org.slf4j:slf4j-log4j12-3.0",
			Version:        "1.7.25",
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
			PackageManager: models.Maven,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 12, End: 16},
				Column:   models.Position{Start: 5, End: 18},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 14, End: 14},
				Column:   models.Position{Start: 19, End: 48},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 15, End: 15},
				Column:   models.Position{Start: 16, End: 22},
				Filename: path,
			},
			IsDirect: true,
		},
	})
}

func TestParseMavenLock_TwoPackages(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/maven/two-packages.xml"))
	packages, err := lockfile.ParseMavenLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "io.netty:netty-all",
			Version:        "4.1.42.Final",
			PackageManager: models.Maven,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 7, End: 11},
				Column:   models.Position{Start: 5, End: 18},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 9, End: 9},
				Column:   models.Position{Start: 19, End: 28},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 10, End: 10},
				Column:   models.Position{Start: 16, End: 28},
				Filename: path,
			},
			IsDirect: true,
		},
		{
			Name:           "org.slf4j:slf4j-log4j12",
			Version:        "1.7.25",
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
			PackageManager: models.Maven,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 12, End: 16},
				Column:   models.Position{Start: 5, End: 18},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 14, End: 14},
				Column:   models.Position{Start: 19, End: 32},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 15, End: 15},
				Column:   models.Position{Start: 16, End: 22},
				Filename: path,
			},
			IsDirect: true,
		},
	})
}

func TestParseMavenLock_WithDependencyManagement(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/maven/with-dependency-management.xml"))
	packages, err := lockfile.ParseMavenLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "io.netty:netty-all",
			Version:        "4.1.42.Final",
			PackageManager: models.Maven,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 7, End: 10},
				Column:   models.Position{Start: 5, End: 18},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 9, End: 9},
				Column:   models.Position{Start: 19, End: 28},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 23, End: 23},
				Column:   models.Position{Start: 18, End: 30},
				Filename: path,
			},
			IsDirect: true,
		},
		{
			Name:           "org.slf4j:slf4j-log4j12",
			Version:        "1.7.25",
			PackageManager: models.Maven,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 11, End: 15},
				Column:   models.Position{Start: 5, End: 18},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 13, End: 13},
				Column:   models.Position{Start: 19, End: 32},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 14, End: 14},
				Column:   models.Position{Start: 16, End: 22},
				Filename: path,
			},
			IsDirect: true,
		},
	})
}

func TestParseMavenLock_Interpolation(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/maven/interpolation.xml"))
	packages, err := lockfile.ParseMavenLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "org.mine:mypackage",
			Version:        "1.0.0",
			PackageManager: models.Maven,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 18, End: 22},
				Column:   models.Position{Start: 5, End: 18},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 20, End: 20},
				Column:   models.Position{Start: 19, End: 28},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 12, End: 12},
				Column:   models.Position{Start: 23, End: 28},
				Filename: path,
			},
			IsDirect: true,
		},
		{
			Name:           "org.mine:my.package",
			Version:        "2.3.4",
			PackageManager: models.Maven,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 24, End: 28},
				Column:   models.Position{Start: 5, End: 18},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 26, End: 26},
				Column:   models.Position{Start: 19, End: 29},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 13, End: 13},
				Column:   models.Position{Start: 25, End: 30},
				Filename: path,
			},
			IsDirect: true,
		},
		{
			Name:           "org.mine:ranged-package",
			Version:        "9.4.35.v20201120",
			PackageManager: models.Maven,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 30, End: 33},
				Column:   models.Position{Start: 5, End: 18},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 32, End: 32},
				Column:   models.Position{Start: 19, End: 33},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 14, End: 14},
				Column:   models.Position{Start: 20, End: 42},
				Filename: path,
			},
			IsDirect: true,
		},
	})
}

func TestMavenLock_WithParent(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	parentPath := filepath.FromSlash(filepath.Join(dir, "fixtures/maven/parent.xml"))
	childPath := filepath.FromSlash(filepath.Join(dir, "fixtures/maven/children/with-parent.xml"))
	packages, err := lockfile.ParseMavenLock(childPath)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "com.google.code.findbugs:jsr305",
			Version:        "3.0.2",
			PackageManager: models.Maven,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 26, End: 29},
				Column:   models.Position{Start: 5, End: 18},
				Filename: parentPath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 28, End: 28},
				Column:   models.Position{Start: 19, End: 25},
				Filename: parentPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 20, End: 20},
				Column:   models.Position{Start: 18, End: 23},
				Filename: parentPath,
			},
			IsDirect: true,
		},
		{
			Name:           "io.netty:netty-all",
			Version:        "4.1.42.Final",
			PackageManager: models.Maven,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 14, End: 17},
				Column:   models.Position{Start: 5, End: 18},
				Filename: childPath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 16, End: 16},
				Column:   models.Position{Start: 19, End: 28},
				Filename: childPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 15, End: 15},
				Column:   models.Position{Start: 18, End: 30},
				Filename: parentPath,
			},
			IsDirect: true,
		},
		{
			Name:           "org.slf4j:slf4j-log4j12",
			Version:        "1.7.25",
			PackageManager: models.Maven,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 18, End: 22},
				Column:   models.Position{Start: 5, End: 18},
				Filename: childPath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 20, End: 20},
				Column:   models.Position{Start: 19, End: 32},
				Filename: childPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 21, End: 21},
				Column:   models.Position{Start: 16, End: 22},
				Filename: childPath,
			},
			IsDirect: true,
		},
		{
			Name:           "org.mine:mypackage",
			Version:        "1.0.0",
			PackageManager: models.Maven,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 23, End: 27},
				Column:   models.Position{Start: 5, End: 18},
				Filename: childPath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 25, End: 25},
				Column:   models.Position{Start: 19, End: 28},
				Filename: childPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 4, End: 4},
				Column:   models.Position{Start: 23, End: 28},
				Filename: parentPath,
			},
			IsDirect: true,
		},
		{
			Name:           "org.mine:my.package",
			Version:        "2.3.4",
			PackageManager: models.Maven,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 28, End: 32},
				Column:   models.Position{Start: 5, End: 18},
				Filename: childPath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 30, End: 30},
				Column:   models.Position{Start: 19, End: 29},
				Filename: childPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 25, End: 30},
				Filename: parentPath,
			},
			IsDirect: true,
		},
		{
			Name:           "dev.foo:bar",
			Version:        "1.0-SNAPSHOT",
			PackageManager: models.Maven,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 33, End: 37},
				Column:   models.Position{Start: 5, End: 18},
				Filename: childPath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 35, End: 35},
				Column:   models.Position{Start: 19, End: 22},
				Filename: childPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 8, End: 8},
				Column:   models.Position{Start: 12, End: 24},
				Filename: parentPath,
			},
			IsDirect: true,
		},
	})
}

func TestMavenLock_WithParentDirOnly(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	parentPath := filepath.Join(dir, filepath.FromSlash("fixtures/maven/pom.xml"))
	childPath := filepath.Join(dir, filepath.FromSlash("fixtures/maven/children/with-parent-dir-only.xml"))
	packages, err := lockfile.ParseMavenLock(childPath)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "com.google.code.findbugs:jsr305",
			Version:        "3.0.2",
			PackageManager: models.Maven,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 25, End: 28},
				Column:   models.Position{Start: 5, End: 18},
				Filename: parentPath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 27, End: 27},
				Column:   models.Position{Start: 19, End: 25},
				Filename: parentPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 19, End: 19},
				Column:   models.Position{Start: 18, End: 23},
				Filename: parentPath,
			},
			IsDirect: true,
		},
		{
			Name:           "io.netty:netty-all",
			Version:        "4.1.42.Final",
			PackageManager: models.Maven,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 14, End: 17},
				Column:   models.Position{Start: 5, End: 18},
				Filename: childPath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 16, End: 16},
				Column:   models.Position{Start: 19, End: 28},
				Filename: childPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 14, End: 14},
				Column:   models.Position{Start: 18, End: 30},
				Filename: parentPath,
			},
			IsDirect: true,
		},
		{
			Name:           "org.slf4j:slf4j-log4j12",
			Version:        "1.7.25",
			PackageManager: models.Maven,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 18, End: 22},
				Column:   models.Position{Start: 5, End: 18},
				Filename: childPath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 20, End: 20},
				Column:   models.Position{Start: 19, End: 32},
				Filename: childPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 21, End: 21},
				Column:   models.Position{Start: 16, End: 22},
				Filename: childPath,
			},
			IsDirect: true,
		},
		{
			Name:           "org.mine:mypackage",
			Version:        "1.0.0",
			PackageManager: models.Maven,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 23, End: 27},
				Column:   models.Position{Start: 5, End: 18},
				Filename: childPath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 25, End: 25},
				Column:   models.Position{Start: 19, End: 28},
				Filename: childPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 4, End: 4},
				Column:   models.Position{Start: 23, End: 28},
				Filename: parentPath,
			},
			IsDirect: true,
		},
		{
			Name:           "org.mine:my.package",
			Version:        "2.3.4",
			PackageManager: models.Maven,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 28, End: 32},
				Column:   models.Position{Start: 5, End: 18},
				Filename: childPath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 30, End: 30},
				Column:   models.Position{Start: 19, End: 29},
				Filename: childPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 25, End: 30},
				Filename: parentPath,
			},
			IsDirect: true,
		},
	})
}

func TestMavenLock_WithParentWithoutRelativePath(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	parentPath := filepath.Join(dir, filepath.FromSlash("fixtures/maven/pom.xml"))
	childPath := filepath.Join(dir, filepath.FromSlash("fixtures/maven/children/with-parent-without-relative-path.xml"))
	packages, err := lockfile.ParseMavenLock(childPath)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "com.google.code.findbugs:jsr305",
			Version:        "3.0.2",
			PackageManager: models.Maven,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 25, End: 28},
				Column:   models.Position{Start: 5, End: 18},
				Filename: parentPath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 27, End: 27},
				Column:   models.Position{Start: 19, End: 25},
				Filename: parentPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 19, End: 19},
				Column:   models.Position{Start: 18, End: 23},
				Filename: parentPath,
			},
			IsDirect: true,
		},
		{
			Name:           "io.netty:netty-all",
			Version:        "4.1.42.Final",
			PackageManager: models.Maven,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 13, End: 16},
				Column:   models.Position{Start: 5, End: 18},
				Filename: childPath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 15, End: 15},
				Column:   models.Position{Start: 19, End: 28},
				Filename: childPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 14, End: 14},
				Column:   models.Position{Start: 18, End: 30},
				Filename: parentPath,
			},
			IsDirect: true,
		},
		{
			Name:           "org.slf4j:slf4j-log4j12",
			Version:        "1.7.25",
			PackageManager: models.Maven,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 17, End: 21},
				Column:   models.Position{Start: 5, End: 18},
				Filename: childPath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 19, End: 19},
				Column:   models.Position{Start: 19, End: 32},
				Filename: childPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 20, End: 20},
				Column:   models.Position{Start: 16, End: 22},
				Filename: childPath,
			},
			IsDirect: true,
		},
		{
			Name:           "org.mine:mypackage",
			Version:        "1.0.0",
			PackageManager: models.Maven,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 22, End: 26},
				Column:   models.Position{Start: 5, End: 18},
				Filename: childPath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 24, End: 24},
				Column:   models.Position{Start: 19, End: 28},
				Filename: childPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 4, End: 4},
				Column:   models.Position{Start: 23, End: 28},
				Filename: parentPath,
			},
			IsDirect: true,
		},
		{
			Name:           "org.mine:my.package",
			Version:        "2.3.4",
			PackageManager: models.Maven,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 27, End: 31},
				Column:   models.Position{Start: 5, End: 18},
				Filename: childPath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 29, End: 29},
				Column:   models.Position{Start: 19, End: 29},
				Filename: childPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 25, End: 30},
				Filename: parentPath,
			},
			IsDirect: true,
		},
	})
}

func TestMavenLock_WithParent_Child_Project(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	parentPath := filepath.FromSlash(filepath.Join(dir, "fixtures/maven/parent-project-version.xml"))
	childPath := filepath.FromSlash(filepath.Join(dir, "fixtures/maven/children/with-parent-child-project-version.xml"))
	packages, err := lockfile.ParseMavenLock(childPath)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "com.google.code.findbugs:jsr305",
			Version:        "1.0-CHILD-SNAPSHOT",
			PackageManager: models.Maven,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 11, End: 15},
				Column:   models.Position{Start: 5, End: 18},
				Filename: parentPath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 13, End: 13},
				Column:   models.Position{Start: 19, End: 25},
				Filename: parentPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 6, End: 6},
				Column:   models.Position{Start: 12, End: 30},
				Filename: childPath,
			},
			IsDirect: true,
		},
	})
}

func TestMavenLock_WithMultipleParents(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	rootPath := filepath.Join(dir, filepath.FromSlash("fixtures/maven/parent.xml"))
	parentPath := filepath.Join(dir, filepath.FromSlash("fixtures/maven/children/with-parent.xml"))
	childPath := filepath.Join(dir, filepath.FromSlash("fixtures/maven/children/with-multiple-parent.xml"))
	packages, err := lockfile.ParseMavenLock(childPath)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "com.google.code.findbugs:jsr305",
			Version:        "3.0.2",
			PackageManager: models.Maven,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 26, End: 29},
				Column:   models.Position{Start: 5, End: 18},
				Filename: rootPath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 28, End: 28},
				Column:   models.Position{Start: 19, End: 25},
				Filename: rootPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 20, End: 20},
				Column:   models.Position{Start: 18, End: 23},
				Filename: rootPath,
			},
			IsDirect: true,
		},
		{
			Name:           "io.netty:netty-all",
			Version:        "4.1.42.Final",
			PackageManager: models.Maven,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 14, End: 17},
				Column:   models.Position{Start: 5, End: 18},
				Filename: parentPath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 16, End: 16},
				Column:   models.Position{Start: 19, End: 28},
				Filename: parentPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 15, End: 15},
				Column:   models.Position{Start: 18, End: 30},
				Filename: rootPath,
			},
			IsDirect: true,
		},
		{
			Name:           "org.slf4j:slf4j-log4j12",
			Version:        "1.7.25",
			PackageManager: models.Maven,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 18, End: 22},
				Column:   models.Position{Start: 5, End: 18},
				Filename: parentPath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 20, End: 20},
				Column:   models.Position{Start: 19, End: 32},
				Filename: parentPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 21, End: 21},
				Column:   models.Position{Start: 16, End: 22},
				Filename: parentPath,
			},
			IsDirect: true,
		},
		{
			Name:           "org.mine:mypackage",
			Version:        "1.0.0",
			PackageManager: models.Maven,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 23, End: 27},
				Column:   models.Position{Start: 5, End: 18},
				Filename: parentPath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 25, End: 25},
				Column:   models.Position{Start: 19, End: 28},
				Filename: parentPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 4, End: 4},
				Column:   models.Position{Start: 23, End: 28},
				Filename: rootPath,
			},
			IsDirect: true,
		},
		{
			Name:           "org.mine:my.package",
			Version:        "9.4.35.v20201120",
			PackageManager: models.Maven,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 14, End: 18},
				Column:   models.Position{Start: 5, End: 18},
				Filename: childPath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 16, End: 16},
				Column:   models.Position{Start: 19, End: 29},
				Filename: childPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 6, End: 6},
				Column:   models.Position{Start: 20, End: 42},
				Filename: rootPath,
			},
			IsDirect: true,
		},
		{
			Name:           "dev.foo:bar",
			Version:        "1.0-SNAPSHOT",
			PackageManager: models.Maven,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 33, End: 37},
				Column:   models.Position{Start: 5, End: 18},
				Filename: parentPath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 35, End: 35},
				Column:   models.Position{Start: 19, End: 22},
				Filename: parentPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 8, End: 8},
				Column:   models.Position{Start: 12, End: 24},
				Filename: rootPath,
			},
			IsDirect: true,
		},
	})
}

func TestMavenLockDependency_ResolveVersion(t *testing.T) {
	t.Parallel()

	type fields struct {
		Version models.StringHolder
	}
	type args struct {
		lockfile lockfile.MavenLockFile
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   string
	}{
		// 1.0: Soft requirement for 1.0. Use 1.0 if no other version appears earlier in the dependency tree.
		{
			name: "",
			fields: fields{Version: models.StringHolder{
				Value: "1.0",
			}},
			args: args{lockfile: lockfile.MavenLockFile{}},
			want: "1.0",
		},
		// [1.0]: Hard requirement for 1.0. Use 1.0 and only 1.0.
		{
			name: "",
			fields: fields{Version: models.StringHolder{
				Value: "[1.0]",
			}},
			args: args{lockfile: lockfile.MavenLockFile{}},
			want: "1.0",
		},
		// (,1.0]: Hard requirement for any version <= 1.0.
		{
			name: "",
			fields: fields{Version: models.StringHolder{
				Value: "(,1.0]",
			}},
			args: args{lockfile: lockfile.MavenLockFile{}},
			want: "",
		},
		// [1.2,1.3]: Hard requirement for any version between 1.2 and 1.3 inclusive.
		{
			name: "",
			fields: fields{Version: models.StringHolder{
				Value: "[1.2,1.3]",
			}},
			args: args{lockfile: lockfile.MavenLockFile{}},
			want: "1.2",
		},
		// [1.0,2.0): 1.0 <= x < 2.0; Hard requirement for any version between 1.0 inclusive and 2.0 exclusive.
		{
			name: "",
			fields: fields{Version: models.StringHolder{
				Value: "[1.0,2.0)",
			}},
			args: args{lockfile: lockfile.MavenLockFile{}},
			want: "1.0",
		},
		// [1.5,): Hard requirement for any version greater than or equal to 1.5.
		{
			name: "",
			fields: fields{Version: models.StringHolder{
				Value: "[1.5,)",
			}},
			args: args{lockfile: lockfile.MavenLockFile{}},
			want: "1.5",
		},
		// (,1.0],[1.2,): Hard requirement for any version less than or equal to 1.0 than or greater than or equal to 1.2, but not 1.1.
		{
			name: "",
			fields: fields{Version: models.StringHolder{
				Value: "(,1.0],[1.2,)",
			}},
			args: args{lockfile: lockfile.MavenLockFile{}},
			want: "",
		},
		// (,1.1),(1.1,): Hard requirement for any version except 1.1; for example because 1.1 has a critical vulnerability.
		{
			name: "",
			fields: fields{Version: models.StringHolder{
				Value: "(,1.1),(1.1,)",
			}},
			args: args{lockfile: lockfile.MavenLockFile{}},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mld := lockfile.MavenLockDependency{
				Version: tt.fields.Version,
			}
			if got, _ := mld.ResolveVersion(tt.args.lockfile); got != tt.want {
				t.Errorf("ResolveVersion() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseMavenLock_WithScope(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.Join(dir, filepath.FromSlash("fixtures/maven/with-scope.xml"))
	packages, err := lockfile.ParseMavenLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "abc:xyz",
			Version:        "1.2.3",
			PackageManager: models.Maven,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 3, End: 8},
				Column:   models.Position{Start: 5, End: 18},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 19, End: 22},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 6, End: 6},
				Column:   models.Position{Start: 16, End: 21},
				Filename: path,
			},
			IsDirect: true,
		},
		{
			Name:           "junit:junit",
			Version:        "4.12",
			PackageManager: models.Maven,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
			Commit:         "",
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 9, End: 14},
				Column:   models.Position{Start: 5, End: 18},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 11, End: 11},
				Column:   models.Position{Start: 19, End: 24},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 12, End: 12},
				Column:   models.Position{Start: 16, End: 20},
				Filename: path,
			},
			DepGroups: []string{"test"},
			IsDirect:  true,
		},
	})
}

func TestParseMavenLock_WithUnusedDependencyManagementDependencies(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.Join(dir, filepath.FromSlash("fixtures/maven/with-unused-dependency-management.xml"))
	packages, err := lockfile.ParseMavenLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "io.netty:netty-all",
			Version:        "4.1.42.Final",
			PackageManager: models.Maven,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
			Commit:         "",
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 17, End: 21},
				Column:   models.Position{Start: 5, End: 18},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 19, End: 19},
				Column:   models.Position{Start: 19, End: 28},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 20, End: 20},
				Column:   models.Position{Start: 16, End: 28},
				Filename: path,
			},
			DepGroups: nil,
			IsDirect:  true,
		},
	})
}

func TestParseMavenLock_WithOverriddenDependencyVersions(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.Join(dir, filepath.FromSlash("fixtures/maven/with-overridden-dependency-version.xml"))
	packages, err := lockfile.ParseMavenLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "junit:junit",
			Version:        "4.12",
			PackageManager: models.Maven,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
			Commit:         "",
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 14, End: 18},
				Column:   models.Position{Start: 5, End: 18},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 16, End: 16},
				Column:   models.Position{Start: 19, End: 24},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 17, End: 17},
				Column:   models.Position{Start: 16, End: 20},
				Filename: path,
			},
			DepGroups: nil,
			IsDirect:  true,
		},
	})
}

func TestParseMavenLock_WithProjectVersionProperty(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.Join(dir, filepath.FromSlash("fixtures/maven/with-project-version-property.xml"))
	packages, err := lockfile.ParseMavenLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "dev.foo:bar",
			Version:        "1.0-SNAPSHOT",
			PackageManager: models.Maven,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
			Commit:         "",
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 8, End: 12},
				Column:   models.Position{Start: 5, End: 18},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 10, End: 10},
				Column:   models.Position{Start: 19, End: 22},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 12, End: 24},
				Filename: path,
			},
			DepGroups: nil,
			IsDirect:  true,
		},
		{
			Name:           "dev.bar:foo",
			Version:        "1.0-SNAPSHOT",
			PackageManager: models.Maven,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
			Commit:         "",
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 13, End: 17},
				Column:   models.Position{Start: 5, End: 18},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 15, End: 15},
				Column:   models.Position{Start: 19, End: 22},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 12, End: 24},
				Filename: path,
			},
			DepGroups: nil,
			IsDirect:  true,
		},
	})
}

func TestParseMavenLock_ResolveProperties(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	require.NoError(t, err)

	path := filepath.Join(dir, filepath.FromSlash("fixtures/maven/resolve-properties.xml"))
	packages, err := lockfile.ParseMavenLock(path)
	require.NoError(t, err)

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "io.netty:netty-all",
			Version:        "4.1.42.Final",
			PackageManager: models.Maven,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
			Commit:         "",
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 27, End: 30},
				Column:   models.Position{Start: 5, End: 18},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 6, End: 6},
				Column:   models.Position{Start: 21, End: 30},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 4, End: 4},
				Column:   models.Position{Start: 20, End: 32},
				Filename: path,
			},
			DepGroups: nil,
			IsDirect:  true,
		},
		{
			Name:           "com.google.code.findbugs:jsr305",
			Version:        "9.4.35.v20201120",
			PackageManager: models.Maven,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
			Commit:         "",
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 31, End: 35},
				Column:   models.Position{Start: 5, End: 18},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 8, End: 8},
				Column:   models.Position{Start: 24, End: 30},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 3, End: 3},
				Column:   models.Position{Start: 20, End: 42},
				Filename: path,
			},
			DepGroups: nil,
			IsDirect:  true,
		},
		{
			Name:           "io.ktor:ktor-server-netty-jvm",
			Version:        "9.4.35.v20201120",
			PackageManager: models.Maven,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
			Commit:         "",
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 36, End: 40},
				Column:   models.Position{Start: 5, End: 18},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 38, End: 38},
				Column:   models.Position{Start: 19, End: 35},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 3, End: 3},
				Column:   models.Position{Start: 20, End: 42},
				Filename: path,
			},
			DepGroups: nil,
			IsDirect:  true,
		},
	})
}

func TestParseMavenLock_NoVersion(t *testing.T) {
	t.Parallel()
	lockfileRelativePath := "fixtures/maven/no-version.xml"
	packages, err := lockfile.ParseMavenLock(lockfileRelativePath)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "org.apache.maven:maven-artifact",
			Version:        "",
			PackageManager: models.Maven,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
			IsDirect:       true,
		},
	})
}

func TestParseMavenLock_SpringRemote(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	require.NoError(t, err)

	path := filepath.Join(dir, filepath.FromSlash("fixtures/maven/spring-remote.xml"))
	packages, err := lockfile.ParseMavenLock(path)
	require.NoError(t, err)

	remotePom := "https://repo.maven.apache.org/maven2/org/springframework/boot/spring-boot-dependencies/3.4.0/spring-boot-dependencies-3.4.0.pom"

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "org.springframework.boot:spring-boot-starter-test",
			Version:        "3.4.0",
			PackageManager: models.Maven,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 38, End: 42},
				Column:   models.Position{Start: 3, End: 16},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 40, End: 40},
				Column:   models.Position{Start: 16, End: 40},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 1811, End: 1811},
				Column:   models.Position{Start: 18, End: 23},
				Filename: remotePom,
			},
			DepGroups: []string{"test"},
			IsDirect:  true,
		},
		{
			Name:           "org.springframework.boot:spring-boot-starter-web",
			Version:        "3.4.0",
			PackageManager: models.Maven,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 33, End: 36},
				Column:   models.Position{Start: 3, End: 16},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 35, End: 35},
				Column:   models.Position{Start: 16, End: 39},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 1836, End: 1836},
				Column:   models.Position{Start: 18, End: 23},
				Filename: remotePom,
			},
			IsDirect: true,
		},
	})
}
