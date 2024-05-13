package lockfile_test

import (
	"io/fs"
	"testing"

	"github.com/google/osv-scanner/pkg/models"

	"github.com/google/osv-scanner/pkg/lockfile"
)

func TestGradleLockExtractor_ShouldExtract(t *testing.T) {
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
			path: "buildscript-gradle.lockfile",
			want: true,
		},
		{
			name: "",
			path: "path/to/my/buildscript-gradle.lockfile",
			want: true,
		},
		{
			name: "",
			path: "path/to/my/buildscript-gradle.lockfile/file",
			want: false,
		},
		{
			name: "",
			path: "path/to/my/buildscript-gradle.lockfile.file",
			want: false,
		},
		{
			name: "",
			path: "path.to.my.buildscript-gradle.lockfile",
			want: false,
		},
		{
			name: "",
			path: "gradle.lockfile",
			want: true,
		},
		{
			name: "",
			path: "path/to/my/gradle.lockfile",
			want: true,
		},
		{
			name: "",
			path: "path/to/my/gradle.lockfile/file",
			want: false,
		},
		{
			name: "",
			path: "path/to/my/gradle.lockfile.file",
			want: false,
		},
		{
			name: "",
			path: "path.to.my.gradle.lockfile",
			want: false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := lockfile.GradleLockExtractor{}
			got := e.ShouldExtract(tt.path)
			if got != tt.want {
				t.Errorf("Extract() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseGradleLock_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseGradleLock("fixtures/gradle/does-not-exist")

	expectErrIs(t, err, fs.ErrNotExist)
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseGradleLock_OnlyComments(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseGradleLock("fixtures/gradle/only-comments")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseGradleLock_EmptyStatement(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseGradleLock("fixtures/gradle/only-empty")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseGradleLock_OnePackage(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseGradleLock("fixtures/gradle/one-pkg")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "org.springframework.security:spring-security-crypto",
			Version:   "5.7.3",
			Ecosystem: lockfile.MavenEcosystem,
			CompareAs: lockfile.MavenEcosystem,
			BlockLocation: models.FilePosition{
				Line:   models.Position{Start: 4, End: 4},
				Column: models.Position{Start: 1, End: 119},
			},
		},
	})
}

func TestParseGradleLock_MultiplePackage(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseGradleLock("fixtures/gradle/5-pkg")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "org.springframework.boot:spring-boot-autoconfigure",
			Version:   "2.7.4",
			Ecosystem: lockfile.MavenEcosystem,
			CompareAs: lockfile.MavenEcosystem,
			BlockLocation: models.FilePosition{
				Line:   models.Position{Start: 5, End: 5},
				Column: models.Position{Start: 1, End: 134},
			},
		},
		{
			Name:      "org.springframework.boot:spring-boot-configuration-processor",
			Version:   "2.7.5",
			Ecosystem: lockfile.MavenEcosystem,
			CompareAs: lockfile.MavenEcosystem,
			BlockLocation: models.FilePosition{
				Line:   models.Position{Start: 6, End: 6},
				Column: models.Position{Start: 1, End: 104},
			},
		},
		{
			Name:      "org.springframework.boot:spring-boot-devtools",
			Version:   "2.7.6",
			Ecosystem: lockfile.MavenEcosystem,
			CompareAs: lockfile.MavenEcosystem,
			BlockLocation: models.FilePosition{
				Line:   models.Position{Start: 7, End: 7},
				Column: models.Position{Start: 1, End: 85},
			},
		},

		{
			Name:      "org.springframework.boot:spring-boot-starter-aop",
			Version:   "2.7.7",
			Ecosystem: lockfile.MavenEcosystem,
			CompareAs: lockfile.MavenEcosystem,
			BlockLocation: models.FilePosition{
				Line:   models.Position{Start: 8, End: 8},
				Column: models.Position{Start: 1, End: 116},
			},
		},
		{
			Name:      "org.springframework.boot:spring-boot-starter-data-jpa",
			Version:   "2.7.8",
			Ecosystem: lockfile.MavenEcosystem,
			CompareAs: lockfile.MavenEcosystem,
			BlockLocation: models.FilePosition{
				Line:   models.Position{Start: 9, End: 9},
				Column: models.Position{Start: 1, End: 121},
			},
		},
	})
}

func TestParseGradleLock_WithInvalidLines(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseGradleLock("fixtures/gradle/with-bad-pkg")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "org.springframework.boot:spring-boot-autoconfigure",
			Version:   "2.7.4",
			Ecosystem: lockfile.MavenEcosystem,
			CompareAs: lockfile.MavenEcosystem,
			BlockLocation: models.FilePosition{
				Line:   models.Position{Start: 7, End: 7},
				Column: models.Position{Start: 1, End: 134},
			},
		},
		{
			Name:      "org.springframework.boot:spring-boot-configuration-processor",
			Version:   "2.7.5",
			Ecosystem: lockfile.MavenEcosystem,
			CompareAs: lockfile.MavenEcosystem,
			BlockLocation: models.FilePosition{
				Line:   models.Position{Start: 14, End: 14},
				Column: models.Position{Start: 1, End: 144},
			},
		},
	})
}
