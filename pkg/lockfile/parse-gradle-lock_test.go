package lockfile_test

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/osv-scanner/pkg/models"

	"github.com/stretchr/testify/assert"

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

	packages, err := lockfile.ParseGradleLock("fixtures/gradle-lockfile/does-not-exist")

	expectErrIs(t, err, fs.ErrNotExist)
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseGradleLock_OnlyComments(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseGradleLock("fixtures/gradle-lockfile/only-comments")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseGradleLock_EmptyStatement(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseGradleLock("fixtures/gradle-lockfile/only-empty")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseGradleLock_OnePackage(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/gradle-lockfile/one-pkg"))
	packages, err := lockfile.ParseGradleLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "org.springframework.security:spring-security-crypto",
			Version:        "5.7.3",
			DepGroups:      []string{"compileClasspath", "productionRuntimeClasspath", "runtimeClasspath"},
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
	})
}

//nolint:paralleltest
func TestParseGradleLock_OnePackage_MatcherFailed(t *testing.T) {
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	stderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}
	os.Stderr = w

	// Mock buildGradleMatcher to fail
	matcherError := errors.New("buildGradleMatcher failed")
	lockfile.GradleExtractor.Matcher = FailingMatcher{Error: matcherError}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/gradle-lockfile/one-pkg"))
	packages, err := lockfile.ParseGradleLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	// Capture stderr
	_ = w.Close()
	os.Stderr = stderr
	var buffer bytes.Buffer
	_, err = io.Copy(&buffer, r)
	if err != nil {
		t.Errorf("failed to copy stderr output: %v", err)
	}
	_ = r.Close()

	assert.Contains(t, buffer.String(), matcherError.Error())
	expectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "org.springframework.security:spring-security-crypto",
			Version:        "5.7.3",
			DepGroups:      []string{"compileClasspath", "productionRuntimeClasspath", "runtimeClasspath"},
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
	})

	// Reset buildGradleMatcher mock
	MockAllMatchers()
}

func TestParseGradleLock_MultiplePackage(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/gradle-lockfile/5-pkg"))
	packages, err := lockfile.ParseGradleLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "org.springframework.boot:spring-boot-autoconfigure",
			Version:        "2.7.4",
			DepGroups:      []string{"compileClasspath", "developmentOnly", "productionRuntimeClasspath", "runtimeClasspath"},
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "org.springframework.boot:spring-boot-configuration-processor",
			Version:        "2.7.5",
			DepGroups:      []string{"annotationProcessor", "compileClasspath"},
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "org.springframework.boot:spring-boot-devtools",
			Version:        "2.7.6",
			DepGroups:      []string{"developmentOnly", "runtimeClasspath"},
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "org.springframework.boot:spring-boot-starter-aop",
			Version:        "2.7.7",
			DepGroups:      []string{"compileClasspath", "productionRuntimeClasspath", "runtimeClasspath"},
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "org.springframework.boot:spring-boot-starter-data-jpa",
			Version:        "2.7.8",
			DepGroups:      []string{"compileClasspath", "productionRuntimeClasspath", "runtimeClasspath"},
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
	})
}

func TestParseGradleLock_WithInvalidLines(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/gradle-lockfile/with-bad-pkg"))
	packages, err := lockfile.ParseGradleLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "org.springframework.boot:spring-boot-autoconfigure",
			Version:        "2.7.4",
			DepGroups:      []string{"compileClasspath", "developmentOnly", "productionRuntimeClasspath", "runtimeClasspath"},
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
		{
			Name:           "org.springframework.boot:spring-boot-configuration-processor",
			Version:        "2.7.5",
			DepGroups:      []string{"compileClasspath", "developmentOnly", "productionRuntimeClasspath", "runtimeClasspath"},
			PackageManager: models.Gradle,
			Ecosystem:      lockfile.MavenEcosystem,
			CompareAs:      lockfile.MavenEcosystem,
		},
	})
}
