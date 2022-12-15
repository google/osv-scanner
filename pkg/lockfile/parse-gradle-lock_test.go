package lockfile_test

import (
	"testing"

	"github.com/google/osv-scanner/pkg/lockfile"
)

func TestParseGradleLock_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseGradleLock("fixtures/gradle/does-not-exist")

	expectErrContaining(t, err, "could not open")
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
		},
		{
			Name:      "org.springframework.boot:spring-boot-configuration-processor",
			Version:   "2.7.5",
			Ecosystem: lockfile.MavenEcosystem,
			CompareAs: lockfile.MavenEcosystem,
		},
		{
			Name:      "org.springframework.boot:spring-boot-devtools",
			Version:   "2.7.6",
			Ecosystem: lockfile.MavenEcosystem,
			CompareAs: lockfile.MavenEcosystem,
		},

		{
			Name:      "org.springframework.boot:spring-boot-starter-aop",
			Version:   "2.7.7",
			Ecosystem: lockfile.MavenEcosystem,
			CompareAs: lockfile.MavenEcosystem,
		},
		{
			Name:      "org.springframework.boot:spring-boot-starter-data-jpa",
			Version:   "2.7.8",
			Ecosystem: lockfile.MavenEcosystem,
			CompareAs: lockfile.MavenEcosystem,
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
		},
		{
			Name:      "org.springframework.boot:spring-boot-configuration-processor",
			Version:   "2.7.5",
			Ecosystem: lockfile.MavenEcosystem,
			CompareAs: lockfile.MavenEcosystem,
		},
	})
}
