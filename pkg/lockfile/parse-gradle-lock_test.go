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

func TestParseGradleLockWithDiagnostics(t *testing.T) {
	t.Parallel()

	testParserWithDiagnostics(t, lockfile.ParseGradleLockWithDiagnostics, []testParserWithDiagnosticsTest{
		// only comments
		{
			name: "",
			file: "fixtures/gradle/only-comments",
			want: []lockfile.PackageDetails{},
			diag: lockfile.Diagnostics{
				Warnings: []string{
					"failed to parse lockline: invalid line in gradle lockfile: ",
					"failed to parse lockline: invalid line in gradle lockfile: ",
					"failed to parse lockline: invalid line in gradle lockfile: ",
					"failed to parse lockline: invalid line in gradle lockfile: ",
				},
			},
		},
		// only empty
		{
			name: "",
			file: "fixtures/gradle/only-empty",
			want: []lockfile.PackageDetails{},
			diag: lockfile.Diagnostics{},
		},
		// one package
		{
			name: "",
			file: "fixtures/gradle/one-pkg",
			want: []lockfile.PackageDetails{
				{
					Name:      "org.springframework.security:spring-security-crypto",
					Version:   "5.7.3",
					Ecosystem: lockfile.MavenEcosystem,
					CompareAs: lockfile.MavenEcosystem,
				},
			},
			diag: lockfile.Diagnostics{
				Warnings: []string{
					"failed to parse lockline: invalid line in gradle lockfile: ",
				},
			},
		},
		// multiple packages
		{
			name: "",
			file: "fixtures/gradle/5-pkg",
			want: []lockfile.PackageDetails{
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
			},
			diag: lockfile.Diagnostics{
				Warnings: []string{
					"failed to parse lockline: invalid line in gradle lockfile: ",
				},
			},
		},
		// with invalid lines
		{
			name: "",
			file: "fixtures/gradle/with-bad-pkg",
			want: []lockfile.PackageDetails{
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
			},
			diag: lockfile.Diagnostics{
				Warnings: []string{
					"failed to parse lockline: invalid line in gradle lockfile: >>>",
					"failed to parse lockline: invalid line in gradle lockfile: ////",
					"failed to parse lockline: invalid line in gradle lockfile: ",
					"failed to parse lockline: invalid line in gradle lockfile: ",
					"failed to parse lockline: invalid line in gradle lockfile: a",
					"failed to parse lockline: invalid line in gradle lockfile: b",
					"failed to parse lockline: invalid line in gradle lockfile: ",
					"failed to parse lockline: invalid line in gradle lockfile: ",
					"failed to parse lockline: invalid line in gradle lockfile: ",
					"failed to parse lockline: invalid line in gradle lockfile: ",
					"failed to parse lockline: invalid line in gradle lockfile: ",
					"failed to parse lockline: invalid line in gradle lockfile: ",
					"failed to parse lockline: invalid line in gradle lockfile: ",
					"failed to parse lockline: invalid line in gradle lockfile: ",
				},
			},
		},
	})
}
