package lockfile_test

import (
	"testing"

	"github.com/google/osv-scanner/pkg/lockfile"
)

func TestParseApkInstalled_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseApkInstalled("fixtures/apk/does-not-exist")

	expectErrContaining(t, err, "could not open")
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseApkInstalledWithDiagnostics(t *testing.T) {
	t.Parallel()

	testParserWithDiagnostics(t, lockfile.ParseApkInstalledWithDiagnostics, []testParserWithDiagnosticsTest{
		// empty
		{
			name: "",
			file: "fixtures/apk/empty_installed",
			want: []lockfile.PackageDetails{},
			diag: lockfile.Diagnostics{},
		},
		// not installed
		{
			name: "",
			file: "fixtures/apk/not_installed",
			want: []lockfile.PackageDetails{},
			diag: lockfile.Diagnostics{
				Warnings: []string{
					"warning: malformed APK installed file. Found no version number in record. Package <unknown>. File: fixtures/apk/not_installed",
					"warning: malformed APK installed file. Found no package name in record. File: fixtures/apk/not_installed",
					"warning: malformed APK installed file. Found no version number in record. Package <unknown>. File: fixtures/apk/not_installed",
					"warning: malformed APK installed file. Found no package name in record. File: fixtures/apk/not_installed",
				},
			},
		},
		// malformed
		{
			name: "",
			file: "fixtures/apk/malformed_installed",
			want: []lockfile.PackageDetails{
				{
					Name:      "busybox",
					Version:   "",
					Commit:    "1dbf7a793afae640ea643a055b6dd4f430ac116b",
					Ecosystem: lockfile.AlpineEcosystem,
					CompareAs: lockfile.AlpineEcosystem,
				},
			},
			diag: lockfile.Diagnostics{
				Warnings: []string{
					"warning: malformed APK installed file. Found no version number in record. Package <unknown>. File: fixtures/apk/malformed_installed",
					"warning: malformed APK installed file. Found no package name in record. File: fixtures/apk/malformed_installed",
					"warning: malformed APK installed file. Found no version number in record. Package <unknown>. File: fixtures/apk/malformed_installed",
					"warning: malformed APK installed file. Found no package name in record. File: fixtures/apk/malformed_installed",
					"warning: malformed APK installed file. Found no package name in record. File: fixtures/apk/malformed_installed",
					"warning: malformed APK installed file. Found no version number in record. Package <unknown>. File: fixtures/apk/malformed_installed",
					"warning: malformed APK installed file. Found no package name in record. File: fixtures/apk/malformed_installed",
					"warning: malformed APK installed file. Found no version number in record. Package busybox. File: fixtures/apk/malformed_installed",
				},
			},
		},
		// one package
		{
			name: "",
			file: "fixtures/apk/single_installed",
			want: []lockfile.PackageDetails{
				{
					Name:      "apk-tools",
					Version:   "2.12.10-r1",
					Commit:    "0188f510baadbae393472103427b9c1875117136",
					Ecosystem: lockfile.AlpineEcosystem,
					CompareAs: lockfile.AlpineEcosystem,
				},
			},
			diag: lockfile.Diagnostics{},
		},
		// different line orders
		{
			name: "",
			file: "fixtures/apk/shuffled_installed",
			want: []lockfile.PackageDetails{
				{
					Name:      "apk-tools",
					Version:   "2.12.10-r1",
					Commit:    "0188f510baadbae393472103427b9c1875117136",
					Ecosystem: lockfile.AlpineEcosystem,
					CompareAs: lockfile.AlpineEcosystem,
				},
			},
			diag: lockfile.Diagnostics{},
		},
		// multiple packages
		{
			name: "",
			file: "fixtures/apk/multiple_installed",
			want: []lockfile.PackageDetails{
				{
					Name:      "alpine-baselayout-data",
					Version:   "3.4.0-r0",
					Commit:    "bd965a7ebf7fd8f07d7a0cc0d7375bf3e4eb9b24",
					Ecosystem: lockfile.AlpineEcosystem,
					CompareAs: lockfile.AlpineEcosystem,
				},
				{
					Name:      "musl",
					Version:   "1.2.3-r4",
					Commit:    "f93af038c3de7146121c2ea8124ba5ce29b4b058",
					Ecosystem: lockfile.AlpineEcosystem,
					CompareAs: lockfile.AlpineEcosystem,
				},
				{
					Name:      "busybox",
					Version:   "1.35.0-r29",
					Commit:    "1dbf7a793afae640ea643a055b6dd4f430ac116b",
					Ecosystem: lockfile.AlpineEcosystem,
					CompareAs: lockfile.AlpineEcosystem,
				},
			},
			diag: lockfile.Diagnostics{},
		},
	})
}
