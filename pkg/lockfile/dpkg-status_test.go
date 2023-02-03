package lockfile_test

import (
	"testing"

	"github.com/google/osv-scanner/pkg/lockfile"
)

func TestParseDpkgStatus_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseDpkgStatus("fixtures/dpkg/does-not-exist")

	expectErrContaining(t, err, "could not open")
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseDpkgStatusWithDiagnostics(t *testing.T) {
	t.Parallel()

	testParserWithDiagnostics(t, lockfile.ParseDpkgStatusWithDiagnostics, []testParserWithDiagnosticsTest{
		// empty
		{
			name: "",
			file: "fixtures/dpkg/empty_status",
			want: []lockfile.PackageDetails{},
			diag: lockfile.Diagnostics{},
		},
		// not status
		{
			name: "",
			file: "fixtures/dpkg/not_status",
			want: []lockfile.PackageDetails{},
			diag: lockfile.Diagnostics{
				Warnings: []string{
					"warning: malformed DPKG status file. Found no version number in record. Package <unknown>. File: fixtures/dpkg/not_status",
					"warning: malformed DPKG status file. Found no package name in record. File: fixtures/dpkg/not_status",
					"warning: malformed DPKG status file. Found no version number in record. Package <unknown>. File: fixtures/dpkg/not_status",
					"warning: malformed DPKG status file. Found no package name in record. File: fixtures/dpkg/not_status",
				},
			},
		},
		// malformed
		{
			name: "",
			file: "fixtures/dpkg/malformed_status",
			want: []lockfile.PackageDetails{
				{
					Name:      "bash",
					Version:   "",
					Ecosystem: lockfile.DebianEcosystem,
					CompareAs: lockfile.DebianEcosystem,
				},
				{
					Name:      "util-linux",
					Version:   "2.36.1-8+deb11u1",
					Ecosystem: lockfile.DebianEcosystem,
					CompareAs: lockfile.DebianEcosystem,
				},
			},
			diag: lockfile.Diagnostics{
				Warnings: []string{
					"warning: malformed DPKG status file. Found no version number in record. Package <unknown>. File: fixtures/dpkg/malformed_status",
					"warning: malformed DPKG status file. Found no package name in record. File: fixtures/dpkg/malformed_status",
					"warning: malformed DPKG status file. Found no version number in record. Package <unknown>. File: fixtures/dpkg/malformed_status",
					"warning: malformed DPKG status file. Found no package name in record. File: fixtures/dpkg/malformed_status",
					"warning: malformed DPKG status file. Found no version number in record. Package bash. File: fixtures/dpkg/malformed_status",
					"warning: malformed DPKG status file. Found no version number in record. Package <unknown>. File: fixtures/dpkg/malformed_status",
					"warning: malformed DPKG status file. Found no package name in record. File: fixtures/dpkg/malformed_status",
					"warning: malformed DPKG status file. Found no version number in record. Package <unknown>. File: fixtures/dpkg/malformed_status",
					"warning: malformed DPKG status file. Found no package name in record. File: fixtures/dpkg/malformed_status",
					"warning: malformed DPKG status file. Found no valid \"Source\" field. File: fixtures/dpkg/malformed_status",
					"warning: malformed DPKG status file. Found no version number in record. Package <unknown>. File: fixtures/dpkg/malformed_status",
					"warning: malformed DPKG status file. Found no package name in record. File: fixtures/dpkg/malformed_status",
					"warning: malformed DPKG status file. Found no version number in record. Package <unknown>. File: fixtures/dpkg/malformed_status",
					"warning: malformed DPKG status file. Found no package name in record. File: fixtures/dpkg/malformed_status",
				},
			},
		},
		// one package
		{
			name: "",
			file: "fixtures/dpkg/single_status",
			want: []lockfile.PackageDetails{
				{
					Name:      "sudo",
					Version:   "1.8.27-1+deb10u1",
					Ecosystem: lockfile.DebianEcosystem,
					CompareAs: lockfile.DebianEcosystem,
				},
			},
			diag: lockfile.Diagnostics{},
		},
		// different line orders
		{
			name: "",
			file: "fixtures/dpkg/shuffled_status",
			want: []lockfile.PackageDetails{
				{
					Name:      "glibc",
					Version:   "2.31-13+deb11u5",
					Ecosystem: lockfile.DebianEcosystem,
					CompareAs: lockfile.DebianEcosystem,
				},
			},
			diag: lockfile.Diagnostics{},
		},
		// multiple packages
		{
			name: "",
			file: "fixtures/dpkg/multiple_status",
			want: []lockfile.PackageDetails{
				{
					Name:      "bash",
					Version:   "5.1-2+deb11u1",
					Ecosystem: lockfile.DebianEcosystem,
					CompareAs: lockfile.DebianEcosystem,
				},
				{
					Name:      "util-linux",
					Version:   "2.36.1-8+deb11u1",
					Ecosystem: lockfile.DebianEcosystem,
					CompareAs: lockfile.DebianEcosystem,
				},
				{
					Name:      "glibc",
					Version:   "2.31-13+deb11u5",
					Ecosystem: lockfile.DebianEcosystem,
					CompareAs: lockfile.DebianEcosystem,
				},
			},
			diag: lockfile.Diagnostics{
				Warnings: []string{
					"warning: malformed DPKG status file. Found no version number in record. Package <unknown>. File: fixtures/dpkg/multiple_status",
					"warning: malformed DPKG status file. Found no package name in record. File: fixtures/dpkg/multiple_status",
				},
			},
		},
		// source version override
		{
			name: "",
			file: "fixtures/dpkg/source_ver_override_status",
			want: []lockfile.PackageDetails{
				{
					Name:      "lvm2",
					Version:   "2.02.176-4.1ubuntu3",
					Ecosystem: lockfile.DebianEcosystem,
					CompareAs: lockfile.DebianEcosystem,
				},
			},
			diag: lockfile.Diagnostics{},
		},
	})
}
