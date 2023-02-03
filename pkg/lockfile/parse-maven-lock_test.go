package lockfile_test

import (
	"github.com/google/osv-scanner/pkg/lockfile"
	"testing"
)

func TestParseMavenLock_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseMavenLock("fixtures/maven/does-not-exist")

	expectErrContaining(t, err, "could not read")
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseMavenLock_Invalid(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseMavenLock("fixtures/maven/not-pom.txt")

	expectErrContaining(t, err, "could not parse")
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestMavenLockDependency_ResolveVersion(t *testing.T) {
	t.Parallel()

	type fields struct {
		Version string
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
			name:   "",
			fields: fields{Version: "1.0"},
			args:   args{lockfile: lockfile.MavenLockFile{}},
			want:   "1.0",
		},
		// [1.0]: Hard requirement for 1.0. Use 1.0 and only 1.0.
		{
			name:   "",
			fields: fields{Version: "[1.0]"},
			args:   args{lockfile: lockfile.MavenLockFile{}},
			want:   "1.0",
		},
		// (,1.0]: Hard requirement for any version <= 1.0.
		{
			name:   "",
			fields: fields{Version: "(,1.0]"},
			args:   args{lockfile: lockfile.MavenLockFile{}},
			want:   "0",
		},
		// [1.2,1.3]: Hard requirement for any version between 1.2 and 1.3 inclusive.
		{
			name:   "",
			fields: fields{Version: "[1.2,1.3]"},
			args:   args{lockfile: lockfile.MavenLockFile{}},
			want:   "1.2",
		},
		// [1.0,2.0): 1.0 <= x < 2.0; Hard requirement for any version between 1.0 inclusive and 2.0 exclusive.
		{
			name:   "",
			fields: fields{Version: "[1.0,2.0)"},
			args:   args{lockfile: lockfile.MavenLockFile{}},
			want:   "1.0",
		},
		// [1.5,): Hard requirement for any version greater than or equal to 1.5.
		{
			name:   "",
			fields: fields{Version: "[1.5,)"},
			args:   args{lockfile: lockfile.MavenLockFile{}},
			want:   "1.5",
		},
		// (,1.0],[1.2,): Hard requirement for any version less than or equal to 1.0 than or greater than or equal to 1.2, but not 1.1.
		{
			name:   "",
			fields: fields{Version: "(,1.0],[1.2,)"},
			args:   args{lockfile: lockfile.MavenLockFile{}},
			want:   "0",
		},
		// (,1.1),(1.1,): Hard requirement for any version except 1.1; for example because 1.1 has a critical vulnerability.
		{
			name:   "",
			fields: fields{Version: "(,1.1),(1.1,)"},
			args:   args{lockfile: lockfile.MavenLockFile{}},
			want:   "0",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var diag lockfile.Diagnostics

			mld := lockfile.MavenLockDependency{
				Version: tt.fields.Version,
			}
			if got := mld.ResolveVersion(&diag, tt.args.lockfile); got != tt.want {
				t.Errorf("ResolveVersion() = %v, want %v", got, tt.want)
			}

			expectDiagnostics(t, diag, lockfile.Diagnostics{})
		})
	}
}

func TestParseMavenLockWithDiagnostics(t *testing.T) {
	t.Parallel()

	testParserWithDiagnostics(t, lockfile.ParseMavenLockWithDiagnostics, []testParserWithDiagnosticsTest{
		// empty
		{
			name: "",
			file: "fixtures/maven/empty.xml",
			want: []lockfile.PackageDetails{},
			diag: lockfile.Diagnostics{},
		},
		// one package
		{
			name: "",
			file: "fixtures/maven/one-package.xml",
			want: []lockfile.PackageDetails{
				{
					Name:      "org.apache.maven:maven-artifact",
					Version:   "1.0.0",
					Ecosystem: lockfile.MavenEcosystem,
					CompareAs: lockfile.MavenEcosystem,
				},
			},
			diag: lockfile.Diagnostics{},
		},
		// two packages
		{
			name: "",
			file: "fixtures/maven/two-packages.xml",
			want: []lockfile.PackageDetails{
				{
					Name:      "io.netty:netty-all",
					Version:   "4.1.42.Final",
					Ecosystem: lockfile.MavenEcosystem,
					CompareAs: lockfile.MavenEcosystem,
				},
				{
					Name:      "org.slf4j:slf4j-log4j12",
					Version:   "1.7.25",
					Ecosystem: lockfile.MavenEcosystem,
					CompareAs: lockfile.MavenEcosystem,
				},
			},
			diag: lockfile.Diagnostics{},
		},
		// with dependency management
		{
			name: "",
			file: "fixtures/maven/with-dependency-management.xml",
			want: []lockfile.PackageDetails{
				{
					Name:      "io.netty:netty-all",
					Version:   "4.1.42.Final",
					Ecosystem: lockfile.MavenEcosystem,
					CompareAs: lockfile.MavenEcosystem,
				},
				{
					Name:      "org.slf4j:slf4j-log4j12",
					Version:   "1.7.25",
					Ecosystem: lockfile.MavenEcosystem,
					CompareAs: lockfile.MavenEcosystem,
				},
				{
					Name:      "com.google.code.findbugs:jsr305",
					Version:   "3.0.2",
					Ecosystem: lockfile.MavenEcosystem,
					CompareAs: lockfile.MavenEcosystem,
				},
			},
			diag: lockfile.Diagnostics{},
		},
		// interpolation
		{
			name: "",
			file: "fixtures/maven/interpolation.xml",
			want: []lockfile.PackageDetails{
				{
					Name:      "org.mine:mypackage",
					Version:   "1.0.0",
					Ecosystem: lockfile.MavenEcosystem,
					CompareAs: lockfile.MavenEcosystem,
				},
				{
					Name:      "org.mine:my.package",
					Version:   "2.3.4",
					Ecosystem: lockfile.MavenEcosystem,
					CompareAs: lockfile.MavenEcosystem,
				},
				{
					Name:      "org.mine:ranged-package",
					Version:   "9.4.35.v20201120",
					Ecosystem: lockfile.MavenEcosystem,
					CompareAs: lockfile.MavenEcosystem,
				},
				{
					Name:      "org.mine:missing-property",
					Version:   "0",
					Ecosystem: lockfile.MavenEcosystem,
					CompareAs: lockfile.MavenEcosystem,
				},
			},
			diag: lockfile.Diagnostics{
				Warnings: []string{
					"Failed to resolve version of org.mine:missing-property: property \"missing\" could not be found",
				},
			},
		},
	})
}
