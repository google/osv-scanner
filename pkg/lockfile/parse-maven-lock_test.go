package lockfile_test

import (
	"io/fs"
	"testing"

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

	packages, err := lockfile.ParseMavenLock("fixtures/maven/does-not-exist")

	expectErrIs(t, err, fs.ErrNotExist)
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseMavenLock_Invalid(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseMavenLock("fixtures/maven/not-pom.txt")

	expectErrContaining(t, err, "could not extract from")
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseMavenLock_InvalidSyntax(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseMavenLock("fixtures/maven/invalid-syntax.xml")

	expectErrContaining(t, err, "XML syntax error")
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseMavenLock_NoPackages(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseMavenLock("fixtures/maven/empty.xml")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseMavenLock_OnePackage(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseMavenLock("fixtures/maven/one-package.xml")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "org.apache.maven:maven-artifact",
			Version:   "1.0.0",
			Ecosystem: lockfile.MavenEcosystem,
			CompareAs: lockfile.MavenEcosystem,
		},
	})
}

func TestParseMavenLock_TwoPackages(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseMavenLock("fixtures/maven/two-packages.xml")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
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
	})
}

func TestParseMavenLock_WithDependencyManagement(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseMavenLock("fixtures/maven/with-dependency-management.xml")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "io.netty:netty-all",
			Version:   "4.1.9",
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
	})
}

func TestParseMavenLock_Interpolation(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseMavenLock("fixtures/maven/interpolation.xml")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
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
	})
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
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mld := lockfile.MavenLockDependency{
				Version: tt.fields.Version,
			}
			if got := mld.ResolveVersion(tt.args.lockfile); got != tt.want {
				t.Errorf("ResolveVersion() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseMavenLock_WithScope(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseMavenLock("fixtures/maven/with-scope.xml")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "abc:xyz",
			Version:   "1.2.3",
			Ecosystem: lockfile.MavenEcosystem,
			CompareAs: lockfile.MavenEcosystem,
		},
		{
			Name:      "junit:junit",
			Version:   "4.12",
			Ecosystem: lockfile.MavenEcosystem,
			CompareAs: lockfile.MavenEcosystem,
			DepGroups: []string{"test"},
		},
	})
}
