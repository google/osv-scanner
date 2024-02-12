package lockfile_test

import (
	"io/fs"
	"testing"

	"github.com/google/osv-scanner/pkg/models"

	"github.com/google/osv-scanner/pkg/lockfile"
)

func TestPnpmLockExtractor_ShouldExtract(t *testing.T) {
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
			path: "pnpm-lock.yaml",
			want: true,
		},
		{
			name: "",
			path: "path/to/my/pnpm-lock.yaml",
			want: true,
		},
		{
			name: "",
			path: "path/to/my/pnpm-lock.yaml/file",
			want: false,
		},
		{
			name: "",
			path: "path/to/my/pnpm-lock.yaml.file",
			want: false,
		},
		{
			name: "",
			path: "path.to.my.pnpm-lock.yaml",
			want: false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := lockfile.PnpmLockExtractor{}
			got := e.ShouldExtract(tt.path)
			if got != tt.want {
				t.Errorf("Extract() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParsePnpmLock_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePnpmLock("fixtures/pnpm/does-not-exist")

	expectErrIs(t, err, fs.ErrNotExist)
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParsePnpmLock_InvalidYaml(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePnpmLock("fixtures/pnpm/not-yaml.txt")

	expectErrContaining(t, err, "could not extract from")
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParsePnpmLock_Empty(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePnpmLock("fixtures/pnpm/empty.yaml")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParsePnpmLock_NoPackages(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePnpmLock("fixtures/pnpm/no-packages.yaml")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParsePnpmLock_OnePackage(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePnpmLock("fixtures/pnpm/one-package.yaml")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "acorn",
			Version:   "8.7.0",
			Line:      models.Position{Start: 11, End: 15},
			Column:    models.Position{Start: 3, End: 15},
			Ecosystem: lockfile.PnpmEcosystem,
			CompareAs: lockfile.PnpmEcosystem,
		},
	})
}

func TestParsePnpmLock_OnePackageV6Lockfile(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePnpmLock("fixtures/pnpm/one-package-v6-lockfile.yaml")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "acorn",
			Version:   "8.7.0",
			Line:      models.Position{Start: 10, End: 14},
			Column:    models.Position{Start: 3, End: 15},
			Ecosystem: lockfile.PnpmEcosystem,
			CompareAs: lockfile.PnpmEcosystem,
		},
	})
}

func TestParsePnpmLock_OnePackageDev(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePnpmLock("fixtures/pnpm/one-package-dev.yaml")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "acorn",
			Version:   "8.7.0",
			Line:      models.Position{Start: 11, End: 15},
			Column:    models.Position{Start: 3, End: 15},
			Ecosystem: lockfile.PnpmEcosystem,
			CompareAs: lockfile.PnpmEcosystem,
		},
	})
}

func TestParsePnpmLock_ScopedPackages(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePnpmLock("fixtures/pnpm/scoped-packages.yaml")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "@typescript-eslint/types",
			Version:   "5.13.0",
			Line:      models.Position{Start: 11, End: 14},
			Column:    models.Position{Start: 3, End: 15},
			Ecosystem: lockfile.PnpmEcosystem,
			CompareAs: lockfile.PnpmEcosystem,
		},
	})
}

func TestParsePnpmLock_ScopedPackagesV6Lockfile(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePnpmLock("fixtures/pnpm/scoped-packages-v6-lockfile.yaml")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "@typescript-eslint/types",
			Version:   "5.57.1",
			Line:      models.Position{Start: 10, End: 13},
			Column:    models.Position{Start: 3, End: 15},
			Ecosystem: lockfile.PnpmEcosystem,
			CompareAs: lockfile.PnpmEcosystem,
		},
	})
}

func TestParsePnpmLock_PeerDependencies(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePnpmLock("fixtures/pnpm/peer-dependencies.yaml")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "acorn-jsx",
			Version:   "5.3.2",
			Line:      models.Position{Start: 13, End: 19},
			Column:    models.Position{Start: 3, End: 15},
			Ecosystem: lockfile.PnpmEcosystem,
			CompareAs: lockfile.PnpmEcosystem,
		},
		{
			Name:      "acorn",
			Version:   "8.7.0",
			Line:      models.Position{Start: 21, End: 25},
			Column:    models.Position{Start: 3, End: 15},
			Ecosystem: lockfile.PnpmEcosystem,
			CompareAs: lockfile.PnpmEcosystem,
		},
	})
}

func TestParsePnpmLock_PeerDependenciesAdvanced(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePnpmLock("fixtures/pnpm/peer-dependencies-advanced.yaml")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "@typescript-eslint/eslint-plugin",
			Version:   "5.13.0",
			Line:      models.Position{Start: 17, End: 42},
			Column:    models.Position{Start: 3, End: 15},
			Ecosystem: lockfile.PnpmEcosystem,
			CompareAs: lockfile.PnpmEcosystem,
		},
		{
			Name:      "@typescript-eslint/parser",
			Version:   "5.13.0",
			Line:      models.Position{Start: 44, End: 62},
			Column:    models.Position{Start: 3, End: 15},
			Ecosystem: lockfile.PnpmEcosystem,
			CompareAs: lockfile.PnpmEcosystem,
		},
		{
			Name:      "@typescript-eslint/type-utils",
			Version:   "5.13.0",
			Line:      models.Position{Start: 64, End: 81},
			Column:    models.Position{Start: 3, End: 15},
			Ecosystem: lockfile.PnpmEcosystem,
			CompareAs: lockfile.PnpmEcosystem,
		},
		{
			Name:      "@typescript-eslint/types",
			Version:   "5.13.0",
			Line:      models.Position{Start: 83, End: 86},
			Column:    models.Position{Start: 3, End: 15},
			Ecosystem: lockfile.PnpmEcosystem,
			CompareAs: lockfile.PnpmEcosystem,
		},
		{
			Name:      "@typescript-eslint/typescript-estree",
			Version:   "5.13.0",
			Line:      models.Position{Start: 88, End: 107},
			Column:    models.Position{Start: 3, End: 15},
			Ecosystem: lockfile.PnpmEcosystem,
			CompareAs: lockfile.PnpmEcosystem,
		},
		{
			Name:      "@typescript-eslint/utils",
			Version:   "5.13.0",
			Line:      models.Position{Start: 109, End: 125},
			Column:    models.Position{Start: 3, End: 15},
			Ecosystem: lockfile.PnpmEcosystem,
			CompareAs: lockfile.PnpmEcosystem,
		},
		{
			Name:      "eslint-utils",
			Version:   "3.0.0",
			Line:      models.Position{Start: 127, End: 135},
			Column:    models.Position{Start: 3, End: 15},
			Ecosystem: lockfile.PnpmEcosystem,
			CompareAs: lockfile.PnpmEcosystem,
		},
		{
			Name:      "eslint",
			Version:   "8.10.0",
			Line:      models.Position{Start: 137, End: 179},
			Column:    models.Position{Start: 3, End: 15},
			Ecosystem: lockfile.PnpmEcosystem,
			CompareAs: lockfile.PnpmEcosystem,
		},
		{
			Name:      "tsutils",
			Version:   "3.21.0",
			Line:      models.Position{Start: 181, End: 189},
			Column:    models.Position{Start: 3, End: 15},
			Ecosystem: lockfile.PnpmEcosystem,
			CompareAs: lockfile.PnpmEcosystem,
		},
	})
}

func TestParsePnpmLock_MultiplePackages(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePnpmLock("fixtures/pnpm/multiple-packages.yaml")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "aws-sdk",
			Version:   "2.1087.0",
			Line:      models.Position{Start: 11, End: 24},
			Column:    models.Position{Start: 3, End: 15},
			Ecosystem: lockfile.PnpmEcosystem,
			CompareAs: lockfile.PnpmEcosystem,
		},
		{
			Name:      "base64-js",
			Version:   "1.5.1",
			Line:      models.Position{Start: 26, End: 28},
			Column:    models.Position{Start: 3, End: 15},
			Ecosystem: lockfile.PnpmEcosystem,
			CompareAs: lockfile.PnpmEcosystem,
		},
		{
			Name:      "buffer",
			Version:   "4.9.2",
			Line:      models.Position{Start: 30, End: 36},
			Column:    models.Position{Start: 3, End: 15},
			Ecosystem: lockfile.PnpmEcosystem,
			CompareAs: lockfile.PnpmEcosystem,
		},
		{
			Name:      "events",
			Version:   "1.1.1",
			Line:      models.Position{Start: 38, End: 41},
			Column:    models.Position{Start: 3, End: 15},
			Ecosystem: lockfile.PnpmEcosystem,
			CompareAs: lockfile.PnpmEcosystem,
		},
		{
			Name:      "ieee754",
			Version:   "1.1.13",
			Line:      models.Position{Start: 43, End: 45},
			Column:    models.Position{Start: 3, End: 15},
			Ecosystem: lockfile.PnpmEcosystem,
			CompareAs: lockfile.PnpmEcosystem,
		},
		{
			Name:      "isarray",
			Version:   "1.0.0",
			Line:      models.Position{Start: 47, End: 49},
			Column:    models.Position{Start: 3, End: 15},
			Ecosystem: lockfile.PnpmEcosystem,
			CompareAs: lockfile.PnpmEcosystem,
		},
		{
			Name:      "jmespath",
			Version:   "0.16.0",
			Line:      models.Position{Start: 51, End: 54},
			Column:    models.Position{Start: 3, End: 15},
			Ecosystem: lockfile.PnpmEcosystem,
			CompareAs: lockfile.PnpmEcosystem,
		},
		{
			Name:      "punycode",
			Version:   "1.3.2",
			Line:      models.Position{Start: 56, End: 58},
			Column:    models.Position{Start: 3, End: 15},
			Ecosystem: lockfile.PnpmEcosystem,
			CompareAs: lockfile.PnpmEcosystem,
		},
		{
			Name:      "querystring",
			Version:   "0.2.0",
			Line:      models.Position{Start: 60, End: 64},
			Column:    models.Position{Start: 3, End: 15},
			Ecosystem: lockfile.PnpmEcosystem,
			CompareAs: lockfile.PnpmEcosystem,
		},
		{
			Name:      "sax",
			Version:   "1.2.1",
			Line:      models.Position{Start: 66, End: 68},
			Column:    models.Position{Start: 3, End: 15},
			Ecosystem: lockfile.PnpmEcosystem,
			CompareAs: lockfile.PnpmEcosystem,
		},
		{
			Name:      "url",
			Version:   "0.10.3",
			Line:      models.Position{Start: 70, End: 75},
			Column:    models.Position{Start: 3, End: 15},
			Ecosystem: lockfile.PnpmEcosystem,
			CompareAs: lockfile.PnpmEcosystem,
		},
		{
			Name:      "uuid",
			Version:   "3.3.2",
			Line:      models.Position{Start: 77, End: 81},
			Column:    models.Position{Start: 3, End: 15},
			Ecosystem: lockfile.PnpmEcosystem,
			CompareAs: lockfile.PnpmEcosystem,
		},
		{
			Name:      "xml2js",
			Version:   "0.4.19",
			Line:      models.Position{Start: 83, End: 88},
			Column:    models.Position{Start: 3, End: 15},
			Ecosystem: lockfile.PnpmEcosystem,
			CompareAs: lockfile.PnpmEcosystem,
		},
		{
			Name:      "xmlbuilder",
			Version:   "9.0.7",
			Line:      models.Position{Start: 90, End: 93},
			Column:    models.Position{Start: 3, End: 15},
			Ecosystem: lockfile.PnpmEcosystem,
			CompareAs: lockfile.PnpmEcosystem,
		},
	})
}

func TestParsePnpmLock_MultipleVersions(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePnpmLock("fixtures/pnpm/multiple-versions.yaml")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "uuid",
			Version:   "3.3.2",
			Line:      models.Position{Start: 13, End: 17},
			Column:    models.Position{Start: 3, End: 15},
			Ecosystem: lockfile.PnpmEcosystem,
			CompareAs: lockfile.PnpmEcosystem,
		},
		{
			Name:      "uuid",
			Version:   "8.3.2",
			Line:      models.Position{Start: 19, End: 22},
			Column:    models.Position{Start: 3, End: 15},
			Ecosystem: lockfile.PnpmEcosystem,
			CompareAs: lockfile.PnpmEcosystem,
		},
		{
			Name:      "xmlbuilder",
			Version:   "9.0.7",
			Line:      models.Position{Start: 24, End: 27},
			Column:    models.Position{Start: 3, End: 15},
			Ecosystem: lockfile.PnpmEcosystem,
			CompareAs: lockfile.PnpmEcosystem,
		},
	})
}

func TestParsePnpmLock_Tarball(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePnpmLock("fixtures/pnpm/tarball.yaml")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "@my-org/my-package",
			Version:   "3.2.3",
			Line:      models.Position{Start: 10, End: 14},
			Column:    models.Position{Start: 3, End: 14},
			Ecosystem: lockfile.PnpmEcosystem,
			CompareAs: lockfile.PnpmEcosystem,
			Commit:    "",
			DepGroups: []string{"dev"},
		},
	})
}

func TestParsePnpmLock_Exotic(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePnpmLock("fixtures/pnpm/exotic.yaml")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "foo",
			Version:   "1.0.0",
			Line:      models.Position{Start: 10, End: 10},
			Column:    models.Position{Start: 3, End: 14},
			Ecosystem: lockfile.PnpmEcosystem,
			CompareAs: lockfile.PnpmEcosystem,
		},
		{
			Name:      "@foo/bar",
			Version:   "1.0.0",
			Line:      models.Position{Start: 11, End: 11},
			Column:    models.Position{Start: 3, End: 19},
			Ecosystem: lockfile.PnpmEcosystem,
			CompareAs: lockfile.PnpmEcosystem,
		},
		{
			Name:      "foo",
			Version:   "1.1.0",
			Line:      models.Position{Start: 12, End: 12},
			Column:    models.Position{Start: 3, End: 32},
			Ecosystem: lockfile.PnpmEcosystem,
			CompareAs: lockfile.PnpmEcosystem,
		},
		{
			Name:      "@foo/bar",
			Version:   "1.1.0",
			Line:      models.Position{Start: 13, End: 13},
			Column:    models.Position{Start: 3, End: 37},
			Ecosystem: lockfile.PnpmEcosystem,
			CompareAs: lockfile.PnpmEcosystem,
		},
		{
			Name:      "foo",
			Version:   "1.2.0",
			Line:      models.Position{Start: 15, End: 15},
			Column:    models.Position{Start: 3, End: 25},
			Ecosystem: lockfile.PnpmEcosystem,
			CompareAs: lockfile.PnpmEcosystem,
		},
		{
			Name:      "foo",
			Version:   "1.3.0",
			Line:      models.Position{Start: 16, End: 16},
			Column:    models.Position{Start: 3, End: 35},
			Ecosystem: lockfile.PnpmEcosystem,
			CompareAs: lockfile.PnpmEcosystem,
		},
		{
			Name:      "foo",
			Version:   "1.4.0",
			Line:      models.Position{Start: 17, End: 17},
			Column:    models.Position{Start: 3, End: 40},
			Ecosystem: lockfile.PnpmEcosystem,
			CompareAs: lockfile.PnpmEcosystem,
		},
	})
}

func TestParsePnpmLock_Commits(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePnpmLock("fixtures/pnpm/commits.yaml")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "my-bitbucket-package",
			Version:   "1.0.0",
			Line:      models.Position{Start: 14, End: 18},
			Column:    models.Position{Start: 3, End: 15},
			Ecosystem: lockfile.PnpmEcosystem,
			CompareAs: lockfile.PnpmEcosystem,
			Commit:    "6104ae42cd32c3d724036d3964678f197b2c9cdb",
		},
		{
			Name:      "@my-scope/my-package",
			Version:   "1.0.0",
			Line:      models.Position{Start: 20, End: 26},
			Column:    models.Position{Start: 3, End: 15},
			Ecosystem: lockfile.PnpmEcosystem,
			CompareAs: lockfile.PnpmEcosystem,
			Commit:    "267087851ad5fac92a184749c27cd539e2fc862e",
		},
		{
			Name:      "@my-scope/my-other-package",
			Version:   "1.0.0",
			Line:      models.Position{Start: 28, End: 32},
			Column:    models.Position{Start: 3, End: 15},
			Ecosystem: lockfile.PnpmEcosystem,
			CompareAs: lockfile.PnpmEcosystem,
			Commit:    "fbfc962ab51eb1d754749b68c064460221fbd689",
		},
		{
			Name:      "faker-parser",
			Version:   "0.0.1",
			Line:      models.Position{Start: 34, End: 40},
			Column:    models.Position{Start: 3, End: 15},
			Ecosystem: lockfile.PnpmEcosystem,
			CompareAs: lockfile.PnpmEcosystem,
			Commit:    "d2dc42a9351d4d89ec48c525e34f612b6d77993f",
		},
		{
			Name:      "mocks",
			Version:   "20.0.1",
			Line:      models.Position{Start: 42, End: 48},
			Column:    models.Position{Start: 3, End: 15},
			Ecosystem: lockfile.PnpmEcosystem,
			CompareAs: lockfile.PnpmEcosystem,
			Commit:    "590f321b4eb3f692bb211bd74e22947639a6f79d",
		},
	})
}

func TestParsePnpmLock_Files(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePnpmLock("fixtures/pnpm/files.yaml")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "my-file-package",
			Version:   "0.0.0",
			Line:      models.Position{Start: 10, End: 14},
			Column:    models.Position{Start: 3, End: 15},
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			Commit:    "",
		},
		{
			Name:      "a-local-package",
			Version:   "1.0.0",
			Line:      models.Position{Start: 16, End: 20},
			Column:    models.Position{Start: 3, End: 15},
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			Commit:    "",
		},
		{
			Name:      "a-nested-local-package",
			Version:   "1.0.0",
			Line:      models.Position{Start: 22, End: 26},
			Column:    models.Position{Start: 3, End: 15},
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			Commit:    "",
		},
		{
			Name:      "one-up",
			Version:   "1.0.0",
			Line:      models.Position{Start: 28, End: 32},
			Column:    models.Position{Start: 3, End: 15},
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			Commit:    "",
		},
		{
			Name:      "one-up-with-peer",
			Version:   "1.0.0",
			Line:      models.Position{Start: 34, End: 40},
			Column:    models.Position{Start: 3, End: 25},
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			Commit:    "",
		},
	})
}
