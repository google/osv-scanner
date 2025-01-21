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
	expectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{})
}

func TestParsePnpmLock_InvalidYaml(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePnpmLock("fixtures/pnpm/not-yaml.txt")

	expectErrContaining(t, err, "could not extract from")
	expectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{})
}

func TestParsePnpmLock_Empty(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePnpmLock("fixtures/pnpm/empty.yaml")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{})
}

func TestParsePnpmLock_NoPackages(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePnpmLock("fixtures/pnpm/no-packages.yaml")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{})
}

func TestParsePnpmLock_OnePackage(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/pnpm/one-package.yaml"))
	packages, err := lockfile.ParsePnpmLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "acorn",
			Version:        "8.7.0",
			PackageManager: models.Pnpm,
			TargetVersions: []string{"^8.7.0"},
			Ecosystem:      lockfile.PnpmEcosystem,
			CompareAs:      lockfile.PnpmEcosystem,
			IsDirect:       true,
		},
	})
}

//nolint:paralleltest
func TestParsePnpmLock_OnePackage_MatcherFailed(t *testing.T) {
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

	// Mock packageJSONMatcher to fail
	matcherError := errors.New("packageJSONMatcher failed")
	lockfile.PnpmExtractor.Matcher = FailingMatcher{Error: matcherError}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/pnpm/one-package.yaml"))
	packages, err := lockfile.ParsePnpmLock(path)
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
			Name:           "acorn",
			Version:        "8.7.0",
			PackageManager: models.Pnpm,
			TargetVersions: []string{"^8.7.0"},
			Ecosystem:      lockfile.PnpmEcosystem,
			CompareAs:      lockfile.PnpmEcosystem,
			IsDirect:       true,
		},
	})

	// Reset packageJSONMatcher mock
	MockAllMatchers()
}

func TestParsePnpmLock_OnePackageV6Lockfile(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/pnpm/one-package-v6-lockfile.yaml"))
	packages, err := lockfile.ParsePnpmLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "acorn",
			Version:        "8.7.0",
			PackageManager: models.Pnpm,
			TargetVersions: []string{"8.7.0"},
			Ecosystem:      lockfile.PnpmEcosystem,
			CompareAs:      lockfile.PnpmEcosystem,
			IsDirect:       true,
		},
	})
}

func TestParsePnpmLock_OnePackageDev(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/pnpm/one-package-dev.yaml"))
	packages, err := lockfile.ParsePnpmLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "acorn",
			Version:        "8.7.0",
			PackageManager: models.Pnpm,
			TargetVersions: []string{"^8.7.0"},
			Ecosystem:      lockfile.PnpmEcosystem,
			CompareAs:      lockfile.PnpmEcosystem,
			IsDirect:       true,
			DepGroups:      []string{"dev"},
		},
	})
}

func TestParsePnpmLock_ScopedPackages(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/pnpm/scoped-packages.yaml"))
	packages, err := lockfile.ParsePnpmLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "@typescript-eslint/types",
			Version:        "5.13.0",
			PackageManager: models.Pnpm,
			TargetVersions: []string{"^5.0.0"},
			Ecosystem:      lockfile.PnpmEcosystem,
			CompareAs:      lockfile.PnpmEcosystem,
			IsDirect:       true,
		},
	})
}

func TestParsePnpmLock_ScopedPackagesV6Lockfile(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/pnpm/scoped-packages-v6-lockfile.yaml"))
	packages, err := lockfile.ParsePnpmLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "@typescript-eslint/types",
			Version:        "5.57.1",
			PackageManager: models.Pnpm,
			TargetVersions: []string{"^5.0.0"},
			Ecosystem:      lockfile.PnpmEcosystem,
			CompareAs:      lockfile.PnpmEcosystem,
			IsDirect:       true,
		},
	})
}

func TestParsePnpmLock_PeerDependencies(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/pnpm/peer-dependencies.yaml"))
	packages, err := lockfile.ParsePnpmLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "acorn-jsx",
			Version:        "5.3.2",
			PackageManager: models.Pnpm,
			TargetVersions: []string{"^5.3.2"},
			Ecosystem:      lockfile.PnpmEcosystem,
			CompareAs:      lockfile.PnpmEcosystem,
			IsDirect:       true,
		},
		{
			Name:           "acorn",
			Version:        "8.7.0",
			PackageManager: models.Pnpm,
			TargetVersions: []string{"^8.7.0"},
			Ecosystem:      lockfile.PnpmEcosystem,
			CompareAs:      lockfile.PnpmEcosystem,
			IsDirect:       true,
		},
	})
}

func TestParsePnpmLock_PeerDependenciesAdvanced(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/pnpm/peer-dependencies-advanced.yaml"))
	packages, err := lockfile.ParsePnpmLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "@typescript-eslint/eslint-plugin",
			Version:        "5.13.0",
			PackageManager: models.Pnpm,
			TargetVersions: []string{"^5.12.0"},
			Ecosystem:      lockfile.PnpmEcosystem,
			CompareAs:      lockfile.PnpmEcosystem,
			IsDirect:       true,
		},
		{
			Name:           "@typescript-eslint/parser",
			Version:        "5.13.0",
			PackageManager: models.Pnpm,
			TargetVersions: []string{"^5.12.0"},
			Ecosystem:      lockfile.PnpmEcosystem,
			CompareAs:      lockfile.PnpmEcosystem,
			IsDirect:       true,
		},
		{
			Name:           "@typescript-eslint/type-utils",
			Version:        "5.13.0",
			PackageManager: models.Pnpm,
			Ecosystem:      lockfile.PnpmEcosystem,
			CompareAs:      lockfile.PnpmEcosystem,
			IsDirect:       false,
		},
		{
			Name:           "@typescript-eslint/types",
			Version:        "5.13.0",
			PackageManager: models.Pnpm,
			Ecosystem:      lockfile.PnpmEcosystem,
			CompareAs:      lockfile.PnpmEcosystem,
			IsDirect:       false,
		},
		{
			Name:           "@typescript-eslint/typescript-estree",
			Version:        "5.13.0",
			PackageManager: models.Pnpm,
			Ecosystem:      lockfile.PnpmEcosystem,
			CompareAs:      lockfile.PnpmEcosystem,
			IsDirect:       false,
		},
		{
			Name:           "@typescript-eslint/utils",
			Version:        "5.13.0",
			PackageManager: models.Pnpm,
			Ecosystem:      lockfile.PnpmEcosystem,
			CompareAs:      lockfile.PnpmEcosystem,
			IsDirect:       false,
		},
		{
			Name:           "eslint-utils",
			Version:        "3.0.0",
			PackageManager: models.Pnpm,
			Ecosystem:      lockfile.PnpmEcosystem,
			CompareAs:      lockfile.PnpmEcosystem,
			IsDirect:       false,
		},
		{
			Name:           "eslint",
			Version:        "8.10.0",
			PackageManager: models.Pnpm,
			TargetVersions: []string{"^8.0.0"},
			Ecosystem:      lockfile.PnpmEcosystem,
			CompareAs:      lockfile.PnpmEcosystem,
			IsDirect:       true,
		},
		{
			Name:           "tsutils",
			Version:        "3.21.0",
			PackageManager: models.Pnpm,
			Ecosystem:      lockfile.PnpmEcosystem,
			CompareAs:      lockfile.PnpmEcosystem,
			IsDirect:       false,
		},
	})
}

func TestParsePnpmLock_MultiplePackages(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/pnpm/multiple-packages.yaml"))
	packages, err := lockfile.ParsePnpmLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "aws-sdk",
			Version:        "2.1087.0",
			PackageManager: models.Pnpm,
			TargetVersions: []string{"^2.1087.0"},
			Ecosystem:      lockfile.PnpmEcosystem,
			CompareAs:      lockfile.PnpmEcosystem,
			IsDirect:       true,
		},
		{
			Name:           "base64-js",
			Version:        "1.5.1",
			PackageManager: models.Pnpm,
			Ecosystem:      lockfile.PnpmEcosystem,
			CompareAs:      lockfile.PnpmEcosystem,
			IsDirect:       false,
		},
		{
			Name:           "buffer",
			Version:        "4.9.2",
			PackageManager: models.Pnpm,
			Ecosystem:      lockfile.PnpmEcosystem,
			CompareAs:      lockfile.PnpmEcosystem,
			IsDirect:       false,
		},
		{
			Name:           "events",
			Version:        "1.1.1",
			PackageManager: models.Pnpm,
			Ecosystem:      lockfile.PnpmEcosystem,
			CompareAs:      lockfile.PnpmEcosystem,
			IsDirect:       false,
		},
		{
			Name:           "ieee754",
			Version:        "1.1.13",
			PackageManager: models.Pnpm,
			Ecosystem:      lockfile.PnpmEcosystem,
			CompareAs:      lockfile.PnpmEcosystem,
		},
		{
			Name:           "isarray",
			Version:        "1.0.0",
			PackageManager: models.Pnpm,
			Ecosystem:      lockfile.PnpmEcosystem,
			CompareAs:      lockfile.PnpmEcosystem,
			IsDirect:       false,
		},
		{
			Name:           "jmespath",
			Version:        "0.16.0",
			PackageManager: models.Pnpm,
			Ecosystem:      lockfile.PnpmEcosystem,
			CompareAs:      lockfile.PnpmEcosystem,
			IsDirect:       false,
		},
		{
			Name:           "punycode",
			Version:        "1.3.2",
			PackageManager: models.Pnpm,
			Ecosystem:      lockfile.PnpmEcosystem,
			CompareAs:      lockfile.PnpmEcosystem,
		},
		{
			Name:           "querystring",
			Version:        "0.2.0",
			PackageManager: models.Pnpm,
			Ecosystem:      lockfile.PnpmEcosystem,
			CompareAs:      lockfile.PnpmEcosystem,
			IsDirect:       false,
		},
		{
			Name:           "sax",
			Version:        "1.2.1",
			PackageManager: models.Pnpm,
			Ecosystem:      lockfile.PnpmEcosystem,
			CompareAs:      lockfile.PnpmEcosystem,
			IsDirect:       false,
		},
		{
			Name:           "url",
			Version:        "0.10.3",
			PackageManager: models.Pnpm,
			Ecosystem:      lockfile.PnpmEcosystem,
			CompareAs:      lockfile.PnpmEcosystem,
			IsDirect:       false,
		},
		{
			Name:           "uuid",
			Version:        "3.3.2",
			PackageManager: models.Pnpm,
			Ecosystem:      lockfile.PnpmEcosystem,
			CompareAs:      lockfile.PnpmEcosystem,
			IsDirect:       false,
		},
		{
			Name:           "xml2js",
			Version:        "0.4.19",
			PackageManager: models.Pnpm,
			Ecosystem:      lockfile.PnpmEcosystem,
			CompareAs:      lockfile.PnpmEcosystem,
			IsDirect:       false,
		},
		{
			Name:           "xmlbuilder",
			Version:        "9.0.7",
			PackageManager: models.Pnpm,
			Ecosystem:      lockfile.PnpmEcosystem,
			CompareAs:      lockfile.PnpmEcosystem,
			IsDirect:       false,
		},
	})
}

func TestParsePnpmLock_MultipleVersions(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/pnpm/multiple-versions.yaml"))
	packages, err := lockfile.ParsePnpmLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "uuid",
			Version:        "3.3.2",
			PackageManager: models.Pnpm,
			Ecosystem:      lockfile.PnpmEcosystem,
			CompareAs:      lockfile.PnpmEcosystem,
			IsDirect:       true,
		},
		{
			Name:           "uuid",
			Version:        "8.3.2",
			PackageManager: models.Pnpm,
			TargetVersions: []string{"^8.0.0"},
			Ecosystem:      lockfile.PnpmEcosystem,
			CompareAs:      lockfile.PnpmEcosystem,
			IsDirect:       true,
		},
		{
			Name:           "xmlbuilder",
			Version:        "9.0.7",
			PackageManager: models.Pnpm,
			Ecosystem:      lockfile.PnpmEcosystem,
			CompareAs:      lockfile.PnpmEcosystem,
			IsDirect:       false,
		},
	})
}

func TestParsePnpmLock_Tarball(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/pnpm/tarball.yaml"))
	packages, err := lockfile.ParsePnpmLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "@my-org/my-package",
			Version:        "3.2.3",
			PackageManager: models.Pnpm,
			TargetVersions: []string{"https://gitlab.my-org.org/api/v4/projects/1/packages/npm/@my-org/my-package/-/@my-org/my-package-3.2.3.tgz"},
			Ecosystem:      lockfile.PnpmEcosystem,
			CompareAs:      lockfile.PnpmEcosystem,
			Commit:         "",
			DepGroups:      []string{"dev"},
			IsDirect:       true,
		},
	})
}

func TestParsePnpmLock_Exotic(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/pnpm/exotic.yaml"))
	packages, err := lockfile.ParsePnpmLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "foo",
			Version:        "1.0.0",
			PackageManager: models.Pnpm,
			Ecosystem:      lockfile.PnpmEcosystem,
			CompareAs:      lockfile.PnpmEcosystem,
		},
		{
			Name:           "@foo/bar",
			Version:        "1.0.0",
			PackageManager: models.Pnpm,
			Ecosystem:      lockfile.PnpmEcosystem,
			CompareAs:      lockfile.PnpmEcosystem,
		},
		{
			Name:           "foo",
			Version:        "1.1.0",
			PackageManager: models.Pnpm,
			Ecosystem:      lockfile.PnpmEcosystem,
			CompareAs:      lockfile.PnpmEcosystem,
		},
		{
			Name:           "@foo/bar",
			Version:        "1.1.0",
			PackageManager: models.Pnpm,
			Ecosystem:      lockfile.PnpmEcosystem,
			CompareAs:      lockfile.PnpmEcosystem,
		},
		{
			Name:           "foo",
			Version:        "1.2.0",
			PackageManager: models.Pnpm,
			Ecosystem:      lockfile.PnpmEcosystem,
			CompareAs:      lockfile.PnpmEcosystem,
		},
		{
			Name:           "foo",
			Version:        "1.3.0",
			PackageManager: models.Pnpm,
			Ecosystem:      lockfile.PnpmEcosystem,
			CompareAs:      lockfile.PnpmEcosystem,
		},
		{
			Name:           "foo",
			Version:        "1.4.0",
			PackageManager: models.Pnpm,
			Ecosystem:      lockfile.PnpmEcosystem,
			CompareAs:      lockfile.PnpmEcosystem,
		},
	})
}

func TestParsePnpmLock_Commits(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/pnpm/commits.yaml"))
	packages, err := lockfile.ParsePnpmLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "my-bitbucket-package",
			Version:        "1.0.0",
			PackageManager: models.Pnpm,
			TargetVersions: []string{"ssh://git@bitbucket.org:my-org/my-bitbucket-package#main"},
			Ecosystem:      lockfile.PnpmEcosystem,
			CompareAs:      lockfile.PnpmEcosystem,
			Commit:         "6104ae42cd32c3d724036d3964678f197b2c9cdb",
			IsDirect:       true,
		},
		{
			Name:           "@my-scope/my-package",
			Version:        "1.0.0",
			PackageManager: models.Pnpm,
			TargetVersions: []string{"git@github.com:my-org/my-package.git"},
			Ecosystem:      lockfile.PnpmEcosystem,
			CompareAs:      lockfile.PnpmEcosystem,
			Commit:         "267087851ad5fac92a184749c27cd539e2fc862e",
			IsDirect:       true,
		},
		{
			Name:           "@my-scope/my-other-package",
			Version:        "1.0.0",
			PackageManager: models.Pnpm,
			Ecosystem:      lockfile.PnpmEcosystem,
			CompareAs:      lockfile.PnpmEcosystem,
			Commit:         "fbfc962ab51eb1d754749b68c064460221fbd689",
			IsDirect:       false,
		},
		{
			Name:           "faker-parser",
			Version:        "0.0.1",
			PackageManager: models.Pnpm,
			Ecosystem:      lockfile.PnpmEcosystem,
			CompareAs:      lockfile.PnpmEcosystem,
			Commit:         "d2dc42a9351d4d89ec48c525e34f612b6d77993f",
			IsDirect:       false,
		},
		{
			Name:           "mocks",
			Version:        "20.0.1",
			PackageManager: models.Pnpm,
			TargetVersions: []string{"github:my-org/mocks#main"},
			Ecosystem:      lockfile.PnpmEcosystem,
			CompareAs:      lockfile.PnpmEcosystem,
			Commit:         "590f321b4eb3f692bb211bd74e22947639a6f79d",
			IsDirect:       true,
		},
	})
}

func TestParsePnpmLock_Files(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/pnpm/files.yaml"))
	packages, err := lockfile.ParsePnpmLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "my-file-package",
			Version:        "0.0.0",
			PackageManager: models.Pnpm,
			TargetVersions: []string{"projects/package-a.tgz"},
			Ecosystem:      lockfile.NpmEcosystem,
			CompareAs:      lockfile.NpmEcosystem,
			Commit:         "",
			IsDirect:       true,
		},
		{
			Name:           "a-local-package",
			Version:        "1.0.0",
			PackageManager: models.Pnpm,
			Ecosystem:      lockfile.NpmEcosystem,
			CompareAs:      lockfile.NpmEcosystem,
			Commit:         "",
			IsDirect:       false,
		},
		{
			Name:           "a-nested-local-package",
			Version:        "1.0.0",
			PackageManager: models.Pnpm,
			Ecosystem:      lockfile.NpmEcosystem,
			CompareAs:      lockfile.NpmEcosystem,
			Commit:         "",
			IsDirect:       false,
		},
		{
			Name:           "one-up",
			Version:        "1.0.0",
			PackageManager: models.Pnpm,
			Ecosystem:      lockfile.NpmEcosystem,
			CompareAs:      lockfile.NpmEcosystem,
			Commit:         "",
			IsDirect:       false,
		},
		{
			Name:           "one-up-with-peer",
			Version:        "1.0.0",
			PackageManager: models.Pnpm,
			Ecosystem:      lockfile.NpmEcosystem,
			CompareAs:      lockfile.NpmEcosystem,
			Commit:         "",
			IsDirect:       false,
		},
	})
}
