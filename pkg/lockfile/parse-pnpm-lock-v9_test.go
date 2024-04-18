package lockfile_test

import (
	"testing"

	"github.com/google/osv-scanner/pkg/lockfile"
)

func TestParsePnpmLock_v9_NoPackages(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePnpmLock("fixtures/pnpm/no-packages.v9.yaml")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParsePnpmLock_v9_OnePackage(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePnpmLock("fixtures/pnpm/one-package.v9.yaml")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "acorn",
			Version:   "8.11.3",
			Ecosystem: lockfile.PnpmEcosystem,
			CompareAs: lockfile.PnpmEcosystem,
		},
	})
}

func TestParsePnpmLock_v9_OnePackageDev(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePnpmLock("fixtures/pnpm/one-package-dev.v9.yaml")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "acorn",
			Version:   "8.7.0",
			Ecosystem: lockfile.PnpmEcosystem,
			CompareAs: lockfile.PnpmEcosystem,
		},
	})
}

func TestParsePnpmLock_v9_ScopedPackages(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePnpmLock("fixtures/pnpm/scoped-packages.v9.yaml")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "@typescript-eslint/types",
			Version:   "5.13.0",
			Ecosystem: lockfile.PnpmEcosystem,
			CompareAs: lockfile.PnpmEcosystem,
		},
	})
}

func TestParsePnpmLock_v9_PeerDependencies(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePnpmLock("fixtures/pnpm/peer-dependencies.v9.yaml")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "acorn-jsx",
			Version:   "5.3.2",
			Ecosystem: lockfile.PnpmEcosystem,
			CompareAs: lockfile.PnpmEcosystem,
		},
		{
			Name:      "acorn",
			Version:   "8.11.3",
			Ecosystem: lockfile.PnpmEcosystem,
			CompareAs: lockfile.PnpmEcosystem,
		},
	})
}

func TestParsePnpmLock_v9_PeerDependenciesAdvanced(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePnpmLock("fixtures/pnpm/peer-dependencies-advanced.v9.yaml")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "@typescript-eslint/eslint-plugin",
			Version:   "5.13.0",
			Ecosystem: lockfile.PnpmEcosystem,
			CompareAs: lockfile.PnpmEcosystem,
		},
		{
			Name:      "@typescript-eslint/parser",
			Version:   "5.13.0",
			Ecosystem: lockfile.PnpmEcosystem,
			CompareAs: lockfile.PnpmEcosystem,
		},
		{
			Name:      "@typescript-eslint/type-utils",
			Version:   "5.13.0",
			Ecosystem: lockfile.PnpmEcosystem,
			CompareAs: lockfile.PnpmEcosystem,
		},
		{
			Name:      "@typescript-eslint/types",
			Version:   "5.13.0",
			Ecosystem: lockfile.PnpmEcosystem,
			CompareAs: lockfile.PnpmEcosystem,
		},
		{
			Name:      "@typescript-eslint/typescript-estree",
			Version:   "5.13.0",
			Ecosystem: lockfile.PnpmEcosystem,
			CompareAs: lockfile.PnpmEcosystem,
		},
		{
			Name:      "@typescript-eslint/utils",
			Version:   "5.13.0",
			Ecosystem: lockfile.PnpmEcosystem,
			CompareAs: lockfile.PnpmEcosystem,
		},
		{
			Name:      "eslint-utils",
			Version:   "3.0.0",
			Ecosystem: lockfile.PnpmEcosystem,
			CompareAs: lockfile.PnpmEcosystem,
		},
		{
			Name:      "eslint",
			Version:   "8.10.0",
			Ecosystem: lockfile.PnpmEcosystem,
			CompareAs: lockfile.PnpmEcosystem,
		},
		{
			Name:      "tsutils",
			Version:   "3.21.0",
			Ecosystem: lockfile.PnpmEcosystem,
			CompareAs: lockfile.PnpmEcosystem,
		},
	})
}

func TestParsePnpmLock_v9_MultipleVersions(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePnpmLock("fixtures/pnpm/multiple-versions.v9.yaml")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "uuid",
			Version:   "3.3.2",
			Ecosystem: lockfile.PnpmEcosystem,
			CompareAs: lockfile.PnpmEcosystem,
		},
		{
			Name:      "uuid",
			Version:   "8.3.2",
			Ecosystem: lockfile.PnpmEcosystem,
			CompareAs: lockfile.PnpmEcosystem,
		},
		{
			Name:      "xmlbuilder",
			Version:   "9.0.7",
			Ecosystem: lockfile.PnpmEcosystem,
			CompareAs: lockfile.PnpmEcosystem,
		},
	})
}

func TestParsePnpmLock_v9_Commits(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePnpmLock("fixtures/pnpm/commits.v9.yaml")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "my-bitbucket-package",
			Version:   "1.0.0",
			Ecosystem: lockfile.PnpmEcosystem,
			CompareAs: lockfile.PnpmEcosystem,
			Commit:    "6104ae42cd32c3d724036d3964678f197b2c9cdb",
		},
		{
			Name:      "@my-scope/my-package",
			Version:   "1.0.0",
			Ecosystem: lockfile.PnpmEcosystem,
			CompareAs: lockfile.PnpmEcosystem,
			Commit:    "267087851ad5fac92a184749c27cd539e2fc862e",
		},
		{
			Name:      "@my-scope/my-other-package",
			Version:   "1.0.0",
			Ecosystem: lockfile.PnpmEcosystem,
			CompareAs: lockfile.PnpmEcosystem,
			Commit:    "fbfc962ab51eb1d754749b68c064460221fbd689",
		},
		{
			Name:      "faker-parser",
			Version:   "0.0.1",
			Ecosystem: lockfile.PnpmEcosystem,
			CompareAs: lockfile.PnpmEcosystem,
			Commit:    "d2dc42a9351d4d89ec48c525e34f612b6d77993f",
		},
		{
			Name:      "mocks",
			Version:   "20.0.1",
			Ecosystem: lockfile.PnpmEcosystem,
			CompareAs: lockfile.PnpmEcosystem,
			Commit:    "590f321b4eb3f692bb211bd74e22947639a6f79d",
		},
	})
}
