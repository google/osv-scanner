package lockfile_test

import (
	"github.com/google/osv-scanner/pkg/lockfile"
	"testing"
)

func TestParseRequirementsTxt_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseRequirementsTxt("fixtures/pip/does-not-exist")

	expectErrContaining(t, err, "could not open")
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseRequirementsTxt_Empty(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseRequirementsTxt("fixtures/pip/empty.txt")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseRequirementsTxt_CommentsOnly(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseRequirementsTxt("fixtures/pip/only-comments.txt")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseRequirementsTxt_OneRequirementUnconstrained(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseRequirementsTxt("fixtures/pip/one-package-unconstrained.txt")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "flask",
			Version:   "0.0.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
		},
	})
}

func TestParseRequirementsTxt_OneRequirementConstrained(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseRequirementsTxt("fixtures/pip/one-package-constrained.txt")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "django",
			Version:   "2.2.24",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
		},
	})
}

func TestParseRequirementsTxt_MultipleRequirementsConstrained(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseRequirementsTxt("fixtures/pip/multiple-packages-constrained.txt")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "astroid",
			Version:   "2.5.1",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
		},
		{
			Name:      "beautifulsoup4",
			Version:   "4.9.3",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
		},
		{
			Name:      "boto3",
			Version:   "1.17.19",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
		},
		{
			Name:      "botocore",
			Version:   "1.20.19",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
		},
		{
			Name:      "certifi",
			Version:   "2020.12.5",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
		},
		{
			Name:      "chardet",
			Version:   "4.0.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
		},
		{
			Name:      "circus",
			Version:   "0.17.1",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
		},
		{
			Name:      "click",
			Version:   "7.1.2",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
		},
		{
			Name:      "django-debug-toolbar",
			Version:   "3.2.1",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
		},
		{
			Name:      "django-filter",
			Version:   "2.4.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
		},
		{
			Name:      "django-nose",
			Version:   "1.4.7",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
		},
		{
			Name:      "django-storages",
			Version:   "1.11.1",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
		},
		{
			Name:      "django",
			Version:   "2.2.24",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
		},
	})
}

func TestParseRequirementsTxt_MultipleRequirementsMixed(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseRequirementsTxt("fixtures/pip/multiple-packages-mixed.txt")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "flask",
			Version:   "0.0.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
		},
		{
			Name:      "flask-cors",
			Version:   "0.0.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
		},
		{
			Name:      "pandas",
			Version:   "0.23.4",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
		},
		{
			Name:      "numpy",
			Version:   "1.16.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
		},
		{
			Name:      "scikit-learn",
			Version:   "0.20.1",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
		},
		{
			Name:      "sklearn",
			Version:   "0.0.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
		},
		{
			Name:      "requests",
			Version:   "0.0.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
		},
		{
			Name:      "gevent",
			Version:   "0.0.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
		},
	})
}

func TestParseRequirementsTxt_FileFormatExample(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseRequirementsTxt("fixtures/pip/file-format-example.txt")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "pytest",
			Version:   "0.0.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
		},
		{
			Name:      "pytest-cov",
			Version:   "0.0.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
		},
		{
			Name:      "beautifulsoup4",
			Version:   "0.0.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
		},
		{
			Name:      "docopt",
			Version:   "0.6.1",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
		},
		{
			Name:      "keyring",
			Version:   "4.1.1",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
		},
		{
			Name:      "coverage",
			Version:   "0.0.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
		},
		{
			Name:      "mopidy-dirble",
			Version:   "1.1",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
		},
		{
			Name:      "rejected",
			Version:   "0.0.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
		},
		{
			Name:      "green",
			Version:   "0.0.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
		},
	})
}

func TestParseRequirementsTxt_WithAddedSupport(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseRequirementsTxt("fixtures/pip/with-added-support.txt")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "twisted",
			Version:   "20.3.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
		},
	})
}

func TestParseRequirementsTxt_NonNormalizedNames(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseRequirementsTxt("fixtures/pip/non-normalized-names.txt")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "zope-interface",
			Version:   "5.4.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
		},
		{
			Name:      "pillow",
			Version:   "1.0.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
		},
		{
			Name:      "twisted",
			Version:   "20.3.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
		},
	})
}
