package lockfile_test

import (
	"io/fs"
	"testing"

	"github.com/google/osv-scanner/pkg/lockfile"
)

func TestRequirementsTxtExtractor_ShouldExtract(t *testing.T) {
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
			path: "requirements.txt",
			want: true,
		},
		{
			name: "",
			path: "path/to/my/requirements.txt",
			want: true,
		},
		{
			name: "",
			path: "path/to/my/requirements.txt/file",
			want: false,
		},
		{
			name: "",
			path: "path/to/my/requirements.txt.file",
			want: false,
		},
		{
			name: "",
			path: "path.to.my.requirements.txt",
			want: true,
		},
		{
			name: "",
			path: "requirements-dev.txt",
			want: true,
		},
		{
			name: "",
			path: "requirements.dev.txt",
			want: true,
		},
		{
			name: "",
			path: "dev-requirements.txt",
			want: true,
		},
		{
			name: "",
			path: "requirements-ci.txt",
			want: true,
		},
		{
			name: "",
			path: "requirements.ci.txt",
			want: true,
		},
		{
			name: "",
			path: "ci-requirements.txt",
			want: true,
		},
		{
			name: "",
			path: "dev.txt",
			want: false,
		},
		{
			name: "",
			path: "ci.txt",
			want: false,
		},
		{
			name: "",
			path: "requirements",
			want: false,
		},
		{
			name: "",
			path: "requirements.json",
			want: false,
		},
		{
			name: "",
			path: "requirements/txt",
			want: false,
		},
		{
			name: "",
			path: "requirements/txt.txt",
			want: false,
		},
		{
			name: "",
			path: "path/requirements/txt.txt",
			want: false,
		},
		{
			name: "",
			path: "path/requirements/requirements.txt",
			want: true,
		},
		{
			name: "",
			path: "path/requirements/requirements-dev.txt",
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := lockfile.RequirementsTxtExtractor{}
			got := e.ShouldExtract(tt.path)
			if got != tt.want {
				t.Errorf("Extract() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseRequirementsTxt_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseRequirementsTxt("fixtures/pip/does-not-exist")

	expectErrIs(t, err, fs.ErrNotExist)
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
			DepGroups: []string{"one-package-unconstrained"},
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
			DepGroups: []string{"one-package-constrained"},
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
			DepGroups: []string{"multiple-packages-constrained"},
		},
		{
			Name:      "beautifulsoup4",
			Version:   "4.9.3",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			DepGroups: []string{"multiple-packages-constrained"},
		},
		{
			Name:      "boto3",
			Version:   "1.17.19",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			DepGroups: []string{"multiple-packages-constrained"},
		},
		{
			Name:      "botocore",
			Version:   "1.20.19",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			DepGroups: []string{"multiple-packages-constrained"},
		},
		{
			Name:      "certifi",
			Version:   "2020.12.5",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			DepGroups: []string{"multiple-packages-constrained"},
		},
		{
			Name:      "chardet",
			Version:   "4.0.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			DepGroups: []string{"multiple-packages-constrained"},
		},
		{
			Name:      "circus",
			Version:   "0.17.1",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			DepGroups: []string{"multiple-packages-constrained"},
		},
		{
			Name:      "click",
			Version:   "7.1.2",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			DepGroups: []string{"multiple-packages-constrained"},
		},
		{
			Name:      "django-debug-toolbar",
			Version:   "3.2.1",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			DepGroups: []string{"multiple-packages-constrained"},
		},
		{
			Name:      "django-filter",
			Version:   "2.4.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			DepGroups: []string{"multiple-packages-constrained"},
		},
		{
			Name:      "django-nose",
			Version:   "1.4.7",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			DepGroups: []string{"multiple-packages-constrained"},
		},
		{
			Name:      "django-storages",
			Version:   "1.11.1",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			DepGroups: []string{"multiple-packages-constrained"},
		},
		{
			Name:      "django",
			Version:   "2.2.24",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			DepGroups: []string{"multiple-packages-constrained"},
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
			DepGroups: []string{"multiple-packages-mixed"},
		},
		{
			Name:      "flask-cors",
			Version:   "0.0.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			DepGroups: []string{"multiple-packages-mixed"},
		},
		{
			Name:      "pandas",
			Version:   "0.23.4",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			DepGroups: []string{"multiple-packages-mixed"},
		},
		{
			Name:      "numpy",
			Version:   "1.16.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			DepGroups: []string{"multiple-packages-mixed"},
		},
		{
			Name:      "scikit-learn",
			Version:   "0.20.1",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			DepGroups: []string{"multiple-packages-mixed"},
		},
		{
			Name:      "sklearn",
			Version:   "0.0.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			DepGroups: []string{"multiple-packages-mixed"},
		},
		{
			Name:      "requests",
			Version:   "0.0.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			DepGroups: []string{"multiple-packages-mixed"},
		},
		{
			Name:      "gevent",
			Version:   "0.0.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			DepGroups: []string{"multiple-packages-mixed"},
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
			DepGroups: []string{"file-format-example"},
		},
		{
			Name:      "pytest-cov",
			Version:   "0.0.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			DepGroups: []string{"file-format-example"},
		},
		{
			Name:      "beautifulsoup4",
			Version:   "0.0.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			DepGroups: []string{"file-format-example"},
		},
		{
			Name:      "docopt",
			Version:   "0.6.1",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			DepGroups: []string{"file-format-example"},
		},
		{
			Name:      "keyring",
			Version:   "4.1.1",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			DepGroups: []string{"file-format-example"},
		},
		{
			Name:      "coverage",
			Version:   "0.0.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			DepGroups: []string{"file-format-example"},
		},
		{
			Name:      "mopidy-dirble",
			Version:   "1.1",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			DepGroups: []string{"file-format-example"},
		},
		{
			Name:      "rejected",
			Version:   "0.0.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			DepGroups: []string{"file-format-example"},
		},
		{
			Name:      "green",
			Version:   "0.0.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			DepGroups: []string{"file-format-example"},
		},
		{
			Name:      "django",
			Version:   "2.2.24",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			DepGroups: []string{"other-file"},
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
			DepGroups: []string{"with-added-support"},
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
			DepGroups: []string{"non-normalized-names"},
		},
		{
			Name:      "pillow",
			Version:   "1.0.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			DepGroups: []string{"non-normalized-names"},
		},
		{
			Name:      "twisted",
			Version:   "20.3.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			DepGroups: []string{"non-normalized-names"},
		},
	})
}

func TestParseRequirementsTxt_WithMultipleROptions(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseRequirementsTxt("fixtures/pip/with-multiple-r-options.txt")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "flask",
			Version:   "0.0.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			DepGroups: []string{"multiple-packages-mixed"},
		},
		{
			Name:      "flask-cors",
			Version:   "0.0.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			DepGroups: []string{"multiple-packages-mixed"},
		},
		{
			Name:      "pandas",
			Version:   "0.23.4",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			DepGroups: []string{"multiple-packages-mixed", "with-multiple-r-options"},
		},
		{
			Name:      "numpy",
			Version:   "1.16.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			DepGroups: []string{"multiple-packages-mixed"},
		},
		{
			Name:      "scikit-learn",
			Version:   "0.20.1",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			DepGroups: []string{"multiple-packages-mixed"},
		},
		{
			Name:      "sklearn",
			Version:   "0.0.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			DepGroups: []string{"multiple-packages-mixed"},
		},
		{
			Name:      "requests",
			Version:   "0.0.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			DepGroups: []string{"multiple-packages-mixed"},
		},
		{
			Name:      "gevent",
			Version:   "0.0.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			DepGroups: []string{"multiple-packages-mixed"},
		},
		{
			Name:      "requests",
			Version:   "1.2.3",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			DepGroups: []string{"with-multiple-r-options"},
		},
		{
			Name:      "django",
			Version:   "2.2.24",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			DepGroups: []string{"one-package-constrained"},
		},
	})
}

func TestParseRequirementsTxt_WithBadROption(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseRequirementsTxt("fixtures/pip/with-bad-r-option.txt")

	expectErrIs(t, err, fs.ErrNotExist)
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseRequirementsTxt_DuplicateROptions(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseRequirementsTxt("fixtures/pip/duplicate-r-dev.txt")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "django",
			Version:   "0.1.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			DepGroups: []string{"duplicate-r-base"},
		},
		{
			Name:      "pandas",
			Version:   "0.23.4",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			DepGroups: []string{"duplicate-r-dev"},
		},
		{
			Name:      "requests",
			Version:   "1.2.3",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			DepGroups: []string{"duplicate-r-test", "duplicate-r-dev"},
		},
		{
			Name:      "unittest",
			Version:   "1.0.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			DepGroups: []string{"duplicate-r-test"},
		},
	})
}

func TestParseRequirementsTxt_CyclicRSelf(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseRequirementsTxt("fixtures/pip/cyclic-r-self.txt")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "pandas",
			Version:   "0.23.4",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			DepGroups: []string{"cyclic-r-self"},
		},
		{
			Name:      "requests",
			Version:   "1.2.3",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			DepGroups: []string{"cyclic-r-self"},
		},
	})
}

func TestParseRequirementsTxt_CyclicRComplex(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseRequirementsTxt("fixtures/pip/cyclic-r-complex-1.txt")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "cyclic-r-complex",
			Version:   "1",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			DepGroups: []string{"cyclic-r-complex-1"},
		},
		{
			Name:      "cyclic-r-complex",
			Version:   "2",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			DepGroups: []string{"cyclic-r-complex-2"},
		},
		{
			Name:      "cyclic-r-complex",
			Version:   "3",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			DepGroups: []string{"cyclic-r-complex-3"},
		},
	})
}

func TestParseRequirementsTxt_WithPerRequirementOptions(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseRequirementsTxt("fixtures/pip/with-per-requirement-options.txt")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "boto3",
			Version:   "1.26.121",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			DepGroups: []string{"with-per-requirement-options"},
		},
		{
			Name:      "foo",
			Version:   "1.0.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			DepGroups: []string{"with-per-requirement-options"},
		},
		{
			Name:      "fooproject",
			Version:   "1.2",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			DepGroups: []string{"with-per-requirement-options"},
		},
		{
			Name:      "barproject",
			Version:   "1.2",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			DepGroups: []string{"with-per-requirement-options"},
		},
	})
}

func TestParseRequirementsTxt_LineContinuation(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseRequirementsTxt("fixtures/pip/line-continuation.txt")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "foo",
			Version:   "1.2.3",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			DepGroups: []string{"line-continuation"},
		},
		{
			Name:      "bar",
			Version:   "4.5\\\\",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			DepGroups: []string{"line-continuation"},
		},
		{
			Name:      "baz",
			Version:   "7.8.9",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			DepGroups: []string{"line-continuation"},
		},
		{
			Name:      "qux",
			Version:   "10.11.12",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			DepGroups: []string{"line-continuation"},
		},
	})
}
