package lockfile_test

import (
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
			want: false,
		},
	}
	for _, tt := range tests {
		tt := tt
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

	expectErrContaining(t, err, "no such file or directory")
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
			Source:    absPathNoErr("fixtures/pip/one-package-unconstrained.txt"),
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
			Source:    absPathNoErr("fixtures/pip/one-package-constrained.txt"),
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
			Source:    absPathNoErr("fixtures/pip/multiple-packages-constrained.txt"),
		},
		{
			Name:      "beautifulsoup4",
			Version:   "4.9.3",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			Source:    absPathNoErr("fixtures/pip/multiple-packages-constrained.txt"),
		},
		{
			Name:      "boto3",
			Version:   "1.17.19",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			Source:    absPathNoErr("fixtures/pip/multiple-packages-constrained.txt"),
		},
		{
			Name:      "botocore",
			Version:   "1.20.19",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			Source:    absPathNoErr("fixtures/pip/multiple-packages-constrained.txt"),
		},
		{
			Name:      "certifi",
			Version:   "2020.12.5",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			Source:    absPathNoErr("fixtures/pip/multiple-packages-constrained.txt"),
		},
		{
			Name:      "chardet",
			Version:   "4.0.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			Source:    absPathNoErr("fixtures/pip/multiple-packages-constrained.txt"),
		},
		{
			Name:      "circus",
			Version:   "0.17.1",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			Source:    absPathNoErr("fixtures/pip/multiple-packages-constrained.txt"),
		},
		{
			Name:      "click",
			Version:   "7.1.2",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			Source:    absPathNoErr("fixtures/pip/multiple-packages-constrained.txt"),
		},
		{
			Name:      "django-debug-toolbar",
			Version:   "3.2.1",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			Source:    absPathNoErr("fixtures/pip/multiple-packages-constrained.txt"),
		},
		{
			Name:      "django-filter",
			Version:   "2.4.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			Source:    absPathNoErr("fixtures/pip/multiple-packages-constrained.txt"),
		},
		{
			Name:      "django-nose",
			Version:   "1.4.7",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			Source:    absPathNoErr("fixtures/pip/multiple-packages-constrained.txt"),
		},
		{
			Name:      "django-storages",
			Version:   "1.11.1",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			Source:    absPathNoErr("fixtures/pip/multiple-packages-constrained.txt"),
		},
		{
			Name:      "django",
			Version:   "2.2.24",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			Source:    absPathNoErr("fixtures/pip/multiple-packages-constrained.txt"),
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
			Source:    absPathNoErr("fixtures/pip/multiple-packages-mixed.txt"),
		},
		{
			Name:      "flask-cors",
			Version:   "0.0.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			Source:    absPathNoErr("fixtures/pip/multiple-packages-mixed.txt"),
		},
		{
			Name:      "pandas",
			Version:   "0.23.4",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			Source:    absPathNoErr("fixtures/pip/multiple-packages-mixed.txt"),
		},
		{
			Name:      "numpy",
			Version:   "1.16.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			Source:    absPathNoErr("fixtures/pip/multiple-packages-mixed.txt"),
		},
		{
			Name:      "scikit-learn",
			Version:   "0.20.1",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			Source:    absPathNoErr("fixtures/pip/multiple-packages-mixed.txt"),
		},
		{
			Name:      "sklearn",
			Version:   "0.0.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			Source:    absPathNoErr("fixtures/pip/multiple-packages-mixed.txt"),
		},
		{
			Name:      "requests",
			Version:   "0.0.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			Source:    absPathNoErr("fixtures/pip/multiple-packages-mixed.txt"),
		},
		{
			Name:      "gevent",
			Version:   "0.0.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			Source:    absPathNoErr("fixtures/pip/multiple-packages-mixed.txt"),
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
			Source:    absPathNoErr("fixtures/pip/file-format-example.txt"),
		},
		{
			Name:      "pytest-cov",
			Version:   "0.0.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			Source:    absPathNoErr("fixtures/pip/file-format-example.txt"),
		},
		{
			Name:      "beautifulsoup4",
			Version:   "0.0.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			Source:    absPathNoErr("fixtures/pip/file-format-example.txt"),
		},
		{
			Name:      "docopt",
			Version:   "0.6.1",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			Source:    absPathNoErr("fixtures/pip/file-format-example.txt"),
		},
		{
			Name:      "keyring",
			Version:   "4.1.1",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			Source:    absPathNoErr("fixtures/pip/file-format-example.txt"),
		},
		{
			Name:      "coverage",
			Version:   "0.0.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			Source:    absPathNoErr("fixtures/pip/file-format-example.txt"),
		},
		{
			Name:      "mopidy-dirble",
			Version:   "1.1",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			Source:    absPathNoErr("fixtures/pip/file-format-example.txt"),
		},
		{
			Name:      "rejected",
			Version:   "0.0.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			Source:    absPathNoErr("fixtures/pip/file-format-example.txt"),
		},
		{
			Name:      "green",
			Version:   "0.0.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			Source:    absPathNoErr("fixtures/pip/file-format-example.txt"),
		},
		{
			Name:      "django",
			Version:   "2.2.24",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			Source:    absPathNoErr("fixtures/pip/other-file.txt"),
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
			Source:    absPathNoErr("fixtures/pip/with-added-support.txt"),
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
			Source:    absPathNoErr("fixtures/pip/non-normalized-names.txt"),
		},
		{
			Name:      "pillow",
			Version:   "1.0.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			Source:    absPathNoErr("fixtures/pip/non-normalized-names.txt"),
		},
		{
			Name:      "twisted",
			Version:   "20.3.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			Source:    absPathNoErr("fixtures/pip/non-normalized-names.txt"),
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
			Source:    absPathNoErr("fixtures/pip/multiple-packages-mixed.txt"),
		},
		{
			Name:      "flask-cors",
			Version:   "0.0.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			Source:    absPathNoErr("fixtures/pip/multiple-packages-mixed.txt"),
		},
		{
			Name:      "pandas",
			Version:   "0.23.4",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			Source:    absPathNoErr("fixtures/pip/with-multiple-r-options.txt"),
		},
		{
			Name:      "numpy",
			Version:   "1.16.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			Source:    absPathNoErr("fixtures/pip/multiple-packages-mixed.txt"),
		},
		{
			Name:      "scikit-learn",
			Version:   "0.20.1",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			Source:    absPathNoErr("fixtures/pip/multiple-packages-mixed.txt"),
		},
		{
			Name:      "sklearn",
			Version:   "0.0.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			Source:    absPathNoErr("fixtures/pip/multiple-packages-mixed.txt"),
		},
		{
			Name:      "requests",
			Version:   "0.0.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			Source:    absPathNoErr("fixtures/pip/multiple-packages-mixed.txt"),
		},
		{
			Name:      "gevent",
			Version:   "0.0.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			Source:    absPathNoErr("fixtures/pip/multiple-packages-mixed.txt"),
		},
		{
			Name:      "requests",
			Version:   "1.2.3",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			Source:    absPathNoErr("fixtures/pip/with-multiple-r-options.txt"),
		},
		{
			Name:      "django",
			Version:   "2.2.24",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			Source:    absPathNoErr("fixtures/pip/one-package-constrained.txt"),
		},
	})
}

func TestParseRequirementsTxt_WithBadROption(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseRequirementsTxt("fixtures/pip/with-bad-r-option.txt")

	expectErrContaining(t, err, "no such file or directory")
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
			Source:    absPathNoErr("fixtures/pip/duplicate-r-base.txt"),
		},
		{
			Name:      "pandas",
			Version:   "0.23.4",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			Source:    absPathNoErr("fixtures/pip/duplicate-r-dev.txt"),
		},
		{
			Name:      "requests",
			Version:   "1.2.3",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			Source:    absPathNoErr("fixtures/pip/duplicate-r-dev.txt"),
		},
		{
			Name:      "unittest",
			Version:   "1.0.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			Source:    absPathNoErr("fixtures/pip/duplicate-r-test.txt"),
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
			Source:    absPathNoErr("fixtures/pip/cyclic-r-self.txt"),
		},
		{
			Name:      "requests",
			Version:   "1.2.3",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			Source:    absPathNoErr("fixtures/pip/cyclic-r-self.txt"),
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
			Source:    absPathNoErr("fixtures/pip/cyclic-r-complex-1.txt"),
		},
		{
			Name:      "cyclic-r-complex",
			Version:   "2",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			Source:    absPathNoErr("fixtures/pip/cyclic-r-complex-2.txt"),
		},
		{
			Name:      "cyclic-r-complex",
			Version:   "3",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			Source:    absPathNoErr("fixtures/pip/cyclic-r-complex-3.txt"),
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
			Source:    absPathNoErr("fixtures/pip/with-per-requirement-options.txt"),
		},
		{
			Name:      "foo",
			Version:   "1.0.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			Source:    absPathNoErr("fixtures/pip/with-per-requirement-options.txt"),
		},
		{
			Name:      "fooproject",
			Version:   "1.2",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			Source:    absPathNoErr("fixtures/pip/with-per-requirement-options.txt"),
		},
		{
			Name:      "barproject",
			Version:   "1.2",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			Source:    absPathNoErr("fixtures/pip/with-per-requirement-options.txt"),
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
			Source:    absPathNoErr("fixtures/pip/line-continuation.txt"),
		},
		{
			Name:      "bar",
			Version:   "4.5\\\\",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			Source:    absPathNoErr("fixtures/pip/line-continuation.txt"),
		},
		{
			Name:      "baz",
			Version:   "7.8.9",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			Source:    absPathNoErr("fixtures/pip/line-continuation.txt"),
		},
		{
			Name:      "qux",
			Version:   "10.11.12",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			Source:    absPathNoErr("fixtures/pip/line-continuation.txt"),
		},
	})
}
