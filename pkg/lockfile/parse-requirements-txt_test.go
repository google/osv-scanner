package lockfile_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/osv-scanner/pkg/models"

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
			path: "requirements3.txt",
			want: true,
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
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/pip/one-package-unconstrained.txt"))
	packages, err := lockfile.ParseRequirementsTxt(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "flask",
			Version:   "",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 1, End: 1},
				Column:   models.Position{Start: 1, End: 6},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 1, End: 1},
				Column:   models.Position{Start: 1, End: 6},
				Filename: path,
			},
			DepGroups: []string{"one-package-unconstrained"},
		},
	})
}

func TestParseRequirementsTxt_OneRequirementConstrained(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/pip/one-package-constrained.txt"))
	packages, err := lockfile.ParseRequirementsTxt(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "django",
			Version:   "2.2.24",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 1, End: 1},
				Column:   models.Position{Start: 1, End: 15},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 1, End: 1},
				Column:   models.Position{Start: 1, End: 7},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 1, End: 1},
				Column:   models.Position{Start: 9, End: 15},
				Filename: path,
			},
			DepGroups: []string{"one-package-constrained"},
		},
	})
}

func TestParseRequirementsTxt_MultipleRequirementsConstrained(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/pip/multiple-packages-constrained.txt"))
	packages, err := lockfile.ParseRequirementsTxt(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "astroid",
			Version:   "2.5.1",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 1, End: 1},
				Column:   models.Position{Start: 1, End: 15},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 1, End: 1},
				Column:   models.Position{Start: 1, End: 8},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 1, End: 1},
				Column:   models.Position{Start: 10, End: 15},
				Filename: path,
			},
			DepGroups: []string{"multiple-packages-constrained"},
		},
		{
			Name:      "beautifulsoup4",
			Version:   "4.9.3",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 3, End: 3},
				Column:   models.Position{Start: 1, End: 22},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 3, End: 3},
				Column:   models.Position{Start: 1, End: 15},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 3, End: 3},
				Column:   models.Position{Start: 17, End: 22},
				Filename: path,
			},
			DepGroups: []string{"multiple-packages-constrained"},
		},
		{
			Name:      "boto3",
			Version:   "1.17.19",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 1, End: 15},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 1, End: 6},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 8, End: 15},
				Filename: path,
			},
			DepGroups: []string{"multiple-packages-constrained"},
		},
		{
			Name:      "botocore",
			Version:   "1.20.19",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 7, End: 7},
				Column:   models.Position{Start: 1, End: 18},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 7, End: 7},
				Column:   models.Position{Start: 1, End: 9},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 7, End: 7},
				Column:   models.Position{Start: 11, End: 18},
				Filename: path,
			},
			DepGroups: []string{"multiple-packages-constrained"},
		},
		{
			Name:      "certifi",
			Version:   "2020.12.5",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 11, End: 11},
				Column:   models.Position{Start: 1, End: 19},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 11, End: 11},
				Column:   models.Position{Start: 1, End: 8},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 11, End: 11},
				Column:   models.Position{Start: 10, End: 19},
				Filename: path,
			},
			DepGroups: []string{"multiple-packages-constrained"},
		},
		{
			Name:      "chardet",
			Version:   "4.0.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 13, End: 13},
				Column:   models.Position{Start: 1, End: 15},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 13, End: 13},
				Column:   models.Position{Start: 1, End: 8},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 13, End: 13},
				Column:   models.Position{Start: 10, End: 15},
				Filename: path,
			},
			DepGroups: []string{"multiple-packages-constrained"},
		},
		{
			Name:      "circus",
			Version:   "0.17.1",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 15, End: 15},
				Column:   models.Position{Start: 1, End: 15},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 15, End: 15},
				Column:   models.Position{Start: 1, End: 7},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 15, End: 15},
				Column:   models.Position{Start: 9, End: 15},
				Filename: path,
			},
			DepGroups: []string{"multiple-packages-constrained"},
		},
		{
			Name:      "click",
			Version:   "7.1.2",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 17, End: 17},
				Column:   models.Position{Start: 1, End: 13},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 17, End: 17},
				Column:   models.Position{Start: 1, End: 6},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 17, End: 17},
				Column:   models.Position{Start: 8, End: 13},
				Filename: path,
			},
			DepGroups: []string{"multiple-packages-constrained"},
		},
		{
			Name:      "django-debug-toolbar",
			Version:   "3.2.1",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 19, End: 19},
				Column:   models.Position{Start: 1, End: 28},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 19, End: 19},
				Column:   models.Position{Start: 1, End: 21},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 19, End: 19},
				Column:   models.Position{Start: 23, End: 28},
				Filename: path,
			},
			DepGroups: []string{"multiple-packages-constrained"},
		},
		{
			Name:      "django-filter",
			Version:   "2.4.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 21, End: 21},
				Column:   models.Position{Start: 1, End: 21},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 21, End: 21},
				Column:   models.Position{Start: 1, End: 14},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 21, End: 21},
				Column:   models.Position{Start: 16, End: 21},
				Filename: path,
			},
			DepGroups: []string{"multiple-packages-constrained"},
		},
		{
			Name:      "django-nose",
			Version:   "1.4.7",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 23, End: 23},
				Column:   models.Position{Start: 1, End: 19},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 23, End: 23},
				Column:   models.Position{Start: 1, End: 12},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 23, End: 23},
				Column:   models.Position{Start: 14, End: 19},
				Filename: path,
			},
			DepGroups: []string{"multiple-packages-constrained"},
		},
		{
			Name:      "django-storages",
			Version:   "1.11.1",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 25, End: 25},
				Column:   models.Position{Start: 1, End: 24},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 25, End: 25},
				Column:   models.Position{Start: 1, End: 16},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 25, End: 25},
				Column:   models.Position{Start: 18, End: 24},
				Filename: path,
			},
			DepGroups: []string{"multiple-packages-constrained"},
		},
		{
			Name:      "django",
			Version:   "2.2.24",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 27, End: 27},
				Column:   models.Position{Start: 1, End: 15},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 27, End: 27},
				Column:   models.Position{Start: 1, End: 7},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 27, End: 27},
				Column:   models.Position{Start: 9, End: 15},
				Filename: path,
			},
			DepGroups: []string{"multiple-packages-constrained"},
		},
	})
}

func TestParseRequirementsTxt_MultipleRequirementsMixed(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/pip/multiple-packages-mixed.txt"))
	packages, err := lockfile.ParseRequirementsTxt(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "flask",
			Version:   "",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 1, End: 1},
				Column:   models.Position{Start: 1, End: 6},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 1, End: 1},
				Column:   models.Position{Start: 1, End: 6},
				Filename: path,
			},
			DepGroups: []string{"multiple-packages-mixed"},
		},
		{
			Name:      "flask-cors",
			Version:   "",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 2, End: 2},
				Column:   models.Position{Start: 1, End: 11},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 2, End: 2},
				Column:   models.Position{Start: 1, End: 11},
				Filename: path,
			},
			DepGroups: []string{"multiple-packages-mixed"},
		},
		{
			Name:      "pandas",
			Version:   "0.23.4",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 3, End: 3},
				Column:   models.Position{Start: 1, End: 15},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 3, End: 3},
				Column:   models.Position{Start: 1, End: 7},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 3, End: 3},
				Column:   models.Position{Start: 9, End: 15},
				Filename: path,
			},
			DepGroups: []string{"multiple-packages-mixed"},
		},
		{
			Name:      "numpy",
			Version:   "1.16.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 4, End: 4},
				Column:   models.Position{Start: 1, End: 14},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 4, End: 4},
				Column:   models.Position{Start: 1, End: 6},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 4, End: 4},
				Column:   models.Position{Start: 8, End: 14},
				Filename: path,
			},
			DepGroups: []string{"multiple-packages-mixed"},
		},
		{
			Name:      "scikit-learn",
			Version:   "0.20.1",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 1, End: 21},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 1, End: 13},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 15, End: 21},
				Filename: path,
			},
			DepGroups: []string{"multiple-packages-mixed"},
		},
		{
			Name:      "sklearn",
			Version:   "",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 6, End: 6},
				Column:   models.Position{Start: 1, End: 8},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 6, End: 6},
				Column:   models.Position{Start: 1, End: 8},
				Filename: path,
			},
			DepGroups: []string{"multiple-packages-mixed"},
		},
		{
			Name:      "requests",
			Version:   "",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 7, End: 7},
				Column:   models.Position{Start: 1, End: 9},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 7, End: 7},
				Column:   models.Position{Start: 1, End: 9},
				Filename: path,
			},
			DepGroups: []string{"multiple-packages-mixed"},
		},
		{
			Name:      "gevent",
			Version:   "",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 8, End: 8},
				Column:   models.Position{Start: 1, End: 7},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 8, End: 8},
				Column:   models.Position{Start: 1, End: 7},
				Filename: path,
			},
			DepGroups: []string{"multiple-packages-mixed"},
		},
	})
}

func TestParseRequirementsTxt_FileFormatExample(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	sourcePath := filepath.FromSlash(filepath.Join(dir, "fixtures/pip/file-format-example.txt"))
	otherPath := filepath.FromSlash(filepath.Join(dir, "fixtures/pip/other-file.txt"))
	packages, err := lockfile.ParseRequirementsTxt(sourcePath)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "pytest",
			Version:   "",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 3, End: 3},
				Column:   models.Position{Start: 1, End: 7},
				Filename: sourcePath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 3, End: 3},
				Column:   models.Position{Start: 1, End: 7},
				Filename: sourcePath,
			},
			DepGroups: []string{"file-format-example"},
		},
		{
			Name:      "pytest-cov",
			Version:   "",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 4, End: 4},
				Column:   models.Position{Start: 1, End: 11},
				Filename: sourcePath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 4, End: 4},
				Column:   models.Position{Start: 1, End: 11},
				Filename: sourcePath,
			},
			DepGroups: []string{"file-format-example"},
		},
		{
			Name:      "beautifulsoup4",
			Version:   "",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 1, End: 15},
				Filename: sourcePath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 1, End: 15},
				Filename: sourcePath,
			},
			DepGroups: []string{"file-format-example"},
		},
		{
			Name:      "docopt",
			Version:   "0.6.1",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 9, End: 9},
				Column:   models.Position{Start: 1, End: 70},
				Filename: sourcePath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 9, End: 9},
				Column:   models.Position{Start: 1, End: 7},
				Filename: sourcePath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 9, End: 9},
				Column:   models.Position{Start: 11, End: 16},
				Filename: sourcePath,
			},
			DepGroups: []string{"file-format-example"},
		},
		{
			Name:      "keyring",
			Version:   "4.1.1",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 10, End: 10},
				Column:   models.Position{Start: 1, End: 52},
				Filename: sourcePath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 10, End: 10},
				Column:   models.Position{Start: 1, End: 8},
				Filename: sourcePath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 10, End: 10},
				Column:   models.Position{Start: 12, End: 17},
				Filename: sourcePath,
			},
			DepGroups: []string{"file-format-example"},
		},
		{
			Name:      "coverage",
			Version:   "",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 11, End: 11},
				Column:   models.Position{Start: 1, End: 77},
				Filename: sourcePath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 11, End: 11},
				Column:   models.Position{Start: 1, End: 9},
				Filename: sourcePath,
			},
			DepGroups: []string{"file-format-example"},
		},
		{
			Name:      "mopidy-dirble",
			Version:   "1.1",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 12, End: 12},
				Column:   models.Position{Start: 1, End: 73},
				Filename: sourcePath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 12, End: 12},
				Column:   models.Position{Start: 1, End: 14},
				Filename: sourcePath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 12, End: 12},
				Column:   models.Position{Start: 18, End: 21},
				Filename: sourcePath,
			},
			DepGroups: []string{"file-format-example"},
		},
		{
			Name:      "rejected",
			Version:   "",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 23, End: 23},
				Column:   models.Position{Start: 1, End: 9},
				Filename: sourcePath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 23, End: 23},
				Column:   models.Position{Start: 1, End: 9},
				Filename: sourcePath,
			},
			DepGroups: []string{"file-format-example"},
		},
		{
			Name:      "green",
			Version:   "",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 24, End: 24},
				Column:   models.Position{Start: 1, End: 6},
				Filename: sourcePath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 24, End: 24},
				Column:   models.Position{Start: 1, End: 6},
				Filename: sourcePath,
			},
			DepGroups: []string{"file-format-example"},
		},
		{
			Name:      "django",
			Version:   "2.2.24",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 1, End: 1},
				Column:   models.Position{Start: 1, End: 15},
				Filename: otherPath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 1, End: 1},
				Column:   models.Position{Start: 1, End: 7},
				Filename: otherPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 1, End: 1},
				Column:   models.Position{Start: 9, End: 15},
				Filename: otherPath,
			},
			DepGroups: []string{"other-file"},
		},
	})
}

func TestParseRequirementsTxt_WithAddedSupport(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/pip/with-added-support.txt"))
	packages, err := lockfile.ParseRequirementsTxt(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "twisted",
			Version:   "20.3.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 1, End: 1},
				Column:   models.Position{Start: 1, End: 23},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 1, End: 1},
				Column:   models.Position{Start: 1, End: 15},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 1, End: 1},
				Column:   models.Position{Start: 17, End: 23},
				Filename: path,
			},
			DepGroups: []string{"with-added-support"},
		},
	})
}

func TestParseRequirementsTxt_NonNormalizedNames(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/pip/non-normalized-names.txt"))
	packages, err := lockfile.ParseRequirementsTxt(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "zope-interface",
			Version:   "5.4.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 1, End: 1},
				Column:   models.Position{Start: 1, End: 22},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 1, End: 1},
				Column:   models.Position{Start: 1, End: 15},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 1, End: 1},
				Column:   models.Position{Start: 17, End: 22},
				Filename: path,
			},
			DepGroups: []string{"non-normalized-names"},
		},
		{
			Name:      "pillow",
			Version:   "1.0.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 6, End: 6},
				Column:   models.Position{Start: 1, End: 14},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 6, End: 6},
				Column:   models.Position{Start: 1, End: 7},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 6, End: 6},
				Column:   models.Position{Start: 9, End: 14},
				Filename: path,
			},
			DepGroups: []string{"non-normalized-names"},
		},
		{
			Name:      "twisted",
			Version:   "20.3.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 8, End: 8},
				Column:   models.Position{Start: 1, End: 23},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 8, End: 8},
				Column:   models.Position{Start: 1, End: 15},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 8, End: 8},
				Column:   models.Position{Start: 17, End: 23},
				Filename: path,
			},
			DepGroups: []string{"non-normalized-names"},
		},
	})
}

func TestParseRequirementsTxt_WithMultipleROptions(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	sourcePath := filepath.FromSlash(filepath.Join(dir, "fixtures/pip/with-multiple-r-options.txt"))
	onePackagePath := filepath.FromSlash(filepath.Join(dir, "fixtures/pip/one-package-constrained.txt"))
	multiplePackagesPath := filepath.FromSlash(filepath.Join(dir, "fixtures/pip/multiple-packages-mixed.txt"))
	packages, err := lockfile.ParseRequirementsTxt(sourcePath)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "flask",
			Version:   "",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 1, End: 1},
				Column:   models.Position{Start: 1, End: 6},
				Filename: multiplePackagesPath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 1, End: 1},
				Column:   models.Position{Start: 1, End: 6},
				Filename: multiplePackagesPath,
			},
			DepGroups: []string{"multiple-packages-mixed"},
		},
		{
			Name:      "flask-cors",
			Version:   "",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 2, End: 2},
				Column:   models.Position{Start: 1, End: 11},
				Filename: multiplePackagesPath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 2, End: 2},
				Column:   models.Position{Start: 1, End: 11},
				Filename: multiplePackagesPath,
			},
			DepGroups: []string{"multiple-packages-mixed"},
		},
		{
			Name:      "pandas",
			Version:   "0.23.4",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 3, End: 3},
				Column:   models.Position{Start: 1, End: 15},
				Filename: multiplePackagesPath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 3, End: 3},
				Column:   models.Position{Start: 1, End: 7},
				Filename: multiplePackagesPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 3, End: 3},
				Column:   models.Position{Start: 9, End: 15},
				Filename: multiplePackagesPath,
			},
			DepGroups: []string{"multiple-packages-mixed", "with-multiple-r-options"},
		},
		{
			Name:      "numpy",
			Version:   "1.16.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 4, End: 4},
				Column:   models.Position{Start: 1, End: 14},
				Filename: multiplePackagesPath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 4, End: 4},
				Column:   models.Position{Start: 1, End: 6},
				Filename: multiplePackagesPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 4, End: 4},
				Column:   models.Position{Start: 8, End: 14},
				Filename: multiplePackagesPath,
			},
			DepGroups: []string{"multiple-packages-mixed"},
		},
		{
			Name:      "scikit-learn",
			Version:   "0.20.1",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 1, End: 21},
				Filename: multiplePackagesPath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 1, End: 13},
				Filename: multiplePackagesPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 15, End: 21},
				Filename: multiplePackagesPath,
			},
			DepGroups: []string{"multiple-packages-mixed"},
		},
		{
			Name:      "sklearn",
			Version:   "",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 6, End: 6},
				Column:   models.Position{Start: 1, End: 8},
				Filename: multiplePackagesPath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 6, End: 6},
				Column:   models.Position{Start: 1, End: 8},
				Filename: multiplePackagesPath,
			},
			DepGroups: []string{"multiple-packages-mixed"},
		},
		{
			Name:      "requests",
			Version:   "",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 7, End: 7},
				Column:   models.Position{Start: 1, End: 9},
				Filename: multiplePackagesPath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 7, End: 7},
				Column:   models.Position{Start: 1, End: 9},
				Filename: multiplePackagesPath,
			},
			DepGroups: []string{"multiple-packages-mixed"},
		},
		{
			Name:      "gevent",
			Version:   "",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 8, End: 8},
				Column:   models.Position{Start: 1, End: 7},
				Filename: multiplePackagesPath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 8, End: 8},
				Column:   models.Position{Start: 1, End: 7},
				Filename: multiplePackagesPath,
			},
			DepGroups: []string{"multiple-packages-mixed"},
		},
		{
			Name:      "requests",
			Version:   "1.2.3",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 4, End: 4},
				Column:   models.Position{Start: 1, End: 16},
				Filename: sourcePath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 4, End: 4},
				Column:   models.Position{Start: 1, End: 9},
				Filename: sourcePath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 4, End: 4},
				Column:   models.Position{Start: 11, End: 16},
				Filename: sourcePath,
			},
			DepGroups: []string{"with-multiple-r-options"},
		},
		{
			Name:      "django",
			Version:   "2.2.24",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 1, End: 1},
				Column:   models.Position{Start: 1, End: 15},
				Filename: onePackagePath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 1, End: 1},
				Column:   models.Position{Start: 1, End: 7},
				Filename: onePackagePath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 1, End: 1},
				Column:   models.Position{Start: 9, End: 15},
				Filename: onePackagePath,
			},
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

func TestParseRequirementsTxt_WithURLROption(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/pip/with-url-r-option.txt"))
	packages, err := lockfile.ParseRequirementsTxt(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "requests",
			Version:   "1.2.3",
			Commit:    "",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 1, End: 1},
				Column:   models.Position{Start: 1, End: 16},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 1, End: 1},
				Column:   models.Position{Start: 1, End: 9},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 1, End: 1},
				Column:   models.Position{Start: 11, End: 16},
				Filename: path,
			},
			DepGroups: []string{"with-url-r-option"},
		},
	})
}

func TestParseRequirementsTxt_DuplicateROptions(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	sourcePath := filepath.FromSlash(filepath.Join(dir, "fixtures/pip/duplicate-r-dev.txt"))
	basePath := filepath.FromSlash(filepath.Join(dir, "fixtures/pip/duplicate-r-base.txt"))
	testPath := filepath.FromSlash(filepath.Join(dir, "fixtures/pip/duplicate-r-test.txt"))
	packages, err := lockfile.ParseRequirementsTxt(sourcePath)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "django",
			Version:   "0.1.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 1, End: 1},
				Column:   models.Position{Start: 1, End: 14},
				Filename: basePath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 1, End: 1},
				Column:   models.Position{Start: 1, End: 7},
				Filename: basePath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 1, End: 1},
				Column:   models.Position{Start: 9, End: 14},
				Filename: basePath,
			},
			DepGroups: []string{"duplicate-r-base"},
		},
		{
			Name:      "pandas",
			Version:   "0.23.4",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 4, End: 4},
				Column:   models.Position{Start: 1, End: 15},
				Filename: sourcePath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 4, End: 4},
				Column:   models.Position{Start: 1, End: 7},
				Filename: sourcePath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 4, End: 4},
				Column:   models.Position{Start: 9, End: 15},
				Filename: sourcePath,
			},
			DepGroups: []string{"duplicate-r-dev"},
		},
		{
			Name:      "requests",
			Version:   "1.2.3",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 3, End: 3},
				Column:   models.Position{Start: 1, End: 16},
				Filename: testPath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 3, End: 3},
				Column:   models.Position{Start: 1, End: 9},
				Filename: testPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 3, End: 3},
				Column:   models.Position{Start: 11, End: 16},
				Filename: testPath,
			},
			DepGroups: []string{"duplicate-r-test", "duplicate-r-dev"},
		},
		{
			Name:      "unittest",
			Version:   "1.0.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 4, End: 4},
				Column:   models.Position{Start: 1, End: 16},
				Filename: testPath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 4, End: 4},
				Column:   models.Position{Start: 1, End: 9},
				Filename: testPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 4, End: 4},
				Column:   models.Position{Start: 11, End: 16},
				Filename: testPath,
			},
			DepGroups: []string{"duplicate-r-test"},
		},
	})
}

func TestParseRequirementsTxt_CyclicRSelf(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/pip/cyclic-r-self.txt"))
	packages, err := lockfile.ParseRequirementsTxt(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "pandas",
			Version:   "0.23.4",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 4, End: 4},
				Column:   models.Position{Start: 1, End: 15},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 4, End: 4},
				Column:   models.Position{Start: 1, End: 7},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 4, End: 4},
				Column:   models.Position{Start: 9, End: 15},
				Filename: path,
			},
			DepGroups: []string{"cyclic-r-self"},
		},
		{
			Name:      "requests",
			Version:   "1.2.3",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 3, End: 3},
				Column:   models.Position{Start: 1, End: 16},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 3, End: 3},
				Column:   models.Position{Start: 1, End: 9},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 3, End: 3},
				Column:   models.Position{Start: 11, End: 16},
				Filename: path,
			},
			DepGroups: []string{"cyclic-r-self"},
		},
	})
}

func TestParseRequirementsTxt_CyclicRComplex(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	sourcePath := filepath.FromSlash(filepath.Join(dir, "fixtures/pip/cyclic-r-complex-1.txt"))
	cyclic2Path := filepath.FromSlash(filepath.Join(dir, "fixtures/pip/cyclic-r-complex-2.txt"))
	cyclic3Path := filepath.FromSlash(filepath.Join(dir, "fixtures/pip/cyclic-r-complex-3.txt"))
	packages, err := lockfile.ParseRequirementsTxt(sourcePath)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "cyclic-r-complex",
			Version:   "1",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 3, End: 3},
				Column:   models.Position{Start: 1, End: 20},
				Filename: sourcePath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 3, End: 3},
				Column:   models.Position{Start: 1, End: 17},
				Filename: sourcePath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 3, End: 3},
				Column:   models.Position{Start: 19, End: 20},
				Filename: sourcePath,
			},
			DepGroups: []string{"cyclic-r-complex-1"},
		},
		{
			Name:      "cyclic-r-complex",
			Version:   "2",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 4, End: 4},
				Column:   models.Position{Start: 1, End: 20},
				Filename: cyclic2Path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 4, End: 4},
				Column:   models.Position{Start: 1, End: 17},
				Filename: cyclic2Path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 4, End: 4},
				Column:   models.Position{Start: 19, End: 20},
				Filename: cyclic2Path,
			},
			DepGroups: []string{"cyclic-r-complex-2"},
		},
		{
			Name:      "cyclic-r-complex",
			Version:   "3",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 4, End: 4},
				Column:   models.Position{Start: 1, End: 20},
				Filename: cyclic3Path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 4, End: 4},
				Column:   models.Position{Start: 1, End: 17},
				Filename: cyclic3Path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 4, End: 4},
				Column:   models.Position{Start: 19, End: 20},
				Filename: cyclic3Path,
			},
			DepGroups: []string{"cyclic-r-complex-3"},
		},
	})
}

func TestParseRequirementsTxt_WithPerRequirementOptions(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/pip/with-per-requirement-options.txt"))
	packages, err := lockfile.ParseRequirementsTxt(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "boto3",
			Version:   "1.26.121",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 1, End: 1},
				Column:   models.Position{Start: 1, End: 95},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 1, End: 1},
				Column:   models.Position{Start: 1, End: 6},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 1, End: 1},
				Column:   models.Position{Start: 8, End: 16},
				Filename: path,
			},
			DepGroups: []string{"with-per-requirement-options"},
		},
		{
			Name:      "foo",
			Version:   "1.0.0",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 2, End: 2},
				Column:   models.Position{Start: 1, End: 13},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 2, End: 2},
				Column:   models.Position{Start: 1, End: 4},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 2, End: 2},
				Column:   models.Position{Start: 8, End: 13},
				Filename: path,
			},
			DepGroups: []string{"with-per-requirement-options"},
		},
		{
			Name:      "fooproject",
			Version:   "1.2",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 6, End: 8},
				Column:   models.Position{Start: 1, End: 81},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 6, End: 6},
				Column:   models.Position{Start: 1, End: 11},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 6, End: 6},
				Column:   models.Position{Start: 15, End: 18},
				Filename: path,
			},
			DepGroups: []string{"with-per-requirement-options"},
		},
		{
			Name:      "barproject",
			Version:   "1.2",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 12, End: 12},
				Column:   models.Position{Start: 1, End: 50},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 12, End: 12},
				Column:   models.Position{Start: 1, End: 11},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 12, End: 12},
				Column:   models.Position{Start: 15, End: 18},
				Filename: path,
			},
			DepGroups: []string{"with-per-requirement-options"},
		},
	})
}

func TestParseRequirementsTxt_LineContinuation(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/pip/line-continuation.txt"))
	packages, err := lockfile.ParseRequirementsTxt(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "foo",
			Version:   "1.2.3",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 2, End: 6},
				Column:   models.Position{Start: 1, End: 6},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 2, End: 2},
				Column:   models.Position{Start: 1, End: 4},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 6, End: 6},
				Column:   models.Position{Start: 1, End: 6},
				Filename: path,
			},
			DepGroups: []string{"line-continuation"},
		},
		{
			Name:      "bar",
			Version:   "4.5\\\\",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 9, End: 9},
				Column:   models.Position{Start: 1, End: 13},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 9, End: 9},
				Column:   models.Position{Start: 1, End: 4},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 9, End: 9},
				Column:   models.Position{Start: 8, End: 13},
				Filename: path,
			},
			DepGroups: []string{"line-continuation"},
		},
		{
			Name:      "baz",
			Version:   "7.8.9",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 13, End: 14},
				Column:   models.Position{Start: 1, End: 13},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 13, End: 13},
				Column:   models.Position{Start: 1, End: 4},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 13, End: 13},
				Column:   models.Position{Start: 8, End: 13},
				Filename: path,
			},
			DepGroups: []string{"line-continuation"},
		},
		{
			Name:      "qux",
			Version:   "10.11.12",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 17, End: 17},
				Column:   models.Position{Start: 1, End: 17},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 17, End: 17},
				Column:   models.Position{Start: 1, End: 4},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 17, End: 17},
				Column:   models.Position{Start: 8, End: 16},
				Filename: path,
			},
			DepGroups: []string{"line-continuation"},
		},
	})
}

func TestParseRequirementsTxt_EnvironmentMarkers(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/pip/environment-markers.txt"))
	packages, err := lockfile.ParseRequirementsTxt(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "aa",
			Version:   "",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 1, End: 1},
				Column:   models.Position{Start: 1, End: 26},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 1, End: 1},
				Column:   models.Position{Start: 1, End: 3},
				Filename: path,
			},
			Commit:    "",
			DepGroups: []string{"environment-markers"},
		},
		{
			Name:      "name6",
			Version:   "",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 2, End: 2},
				Column:   models.Position{Start: 1, End: 67},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 2, End: 2},
				Column:   models.Position{Start: 1, End: 20},
				Filename: path,
			},
			Commit:    "",
			DepGroups: []string{"environment-markers"},
		},
		{
			Name:      "someproject",
			Version:   "5.4",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 3, End: 3},
				Column:   models.Position{Start: 1, End: 41},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 3, End: 3},
				Column:   models.Position{Start: 1, End: 12},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 3, End: 3},
				Column:   models.Position{Start: 14, End: 17},
				Filename: path,
			},
			Commit:    "",
			DepGroups: []string{"environment-markers"},
		},
	})
}

func TestParseRequirementsTxt_GitUrlPackages(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/pip/url-packages.txt"))
	packages, err := lockfile.ParseRequirementsTxt(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "pyroxy",
			Version:   "",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 1, End: 1},
				Column:   models.Position{Start: 1, End: 52},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 1, End: 1},
				Column:   models.Position{Start: 1, End: 7},
				Filename: path,
			},
			Commit:    "",
			DepGroups: []string{"url-packages"},
		},
	})
}

func TestParseRequirementsTxt_WhlUrlPackages(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/pip/whl-url-packages.txt"))
	packages, err := lockfile.ParseRequirementsTxt(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}
	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "pandas",
			Version:   "2.2.1",
			Ecosystem: lockfile.PipEcosystem,
			CompareAs: lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 1, End: 1},
				Column:   models.Position{Start: 1, End: 161},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 1, End: 1},
				Column:   models.Position{Start: 1, End: 7},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 1, End: 1},
				Column:   models.Position{Start: 124, End: 129},
				Filename: path,
			},
			Commit:    "",
			DepGroups: []string{"whl-url-packages"},
		},
	})
}
