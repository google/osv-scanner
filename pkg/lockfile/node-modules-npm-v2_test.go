package lockfile_test

import (
	"testing"

	"github.com/google/osv-scanner/pkg/models"

	"github.com/google/osv-scanner/pkg/lockfile"
)

func TestNodeModulesExtractor_Extract_npm_v2_InvalidJson(t *testing.T) {
	t.Parallel()

	packages, _, err := testParsingNodeModules(t, "fixtures/npm/not-json.txt")

	expectErrContaining(t, err, "could not extract from")
	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestNodeModulesExtractor_Extract_npm_v2_NoPackages(t *testing.T) {
	t.Parallel()

	packages, _, err := testParsingNodeModules(t, "fixtures/npm/empty.v2.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestNodeModulesExtractor_Extract_npm_v2_OnePackage(t *testing.T) {
	t.Parallel()

	packages, filePath, err := testParsingNodeModules(t, "fixtures/npm/one-package.v2.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "wrappy",
			Version:        "1.0.2",
			TargetVersions: []string{"^1.0.0"},
			Ecosystem:      lockfile.NpmEcosystem,
			CompareAs:      lockfile.NpmEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 10, End: 14},
				Column:   models.Position{Start: 5, End: 6},
				Filename: filePath,
			},
		},
	})
}

func TestNodeModulesExtractor_Extract_npm_v2_OnePackageDev(t *testing.T) {
	t.Parallel()

	packages, filePath, err := testParsingNodeModules(t, "fixtures/npm/one-package-dev.v2.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "wrappy",
			Version:        "1.0.2",
			TargetVersions: []string{"^1.0.0"},
			Ecosystem:      lockfile.NpmEcosystem,
			CompareAs:      lockfile.NpmEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 10, End: 15},
				Column:   models.Position{Start: 5, End: 6},
				Filename: filePath,
			},
			DepGroups: []string{"dev"},
		},
	})
}

func TestNodeModulesExtractor_Extract_npm_v2_TwoPackages(t *testing.T) {
	t.Parallel()

	packages, filePath, err := testParsingNodeModules(t, "fixtures/npm/two-packages.v2.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "wrappy",
			Version:        "1.0.2",
			TargetVersions: []string{"^1.0.0"},
			Ecosystem:      lockfile.NpmEcosystem,
			CompareAs:      lockfile.NpmEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 13, End: 17},
				Column:   models.Position{Start: 5, End: 6},
				Filename: filePath,
			},
		},
		{
			Name:           "supports-color",
			Version:        "5.5.0",
			TargetVersions: []string{"^5.0.0"},
			Ecosystem:      lockfile.NpmEcosystem,
			CompareAs:      lockfile.NpmEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 18, End: 28},
				Column:   models.Position{Start: 5, End: 6},
				Filename: filePath,
			},
		},
	})
}

func TestNodeModulesExtractor_Extract_npm_v2_ScopedPackages(t *testing.T) {
	t.Parallel()

	packages, filePath, err := testParsingNodeModules(t, "fixtures/npm/scoped-packages.v2.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "wrappy",
			Version:   "1.0.2",
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 18, End: 22},
				Column:   models.Position{Start: 5, End: 6},
				Filename: filePath,
			},
		},
		{
			Name:      "@babel/code-frame",
			Version:   "7.0.0",
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 10, End: 17},
				Column:   models.Position{Start: 5, End: 6},
				Filename: filePath,
			},
		},
	})
}

func TestNodeModulesExtractor_Extract_npm_v2_NestedDependencies(t *testing.T) {
	t.Parallel()

	packages, filePath, err := testParsingNodeModules(t, "fixtures/npm/nested-dependencies.v2.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "postcss",
			Version:   "6.0.23",
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 10, End: 22},
				Column:   models.Position{Start: 5, End: 6},
				Filename: filePath,
			},
		},
		{
			Name:      "postcss",
			Version:   "7.0.16",
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 34, End: 46},
				Column:   models.Position{Start: 5, End: 6},
				Filename: filePath,
			},
		},
		{
			Name:      "postcss-calc",
			Version:   "7.0.1",
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 23, End: 33},
				Column:   models.Position{Start: 5, End: 6},
				Filename: filePath,
			},
		},
		{
			Name:      "supports-color",
			Version:   "6.1.0",
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 47, End: 57},
				Column:   models.Position{Start: 5, End: 6},
				Filename: filePath,
			},
		},
		{
			Name:      "supports-color",
			Version:   "5.5.0",
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 58, End: 68},
				Column:   models.Position{Start: 5, End: 6},
				Filename: filePath,
			},
		},
	})
}

func TestNodeModulesExtractor_Extract_npm_v2_NestedDependenciesDup(t *testing.T) {
	t.Parallel()

	packages, filePath, err := testParsingNodeModules(t, "fixtures/npm/nested-dependencies-dup.v2.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:      "supports-color",
			Version:   "6.1.0",
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 10, End: 20},
				Column:   models.Position{Start: 5, End: 6},
				Filename: filePath,
			},
		},
		{
			Name:      "supports-color",
			Version:   "2.0.0",
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 32, End: 39},
				Column:   models.Position{Start: 5, End: 6},
				Filename: filePath,
			},
		},
	})
}

func TestNodeModulesExtractor_Extract_npm_v2_Commits(t *testing.T) {
	t.Parallel()

	packages, filePath, err := testParsingNodeModules(t, "fixtures/npm/commits.v2.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "@segment/analytics.js-integration-facebook-pixel",
			Version:        "2.4.1",
			TargetVersions: []string{"github:segmentio/analytics.js-integrations#2.4.1"},
			Ecosystem:      lockfile.NpmEcosystem,
			CompareAs:      lockfile.NpmEcosystem,
			Commit:         "3b1bb80b302c2e552685dc8a029797ec832ea7c9",
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 26, End: 41},
				Column:   models.Position{Start: 5, End: 6},
				Filename: filePath,
			},
		},
		{
			Name:      "ansi-styles",
			Version:   "1.0.0",
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			Commit:    "",
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 42, End: 49},
				Column:   models.Position{Start: 5, End: 6},
				Filename: filePath,
			},
		},
		{
			Name:           "babel-preset-php",
			Version:        "1.1.1",
			TargetVersions: []string{"gitlab:kornelski/babel-preset-php#main"},
			Ecosystem:      lockfile.NpmEcosystem,
			CompareAs:      lockfile.NpmEcosystem,
			Commit:         "c5a7ba5e0ad98b8db1cb8ce105403dd4b768cced",
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 50, End: 59},
				Column:   models.Position{Start: 5, End: 6},
				Filename: filePath,
			},
			DepGroups: []string{"dev"},
		},
		{
			Name:           "is-number-1",
			Version:        "3.0.0",
			TargetVersions: []string{"https://github.com/jonschlinkert/is-number.git"},
			Ecosystem:      lockfile.NpmEcosystem,
			CompareAs:      lockfile.NpmEcosystem,
			Commit:         "af885e2e890b9ef0875edd2b117305119ee5bdc5",
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 60, End: 72},
				Column:   models.Position{Start: 5, End: 6},
				Filename: filePath,
			},
			DepGroups: []string{"dev"},
		},
		{
			Name:      "is-number-1",
			Version:   "3.0.0",
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			Commit:    "be5935f8d2595bcd97b05718ef1eeae08d812e10",
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 130, End: 142},
				Column:   models.Position{Start: 5, End: 6},
				Filename: filePath,
			},
			DepGroups: []string{"dev"},
		},
		{
			Name:           "is-number-2",
			Version:        "2.0.0",
			TargetVersions: []string{"https://github.com/jonschlinkert/is-number.git#d5ac058"},
			Ecosystem:      lockfile.NpmEcosystem,
			CompareAs:      lockfile.NpmEcosystem,
			Commit:         "d5ac0584ee9ae7bd9288220a39780f155b9ad4c8",
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 73, End: 82},
				Column:   models.Position{Start: 5, End: 6},
				Filename: filePath,
			},
			DepGroups: []string{"dev"},
		},
		{
			Name:      "is-number-2",
			Version:   "2.0.0",
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			Commit:    "82dcc8e914dabd9305ab9ae580709a7825e824f5",
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 143, End: 152},
				Column:   models.Position{Start: 5, End: 6},
				Filename: filePath,
			},
			DepGroups: []string{"dev"},
		},
		{
			Name:           "is-number-3",
			Version:        "2.0.0",
			TargetVersions: []string{"https://github.com/jonschlinkert/is-number.git#2.0.0"},
			Ecosystem:      lockfile.NpmEcosystem,
			CompareAs:      lockfile.NpmEcosystem,
			Commit:         "d5ac0584ee9ae7bd9288220a39780f155b9ad4c8",
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 83, End: 92},
				Column:   models.Position{Start: 5, End: 6},
				Filename: filePath,
			},
			DepGroups: []string{"dev"},
		},
		{
			Name:      "is-number-3",
			Version:   "3.0.0",
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			Commit:    "82ae8802978da40d7f1be5ad5943c9e550ab2c89",
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 153, End: 162},
				Column:   models.Position{Start: 5, End: 6},
				Filename: filePath,
			},
			DepGroups: []string{"dev"},
		},
		{
			Name:           "is-number-4",
			Version:        "3.0.0",
			TargetVersions: []string{"git+ssh://git@github.com:jonschlinkert/is-number.git"},
			Ecosystem:      lockfile.NpmEcosystem,
			CompareAs:      lockfile.NpmEcosystem,
			Commit:         "af885e2e890b9ef0875edd2b117305119ee5bdc5",
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 93, End: 105},
				Column:   models.Position{Start: 5, End: 6},
				Filename: filePath,
			},
			DepGroups: []string{"dev"},
		},
		{
			Name:           "is-number-5",
			Version:        "3.0.0",
			TargetVersions: []string{"https://dummy-token@github.com/jonschlinkert/is-number.git#main"},
			Ecosystem:      lockfile.NpmEcosystem,
			CompareAs:      lockfile.NpmEcosystem,
			Commit:         "af885e2e890b9ef0875edd2b117305119ee5bdc5",
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 106, End: 118},
				Column:   models.Position{Start: 5, End: 6},
				Filename: filePath,
			},
			DepGroups: []string{"dev"},
		},
		{
			Name:      "postcss-calc",
			Version:   "7.0.1",
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			Commit:    "",
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 119, End: 129},
				Column:   models.Position{Start: 5, End: 6},
				Filename: filePath,
			},
		},
		{
			Name:           "raven-js",
			Version:        "",
			TargetVersions: []string{"getsentry/raven-js#3.23.1"},
			Ecosystem:      lockfile.NpmEcosystem,
			CompareAs:      lockfile.NpmEcosystem,
			Commit:         "c2b377e7a254264fd4a1fe328e4e3cfc9e245570",
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 163, End: 165},
				Column:   models.Position{Start: 5, End: 6},
				Filename: filePath,
			},
		},
		{
			Name:           "slick-carousel",
			Version:        "1.7.1",
			TargetVersions: []string{"git://github.com/brianfryer/slick"},
			Ecosystem:      lockfile.NpmEcosystem,
			CompareAs:      lockfile.NpmEcosystem,
			Commit:         "280b560161b751ba226d50c7db1e0a14a78c2de0",
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 166, End: 175},
				Column:   models.Position{Start: 5, End: 6},
				Filename: filePath,
			},
			DepGroups: []string{"dev"},
		},
	})
}

func TestNodeModulesExtractor_Extract_npm_v2_Files(t *testing.T) {
	t.Parallel()

	packages, filePath, err := testParsingNodeModules(t, "fixtures/npm/files.v2.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "etag",
			Version:        "1.8.0",
			TargetVersions: []string{"deps/etag"},
			Ecosystem:      lockfile.NpmEcosystem,
			CompareAs:      lockfile.NpmEcosystem,
			Commit:         "",
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 16, End: 35},
				Column:   models.Position{Start: 5, End: 6},
				Filename: filePath,
			},
			DepGroups: []string{"dev"},
		},
		{
			Name:      "abbrev",
			Version:   "1.0.9",
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			Commit:    "",
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 36, End: 41},
				Column:   models.Position{Start: 5, End: 6},
				Filename: filePath,
			},
			DepGroups: []string{"dev"},
		},
		{
			Name:      "abbrev",
			Version:   "2.3.4",
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			Commit:    "",
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 42, End: 47},
				Column:   models.Position{Start: 5, End: 6},
				Filename: filePath,
			},
			DepGroups: []string{"dev"},
		},
	})
}

func TestNodeModulesExtractor_Extract_npm_v2_Alias(t *testing.T) {
	t.Parallel()

	packages, filePath, err := testParsingNodeModules(t, "fixtures/npm/alias.v2.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "@babel/code-frame",
			Version:        "7.0.0",
			TargetVersions: []string{"^7.0.0"},
			Ecosystem:      lockfile.NpmEcosystem,
			CompareAs:      lockfile.NpmEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 13, End: 21},
				Column:   models.Position{Start: 5, End: 6},
				Filename: filePath,
			},
		},
		{
			Name:           "string-width",
			Version:        "4.2.0",
			TargetVersions: []string{"^4.2.0"},
			Ecosystem:      lockfile.NpmEcosystem,
			CompareAs:      lockfile.NpmEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 32, End: 42},
				Column:   models.Position{Start: 5, End: 6},
				Filename: filePath,
			},
		},
		{
			Name:           "string-width",
			Version:        "5.1.2",
			TargetVersions: []string{"^5.1.2"},
			Ecosystem:      lockfile.NpmEcosystem,
			CompareAs:      lockfile.NpmEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 22, End: 31},
				Column:   models.Position{Start: 5, End: 6},
				Filename: filePath,
			},
		},
	})
}

func TestNodeModulesExtractor_Extract_npm_v2_OptionalPackage(t *testing.T) {
	t.Parallel()

	packages, filePath, err := testParsingNodeModules(t, "fixtures/npm/optional-package.v2.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "wrappy",
			Version:        "1.0.2",
			TargetVersions: []string{"^1.0.0"},
			Ecosystem:      lockfile.NpmEcosystem,
			CompareAs:      lockfile.NpmEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 10, End: 15},
				Column:   models.Position{Start: 5, End: 6},
				Filename: filePath,
			},
			DepGroups: []string{"optional"},
		},
		{
			Name:      "supports-color",
			Version:   "5.5.0",
			Ecosystem: lockfile.NpmEcosystem,
			CompareAs: lockfile.NpmEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 16, End: 27},
				Column:   models.Position{Start: 6, End: 6},
				Filename: filePath,
			},
			DepGroups: []string{"dev", "optional"},
		},
	})
}
