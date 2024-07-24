package lockfile_test

import (
	"testing"

	"github.com/google/osv-scanner/pkg/lockfile"
)

func TestExtractNpmV2Lock(t *testing.T) {
	t.Parallel()

	tests := []testTableEntry{
		{
			name: "v2_ invalid json",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/npm/not-json.txt",
			},
			wantInventory: []*lockfile.Inventory{},
		},

		{
			name: "v2_ no packages",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/npm/empty.v2.json",
			},
			wantInventory: []*lockfile.Inventory{},
		},

		{
			name: "v2_ one package",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/npm/one-package.v2.json",
			},
			wantInventory: []*lockfile.Inventory{
				{
					Name:      "wrappy",
					Version:   "1.0.2",
					Locations: []string{"fixtures/npm/one-package.v2.json"},
					SourceCode: &lockfile.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},

		{
			name: "v2_ one package dev",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/npm/one-package-dev.v2.json",
			},
			wantInventory: []*lockfile.Inventory{
				{
					Name:      "wrappy",
					Version:   "1.0.2",
					Locations: []string{"fixtures/npm/one-package-dev.v2.json"},
					SourceCode: &lockfile.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
			},
		},

		{
			name: "v2_ two packages",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/npm/two-packages.v2.json",
			},
			wantInventory: []*lockfile.Inventory{
				{
					Name:      "wrappy",
					Version:   "1.0.2",
					Locations: []string{"fixtures/npm/two-packages.v2.json"},
					SourceCode: &lockfile.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "supports-color",
					Version:   "5.5.0",
					Locations: []string{"fixtures/npm/two-packages.v2.json"},
					SourceCode: &lockfile.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},

		{
			name: "v2_ scoped packages",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/npm/scoped-packages.v2.json",
			},
			wantInventory: []*lockfile.Inventory{
				{
					Name:      "wrappy",
					Version:   "1.0.2",
					Locations: []string{"fixtures/npm/scoped-packages.v2.json"},
					SourceCode: &lockfile.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "@babel/code-frame",
					Version:   "7.0.0",
					Locations: []string{"fixtures/npm/scoped-packages.v2.json"},
					SourceCode: &lockfile.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},

		{
			name: "v2_ nested dependencies",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/npm/nested-dependencies.v2.json",
			},
			wantInventory: []*lockfile.Inventory{
				{
					Name:      "postcss",
					Version:   "6.0.23",
					Locations: []string{"fixtures/npm/nested-dependencies.v2.json"},
					SourceCode: &lockfile.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "postcss",
					Version:   "7.0.16",
					Locations: []string{"fixtures/npm/nested-dependencies.v2.json"},
					SourceCode: &lockfile.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "postcss-calc",
					Version:   "7.0.1",
					Locations: []string{"fixtures/npm/nested-dependencies.v2.json"},
					SourceCode: &lockfile.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "supports-color",
					Version:   "6.1.0",
					Locations: []string{"fixtures/npm/nested-dependencies.v2.json"},
					SourceCode: &lockfile.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "supports-color",
					Version:   "5.5.0",
					Locations: []string{"fixtures/npm/nested-dependencies.v2.json"},
					SourceCode: &lockfile.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},

		{
			name: "v2_ nested dependencies dup",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/npm/nested-dependencies-dup.v2.json",
			},
			wantInventory: []*lockfile.Inventory{
				{
					Name:      "supports-color",
					Version:   "6.1.0",
					Locations: []string{"fixtures/npm/nested-dependencies-dup.v2.json"},
					SourceCode: &lockfile.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "supports-color",
					Version:   "2.0.0",
					Locations: []string{"fixtures/npm/nested-dependencies-dup.v2.json"},
					SourceCode: &lockfile.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},

		{
			name: "v2_ commits",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/npm/commits.v2.json",
			},
			wantInventory: []*lockfile.Inventory{
				{
					Name:      "@segment/analytics.js-integration-facebook-pixel",
					Version:   "2.4.1",
					Locations: []string{"fixtures/npm/commits.v2.json"},
					SourceCode: &lockfile.SourceCodeIdentifier{
						Commit: "3b1bb80b302c2e552685dc8a029797ec832ea7c9",
					},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "ansi-styles",
					Version:   "1.0.0",
					Locations: []string{"fixtures/npm/commits.v2.json"},
					SourceCode: &lockfile.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "babel-preset-php",
					Version:   "1.1.1",
					Locations: []string{"fixtures/npm/commits.v2.json"},
					SourceCode: &lockfile.SourceCodeIdentifier{
						Commit: "c5a7ba5e0ad98b8db1cb8ce105403dd4b768cced",
					},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
				{
					Name:      "is-number-1",
					Version:   "3.0.0",
					Locations: []string{"fixtures/npm/commits.v2.json"},
					SourceCode: &lockfile.SourceCodeIdentifier{
						Commit: "af885e2e890b9ef0875edd2b117305119ee5bdc5",
					},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
				{
					Name:      "is-number-1",
					Version:   "3.0.0",
					Locations: []string{"fixtures/npm/commits.v2.json"},
					SourceCode: &lockfile.SourceCodeIdentifier{
						Commit: "be5935f8d2595bcd97b05718ef1eeae08d812e10",
					},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
				{
					Name:      "is-number-2",
					Version:   "2.0.0",
					Locations: []string{"fixtures/npm/commits.v2.json"},
					SourceCode: &lockfile.SourceCodeIdentifier{
						Commit: "d5ac0584ee9ae7bd9288220a39780f155b9ad4c8",
					},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
				{
					Name:      "is-number-2",
					Version:   "2.0.0",
					Locations: []string{"fixtures/npm/commits.v2.json"},
					SourceCode: &lockfile.SourceCodeIdentifier{
						Commit: "82dcc8e914dabd9305ab9ae580709a7825e824f5",
					},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
				{
					Name:      "is-number-3",
					Version:   "2.0.0",
					Locations: []string{"fixtures/npm/commits.v2.json"},
					SourceCode: &lockfile.SourceCodeIdentifier{
						Commit: "d5ac0584ee9ae7bd9288220a39780f155b9ad4c8",
					},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
				{
					Name:      "is-number-3",
					Version:   "3.0.0",
					Locations: []string{"fixtures/npm/commits.v2.json"},
					SourceCode: &lockfile.SourceCodeIdentifier{
						Commit: "82ae8802978da40d7f1be5ad5943c9e550ab2c89",
					},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
				{
					Name:      "is-number-4",
					Version:   "3.0.0",
					Locations: []string{"fixtures/npm/commits.v2.json"},
					SourceCode: &lockfile.SourceCodeIdentifier{
						Commit: "af885e2e890b9ef0875edd2b117305119ee5bdc5",
					},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
				{
					Name:      "is-number-5",
					Version:   "3.0.0",
					Locations: []string{"fixtures/npm/commits.v2.json"},
					SourceCode: &lockfile.SourceCodeIdentifier{
						Commit: "af885e2e890b9ef0875edd2b117305119ee5bdc5",
					},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
				{
					Name:      "postcss-calc",
					Version:   "7.0.1",
					Locations: []string{"fixtures/npm/commits.v2.json"},
					SourceCode: &lockfile.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "raven-js",
					Version:   "",
					Locations: []string{"fixtures/npm/commits.v2.json"},
					SourceCode: &lockfile.SourceCodeIdentifier{
						Commit: "c2b377e7a254264fd4a1fe328e4e3cfc9e245570",
					},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "slick-carousel",
					Version:   "1.7.1",
					Locations: []string{"fixtures/npm/commits.v2.json"},
					SourceCode: &lockfile.SourceCodeIdentifier{
						Commit: "280b560161b751ba226d50c7db1e0a14a78c2de0",
					},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
			},
		},

		{
			name: "v2_ files",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/npm/files.v2.json",
			},
			wantInventory: []*lockfile.Inventory{
				{
					Name:      "etag",
					Version:   "1.8.0",
					Locations: []string{"fixtures/npm/files.v2.json"},
					SourceCode: &lockfile.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
				{
					Name:      "abbrev",
					Version:   "1.0.9",
					Locations: []string{"fixtures/npm/files.v2.json"},
					SourceCode: &lockfile.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
				{
					Name:      "abbrev",
					Version:   "2.3.4",
					Locations: []string{"fixtures/npm/files.v2.json"},
					SourceCode: &lockfile.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
			},
		},

		{
			name: "v2_ alias",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/npm/alias.v2.json",
			},
			wantInventory: []*lockfile.Inventory{
				{
					Name:      "@babel/code-frame",
					Version:   "7.0.0",
					Locations: []string{"fixtures/npm/alias.v2.json"},
					SourceCode: &lockfile.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "string-width",
					Version:   "4.2.0",
					Locations: []string{"fixtures/npm/alias.v2.json"},
					SourceCode: &lockfile.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "string-width",
					Version:   "5.1.2",
					Locations: []string{"fixtures/npm/alias.v2.json"},
					SourceCode: &lockfile.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},

		{
			name: "v2_ optional package",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/npm/optional-package.v2.json",
			},
			wantInventory: []*lockfile.Inventory{
				{
					Name:      "wrappy",
					Version:   "1.0.2",
					Locations: []string{"fixtures/npm/optional-package.v2.json"},
					SourceCode: &lockfile.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{"optional"},
					},
				},
				{
					Name:      "supports-color",
					Version:   "5.5.0",
					Locations: []string{"fixtures/npm/optional-package.v2.json"},
					SourceCode: &lockfile.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{"dev", "optional"},
					},
				},
			},
		},

		{
			name: "v2_ same package different groups",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/npm/same-package-different-groups.v2.json",
			},
			wantInventory: []*lockfile.Inventory{
				{
					Name:      "eslint",
					Version:   "1.2.3",
					Locations: []string{"fixtures/npm/same-package-different-groups.v2.json"},
					SourceCode: &lockfile.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
				{
					Name:      "table",
					Version:   "1.0.0",
					Locations: []string{"fixtures/npm/same-package-different-groups.v2.json"},
					SourceCode: &lockfile.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "ajv",
					Version:   "5.5.2",
					Locations: []string{"fixtures/npm/same-package-different-groups.v2.json"},
					SourceCode: &lockfile.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := lockfile.NpmLockExtractor{}
			_, _ = extractionTester(t, e, tt)
		})
	}
}

// func TestParseNpmLock_v2_FileDoesNotExist(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfile.ParseNpmLock("fixtures/npm/does-not-exist")

// 	expectErrIs(t, err, fs.ErrNotExist)
// 	expectPackages(t, packages, []lockfile.PackageDetails{})
// }

// func TestParseNpmLock_v2_InvalidJson(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfile.ParseNpmLock("fixtures/npm/not-json.txt")

// 	expectErrContaining(t, err, "could not extract from")
// 	expectPackages(t, packages, []lockfile.PackageDetails{})
// }

// func TestParseNpmLock_v2_NoPackages(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfile.ParseNpmLock("fixtures/npm/empty.v2.json")

// 	if err != nil {
// 		t.Errorf("Got unexpected error: %v", err)
// 	}

// 	expectPackages(t, packages, []lockfile.PackageDetails{})
// }

// func TestParseNpmLock_v2_OnePackage(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfile.ParseNpmLock("fixtures/npm/one-package.v2.json")

// 	if err != nil {
// 		t.Errorf("Got unexpected error: %v", err)
// 	}

// 	expectPackages(t, packages, []lockfile.PackageDetails{
// 		{
// 			Name:      "wrappy",
// 			Version:   "1.0.2",
// 			Ecosystem: lockfile.NpmEcosystem,
// 			CompareAs: lockfile.NpmEcosystem,
// 		},
// 	})
// }

// func TestParseNpmLock_v2_OnePackageDev(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfile.ParseNpmLock("fixtures/npm/one-package-dev.v2.json")

// 	if err != nil {
// 		t.Errorf("Got unexpected error: %v", err)
// 	}

// 	expectPackages(t, packages, []lockfile.PackageDetails{
// 		{
// 			Name:      "wrappy",
// 			Version:   "1.0.2",
// 			Ecosystem: lockfile.NpmEcosystem,
// 			CompareAs: lockfile.NpmEcosystem,
// 			DepGroups: []string{"dev"},
// 		},
// 	})
// }

// func TestParseNpmLock_v2_TwoPackages(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfile.ParseNpmLock("fixtures/npm/two-packages.v2.json")

// 	if err != nil {
// 		t.Errorf("Got unexpected error: %v", err)
// 	}

// 	expectPackages(t, packages, []lockfile.PackageDetails{
// 		{
// 			Name:      "wrappy",
// 			Version:   "1.0.2",
// 			Ecosystem: lockfile.NpmEcosystem,
// 			CompareAs: lockfile.NpmEcosystem,
// 		},
// 		{
// 			Name:      "supports-color",
// 			Version:   "5.5.0",
// 			Ecosystem: lockfile.NpmEcosystem,
// 			CompareAs: lockfile.NpmEcosystem,
// 		},
// 	})
// }

// func TestParseNpmLock_v2_ScopedPackages(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfile.ParseNpmLock("fixtures/npm/scoped-packages.v2.json")

// 	if err != nil {
// 		t.Errorf("Got unexpected error: %v", err)
// 	}

// 	expectPackages(t, packages, []lockfile.PackageDetails{
// 		{
// 			Name:      "wrappy",
// 			Version:   "1.0.2",
// 			Ecosystem: lockfile.NpmEcosystem,
// 			CompareAs: lockfile.NpmEcosystem,
// 		},
// 		{
// 			Name:      "@babel/code-frame",
// 			Version:   "7.0.0",
// 			Ecosystem: lockfile.NpmEcosystem,
// 			CompareAs: lockfile.NpmEcosystem,
// 		},
// 	})
// }

// func TestParseNpmLock_v2_NestedDependencies(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfile.ParseNpmLock("fixtures/npm/nested-dependencies.v2.json")

// 	if err != nil {
// 		t.Errorf("Got unexpected error: %v", err)
// 	}

// 	expectPackages(t, packages, []lockfile.PackageDetails{
// 		{
// 			Name:      "postcss",
// 			Version:   "6.0.23",
// 			Ecosystem: lockfile.NpmEcosystem,
// 			CompareAs: lockfile.NpmEcosystem,
// 		},
// 		{
// 			Name:      "postcss",
// 			Version:   "7.0.16",
// 			Ecosystem: lockfile.NpmEcosystem,
// 			CompareAs: lockfile.NpmEcosystem,
// 		},
// 		{
// 			Name:      "postcss-calc",
// 			Version:   "7.0.1",
// 			Ecosystem: lockfile.NpmEcosystem,
// 			CompareAs: lockfile.NpmEcosystem,
// 		},
// 		{
// 			Name:      "supports-color",
// 			Version:   "6.1.0",
// 			Ecosystem: lockfile.NpmEcosystem,
// 			CompareAs: lockfile.NpmEcosystem,
// 		},
// 		{
// 			Name:      "supports-color",
// 			Version:   "5.5.0",
// 			Ecosystem: lockfile.NpmEcosystem,
// 			CompareAs: lockfile.NpmEcosystem,
// 		},
// 	})
// }

// func TestParseNpmLock_v2_NestedDependenciesDup(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfile.ParseNpmLock("fixtures/npm/nested-dependencies-dup.v2.json")

// 	if err != nil {
// 		t.Errorf("Got unexpected error: %v", err)
// 	}

// 	expectPackages(t, packages, []lockfile.PackageDetails{
// 		{
// 			Name:      "supports-color",
// 			Version:   "6.1.0",
// 			Ecosystem: lockfile.NpmEcosystem,
// 			CompareAs: lockfile.NpmEcosystem,
// 		},
// 		{
// 			Name:      "supports-color",
// 			Version:   "2.0.0",
// 			Ecosystem: lockfile.NpmEcosystem,
// 			CompareAs: lockfile.NpmEcosystem,
// 		},
// 	})
// }

// func TestParseNpmLock_v2_Commits(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfile.ParseNpmLock("fixtures/npm/commits.v2.json")

// 	if err != nil {
// 		t.Errorf("Got unexpected error: %v", err)
// 	}

// 	expectPackages(t, packages, []lockfile.PackageDetails{
// 		{
// 			Name:      "@segment/analytics.js-integration-facebook-pixel",
// 			Version:   "2.4.1",
// 			Ecosystem: lockfile.NpmEcosystem,
// 			CompareAs: lockfile.NpmEcosystem,
// 			Commit:    "3b1bb80b302c2e552685dc8a029797ec832ea7c9",
// 		},
// 		{
// 			Name:      "ansi-styles",
// 			Version:   "1.0.0",
// 			Ecosystem: lockfile.NpmEcosystem,
// 			CompareAs: lockfile.NpmEcosystem,
// 			Commit:    "",
// 		},
// 		{
// 			Name:      "babel-preset-php",
// 			Version:   "1.1.1",
// 			Ecosystem: lockfile.NpmEcosystem,
// 			CompareAs: lockfile.NpmEcosystem,
// 			Commit:    "c5a7ba5e0ad98b8db1cb8ce105403dd4b768cced",
// 			DepGroups: []string{"dev"},
// 		},
// 		{
// 			Name:      "is-number-1",
// 			Version:   "3.0.0",
// 			Ecosystem: lockfile.NpmEcosystem,
// 			CompareAs: lockfile.NpmEcosystem,
// 			Commit:    "af885e2e890b9ef0875edd2b117305119ee5bdc5",
// 			DepGroups: []string{"dev"},
// 		},
// 		{
// 			Name:      "is-number-1",
// 			Version:   "3.0.0",
// 			Ecosystem: lockfile.NpmEcosystem,
// 			CompareAs: lockfile.NpmEcosystem,
// 			Commit:    "be5935f8d2595bcd97b05718ef1eeae08d812e10",
// 			DepGroups: []string{"dev"},
// 		},
// 		{
// 			Name:      "is-number-2",
// 			Version:   "2.0.0",
// 			Ecosystem: lockfile.NpmEcosystem,
// 			CompareAs: lockfile.NpmEcosystem,
// 			Commit:    "d5ac0584ee9ae7bd9288220a39780f155b9ad4c8",
// 			DepGroups: []string{"dev"},
// 		},
// 		{
// 			Name:      "is-number-2",
// 			Version:   "2.0.0",
// 			Ecosystem: lockfile.NpmEcosystem,
// 			CompareAs: lockfile.NpmEcosystem,
// 			Commit:    "82dcc8e914dabd9305ab9ae580709a7825e824f5",
// 			DepGroups: []string{"dev"},
// 		},
// 		{
// 			Name:      "is-number-3",
// 			Version:   "2.0.0",
// 			Ecosystem: lockfile.NpmEcosystem,
// 			CompareAs: lockfile.NpmEcosystem,
// 			Commit:    "d5ac0584ee9ae7bd9288220a39780f155b9ad4c8",
// 			DepGroups: []string{"dev"},
// 		},
// 		{
// 			Name:      "is-number-3",
// 			Version:   "3.0.0",
// 			Ecosystem: lockfile.NpmEcosystem,
// 			CompareAs: lockfile.NpmEcosystem,
// 			Commit:    "82ae8802978da40d7f1be5ad5943c9e550ab2c89",
// 			DepGroups: []string{"dev"},
// 		},
// 		{
// 			Name:      "is-number-4",
// 			Version:   "3.0.0",
// 			Ecosystem: lockfile.NpmEcosystem,
// 			CompareAs: lockfile.NpmEcosystem,
// 			Commit:    "af885e2e890b9ef0875edd2b117305119ee5bdc5",
// 			DepGroups: []string{"dev"},
// 		},
// 		{
// 			Name:      "is-number-5",
// 			Version:   "3.0.0",
// 			Ecosystem: lockfile.NpmEcosystem,
// 			CompareAs: lockfile.NpmEcosystem,
// 			Commit:    "af885e2e890b9ef0875edd2b117305119ee5bdc5",
// 			DepGroups: []string{"dev"},
// 		},
// 		{
// 			Name:      "postcss-calc",
// 			Version:   "7.0.1",
// 			Ecosystem: lockfile.NpmEcosystem,
// 			CompareAs: lockfile.NpmEcosystem,
// 			Commit:    "",
// 		},
// 		{
// 			Name:      "raven-js",
// 			Version:   "",
// 			Ecosystem: lockfile.NpmEcosystem,
// 			CompareAs: lockfile.NpmEcosystem,
// 			Commit:    "c2b377e7a254264fd4a1fe328e4e3cfc9e245570",
// 		},
// 		{
// 			Name:      "slick-carousel",
// 			Version:   "1.7.1",
// 			Ecosystem: lockfile.NpmEcosystem,
// 			CompareAs: lockfile.NpmEcosystem,
// 			Commit:    "280b560161b751ba226d50c7db1e0a14a78c2de0",
// 			DepGroups: []string{"dev"},
// 		},
// 	})
// }

// func TestParseNpmLock_v2_Files(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfile.ParseNpmLock("fixtures/npm/files.v2.json")

// 	if err != nil {
// 		t.Errorf("Got unexpected error: %v", err)
// 	}

// 	expectPackages(t, packages, []lockfile.PackageDetails{
// 		{
// 			Name:      "etag",
// 			Version:   "1.8.0",
// 			Ecosystem: lockfile.NpmEcosystem,
// 			CompareAs: lockfile.NpmEcosystem,
// 			Commit:    "",
// 			DepGroups: []string{"dev"},
// 		},
// 		{
// 			Name:      "abbrev",
// 			Version:   "1.0.9",
// 			Ecosystem: lockfile.NpmEcosystem,
// 			CompareAs: lockfile.NpmEcosystem,
// 			Commit:    "",
// 			DepGroups: []string{"dev"},
// 		},
// 		{
// 			Name:      "abbrev",
// 			Version:   "2.3.4",
// 			Ecosystem: lockfile.NpmEcosystem,
// 			CompareAs: lockfile.NpmEcosystem,
// 			Commit:    "",
// 			DepGroups: []string{"dev"},
// 		},
// 	})
// }

// func TestParseNpmLock_v2_Alias(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfile.ParseNpmLock("fixtures/npm/alias.v2.json")

// 	if err != nil {
// 		t.Errorf("Got unexpected error: %v", err)
// 	}

// 	expectPackages(t, packages, []lockfile.PackageDetails{
// 		{
// 			Name:      "@babel/code-frame",
// 			Version:   "7.0.0",
// 			Ecosystem: lockfile.NpmEcosystem,
// 			CompareAs: lockfile.NpmEcosystem,
// 		},
// 		{
// 			Name:      "string-width",
// 			Version:   "4.2.0",
// 			Ecosystem: lockfile.NpmEcosystem,
// 			CompareAs: lockfile.NpmEcosystem,
// 		},
// 		{
// 			Name:      "string-width",
// 			Version:   "5.1.2",
// 			Ecosystem: lockfile.NpmEcosystem,
// 			CompareAs: lockfile.NpmEcosystem,
// 		},
// 	})
// }

// func TestParseNpmLock_v2_OptionalPackage(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfile.ParseNpmLock("fixtures/npm/optional-package.v2.json")

// 	if err != nil {
// 		t.Errorf("Got unexpected error: %v", err)
// 	}

// 	expectPackages(t, packages, []lockfile.PackageDetails{
// 		{
// 			Name:      "wrappy",
// 			Version:   "1.0.2",
// 			Ecosystem: lockfile.NpmEcosystem,
// 			CompareAs: lockfile.NpmEcosystem,
// 			DepGroups: []string{"optional"},
// 		},
// 		{
// 			Name:      "supports-color",
// 			Version:   "5.5.0",
// 			Ecosystem: lockfile.NpmEcosystem,
// 			CompareAs: lockfile.NpmEcosystem,
// 			DepGroups: []string{"dev", "optional"},
// 		},
// 	})
// }

// func TestParseNpmLock_v2_SamePackageDifferentGroups(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfile.ParseNpmLock("fixtures/npm/same-package-different-groups.v2.json")

// 	if err != nil {
// 		t.Errorf("Got unexpected error: %v", err)
// 	}

// 	expectPackages(t, packages, []lockfile.PackageDetails{
// 		{
// 			Name:      "eslint",
// 			Version:   "1.2.3",
// 			Ecosystem: lockfile.NpmEcosystem,
// 			CompareAs: lockfile.NpmEcosystem,
// 			DepGroups: []string{"dev"},
// 		},
// 		{
// 			Name:      "table",
// 			Version:   "1.0.0",
// 			Ecosystem: lockfile.NpmEcosystem,
// 			CompareAs: lockfile.NpmEcosystem,
// 		},
// 		{
// 			Name:      "ajv",
// 			Version:   "5.5.2",
// 			Ecosystem: lockfile.NpmEcosystem,
// 			CompareAs: lockfile.NpmEcosystem,
// 		},
// 	})
// }
