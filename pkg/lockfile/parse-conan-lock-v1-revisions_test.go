package lockfile_test

import (
	"testing"

	"github.com/google/osv-scanner/pkg/lockfile"
)

func TestConanLockExtractor_Extract_v1_revisions(t *testing.T) {
	t.Parallel()

	tests := []testTableEntry{
		{
			name: "no packages",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/conan/empty.v1.revisions.json",
			},
			wantInventory: []*lockfile.Inventory{},
		},
		{
			name: "one package",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/conan/one-package.v1.revisions.json",
			},
			wantInventory: []*lockfile.Inventory{
				{
					Name:      "zlib",
					Version:   "1.2.11",
					Locations: []string{"fixtures/conan/one-package.v1.revisions.json"},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			name: "no name",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/conan/no-name.v1.revisions.json",
			},
			wantInventory: []*lockfile.Inventory{
				{
					Name:      "zlib",
					Version:   "1.2.11",
					Locations: []string{"fixtures/conan/no-name.v1.revisions.json"},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			name: "two packages",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/conan/two-packages.v1.revisions.json",
			},
			wantInventory: []*lockfile.Inventory{
				{
					Name:      "zlib",
					Version:   "1.2.11",
					Locations: []string{"fixtures/conan/two-packages.v1.revisions.json"},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "bzip2",
					Version:   "1.0.8",
					Locations: []string{"fixtures/conan/two-packages.v1.revisions.json"},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			name: "nested dependencies",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/conan/nested-dependencies.v1.revisions.json",
			},
			wantInventory: []*lockfile.Inventory{
				{
					Name:      "zlib",
					Version:   "1.2.13",
					Locations: []string{"fixtures/conan/nested-dependencies.v1.revisions.json"},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "bzip2",
					Version:   "1.0.8",
					Locations: []string{"fixtures/conan/nested-dependencies.v1.revisions.json"},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "freetype",
					Version:   "2.12.1",
					Locations: []string{"fixtures/conan/nested-dependencies.v1.revisions.json"},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "libpng",
					Version:   "1.6.39",
					Locations: []string{"fixtures/conan/nested-dependencies.v1.revisions.json"},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "brotli",
					Version:   "1.0.9",
					Locations: []string{"fixtures/conan/nested-dependencies.v1.revisions.json"},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			name: "one package dev",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/conan/one-package-dev.v1.revisions.json",
			},
			wantInventory: []*lockfile.Inventory{
				{
					Name:      "ninja",
					Version:   "1.11.1",
					Locations: []string{"fixtures/conan/one-package-dev.v1.revisions.json"},
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
			e := lockfile.ConanLockExtractor{}
			_, _ = extractionTester(t, e, tt)
		})
	}
}

// func TestParseConanLock_v1_revisions_InvalidJson(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfile.ParseConanLock("fixtures/conan/not-json.txt")

// 	expectErrContaining(t, err, "could not extract from")
// 	expectPackages(t, packages, []lockfile.PackageDetails{})
// }

// func TestParseConanLock_v1_revisions_NoPackages(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfile.ParseConanLock("fixtures/conan/empty.v1.revisions.json")

// 	if err != nil {
// 		t.Errorf("Got unexpected error: %v", err)
// 	}

// 	expectPackages(t, packages, []lockfile.PackageDetails{})
// }

// func TestParseConanLock_v1_revisions_OnePackage(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfile.ParseConanLock("fixtures/conan/one-package.v1.revisions.json")

// 	if err != nil {
// 		t.Errorf("Got unexpected error: %v", err)
// 	}

// 	expectPackages(t, packages, []lockfile.PackageDetails{
// 		{
// 			Name:      "zlib",
// 			Version:   "1.2.11",
// 			Ecosystem: lockfile.ConanEcosystem,
// 			CompareAs: lockfile.ConanEcosystem,
// 		},
// 	})
// }

// func TestParseConanLock_v1_revisions_NoName(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfile.ParseConanLock("fixtures/conan/no-name.v1.revisions.json")

// 	if err != nil {
// 		t.Errorf("Got unexpected error: %v", err)
// 	}

// 	expectPackages(t, packages, []lockfile.PackageDetails{
// 		{
// 			Name:      "zlib",
// 			Version:   "1.2.11",
// 			Ecosystem: lockfile.ConanEcosystem,
// 			CompareAs: lockfile.ConanEcosystem,
// 		},
// 	})
// }

// func TestParseConanLock_v1_revisions_TwoPackages(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfile.ParseConanLock("fixtures/conan/two-packages.v1.revisions.json")

// 	if err != nil {
// 		t.Errorf("Got unexpected error: %v", err)
// 	}

// 	expectPackages(t, packages, []lockfile.PackageDetails{
// 		{
// 			Name:      "zlib",
// 			Version:   "1.2.11",
// 			Ecosystem: lockfile.ConanEcosystem,
// 			CompareAs: lockfile.ConanEcosystem,
// 		},
// 		{
// 			Name:      "bzip2",
// 			Version:   "1.0.8",
// 			Ecosystem: lockfile.ConanEcosystem,
// 			CompareAs: lockfile.ConanEcosystem,
// 		},
// 	})
// }

// func TestParseConanLock_v1_revisions_NestedDependencies(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfile.ParseConanLock("fixtures/conan/nested-dependencies.v1.revisions.json")

// 	if err != nil {
// 		t.Errorf("Got unexpected error: %v", err)
// 	}

// 	expectPackages(t, packages, []lockfile.PackageDetails{
// 		{
// 			Name:      "zlib",
// 			Version:   "1.2.13",
// 			Ecosystem: lockfile.ConanEcosystem,
// 			CompareAs: lockfile.ConanEcosystem,
// 		},
// 		{
// 			Name:      "bzip2",
// 			Version:   "1.0.8",
// 			Ecosystem: lockfile.ConanEcosystem,
// 			CompareAs: lockfile.ConanEcosystem,
// 		},
// 		{
// 			Name:      "freetype",
// 			Version:   "2.12.1",
// 			Ecosystem: lockfile.ConanEcosystem,
// 			CompareAs: lockfile.ConanEcosystem,
// 		},
// 		{
// 			Name:      "libpng",
// 			Version:   "1.6.39",
// 			Ecosystem: lockfile.ConanEcosystem,
// 			CompareAs: lockfile.ConanEcosystem,
// 		},
// 		{
// 			Name:      "brotli",
// 			Version:   "1.0.9",
// 			Ecosystem: lockfile.ConanEcosystem,
// 			CompareAs: lockfile.ConanEcosystem,
// 		},
// 	})
// }

// func TestParseConanLock_v1_revisions_OnePackageDev(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfile.ParseConanLock("fixtures/conan/one-package-dev.v1.revisions.json")

// 	if err != nil {
// 		t.Errorf("Got unexpected error: %v", err)
// 	}

// 	expectPackages(t, packages, []lockfile.PackageDetails{
// 		{
// 			Name:      "ninja",
// 			Version:   "1.11.1",
// 			Ecosystem: lockfile.ConanEcosystem,
// 			CompareAs: lockfile.ConanEcosystem,
// 		},
// 	})
// }
