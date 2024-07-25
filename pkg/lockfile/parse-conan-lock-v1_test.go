package lockfile_test

import (
	"testing"

	"github.com/google/osv-scanner/pkg/lockfile"
)

func TestConanLockExtractor_Extract_v1(t *testing.T) {
	t.Parallel()

	tests := []testTableEntry{
		{
			name: "invalid json",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/conan/not-json.txt",
			},
			wantErrContaining: "could not extract from",
		},
		{
			name: "no packages",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/conan/empty.v1.json",
			},
			wantInventory: []*lockfile.Inventory{},
		},
		{
			name: "one package",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/conan/one-package.v1.json",
			},
			wantInventory: []*lockfile.Inventory{
				{
					Name:      "zlib",
					Version:   "1.2.11",
					Locations: []string{"fixtures/conan/one-package.v1.json"},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			name: "no name",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/conan/no-name.v1.json",
			},
			wantInventory: []*lockfile.Inventory{
				{
					Name:      "zlib",
					Version:   "1.2.11",
					Locations: []string{"fixtures/conan/no-name.v1.json"},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			name: "two packages",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/conan/two-packages.v1.json",
			},
			wantInventory: []*lockfile.Inventory{
				{
					Name:      "zlib",
					Version:   "1.2.11",
					Locations: []string{"fixtures/conan/two-packages.v1.json"},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "bzip2",
					Version:   "1.0.8",
					Locations: []string{"fixtures/conan/two-packages.v1.json"},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			name: "nested dependencies",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/conan/nested-dependencies.v1.json",
			},
			wantInventory: []*lockfile.Inventory{
				{
					Name:      "zlib",
					Version:   "1.2.13",
					Locations: []string{"fixtures/conan/nested-dependencies.v1.json"},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "bzip2",
					Version:   "1.0.8",
					Locations: []string{"fixtures/conan/nested-dependencies.v1.json"},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "freetype",
					Version:   "2.12.1",
					Locations: []string{"fixtures/conan/nested-dependencies.v1.json"},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "libpng",
					Version:   "1.6.39",
					Locations: []string{"fixtures/conan/nested-dependencies.v1.json"},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "brotli",
					Version:   "1.0.9",
					Locations: []string{"fixtures/conan/nested-dependencies.v1.json"},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			name: "one package dev",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/conan/one-package-dev.v1.json",
			},
			wantInventory: []*lockfile.Inventory{
				{
					Name:      "ninja",
					Version:   "1.11.1",
					Locations: []string{"fixtures/conan/one-package-dev.v1.json"},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			name: "old format00",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/conan/old-format-0.0.json",
			},
			wantInventory: []*lockfile.Inventory{
				{
					Name:      "zlib",
					Version:   "1.2.11",
					Locations: []string{"fixtures/conan/old-format-0.0.json"},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			name: "old format01",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/conan/old-format-0.1.json",
			},
			wantInventory: []*lockfile.Inventory{
				{
					Name:      "zlib",
					Version:   "1.2.11",
					Locations: []string{"fixtures/conan/old-format-0.1.json"},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			name: "old format02",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/conan/old-format-0.2.json",
			},
			wantInventory: []*lockfile.Inventory{
				{
					Name:      "zlib",
					Version:   "1.2.11",
					Locations: []string{"fixtures/conan/old-format-0.2.json"},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			name: "old format03",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/conan/old-format-0.3.json",
			},
			wantInventory: []*lockfile.Inventory{
				{
					Name:      "zlib",
					Version:   "1.2.11",
					Locations: []string{"fixtures/conan/old-format-0.3.json"},
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

// func TestParseConanLock_v1_InvalidJson(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfile.ParseConanLock("fixtures/conan/not-json.txt")

// 	expectErrContaining(t, err, "could not extract from")
// 	expectPackages(t, packages, []lockfile.PackageDetails{})
// }

// func TestParseConanLock_v1_NoPackages(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfile.ParseConanLock("fixtures/conan/empty.v1.json")

// 	if err != nil {
// 		t.Errorf("Got unexpected error: %v", err)
// 	}

// 	expectPackages(t, packages, []lockfile.PackageDetails{})
// }

// func TestParseConanLock_v1_OnePackage(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfile.ParseConanLock("fixtures/conan/one-package.v1.json")

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

// func TestParseConanLock_v1_NoName(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfile.ParseConanLock("fixtures/conan/no-name.v1.json")

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

// func TestParseConanLock_v1_TwoPackages(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfile.ParseConanLock("fixtures/conan/two-packages.v1.json")

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

// func TestParseConanLock_v1_NestedDependencies(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfile.ParseConanLock("fixtures/conan/nested-dependencies.v1.json")

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

// func TestParseConanLock_v1_OnePackageDev(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfile.ParseConanLock("fixtures/conan/one-package-dev.v1.json")

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

// func TestParseConanLock_v1_OldFormat00(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfile.ParseConanLock("fixtures/conan/old-format-0.0.json")

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

// func TestParseConanLock_v1_OldFormat01(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfile.ParseConanLock("fixtures/conan/old-format-0.1.json")

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

// func TestParseConanLock_v1_OldFormat02(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfile.ParseConanLock("fixtures/conan/old-format-0.2.json")

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

// func TestParseConanLock_v1_OldFormat03(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfile.ParseConanLock("fixtures/conan/old-format-0.3.json")

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
