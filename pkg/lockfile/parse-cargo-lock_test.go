package lockfile_test

import (
	"context"
	"testing"

	"github.com/google/osv-scanner/pkg/lockfile"
)

func TestCargoLockExtractor_ShouldExtract(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		inputConfig ScanInputMockConfig
		want        bool
	}{
		{
			name: "Empty path",
			inputConfig: ScanInputMockConfig{
				path: "",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				path: "Cargo.lock",
			},
			want: true,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				path: "path/to/my/Cargo.lock",
			},
			want: true,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				path: "path/to/my/Cargo.lock/file",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				path: "path/to/my/Cargo.lock.file",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				path: "path.to.my.Cargo.lock",
			},
			want: false,
		},
	}
	for i, tt := range tests {
		tt := tt
		i := i
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := lockfile.CargoLockExtractor{}
			got := e.FileRequired(tt.inputConfig.path, GenerateFileInfoMock(t, tt.inputConfig))
			if got != tt.want {
				t.Errorf("[#%02d] FileRequired(%s, FileInfo) got = %v, want %v", i, tt.inputConfig.path, got, tt.want)
			}
		})
	}
}

func TestExtractCargoLock(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		inputConfig       ScanInputMockConfig
		wantInventory     []*lockfile.Inventory
		wantErrIs         error
		wantErrContaining string
	}{
		{
			name: "Invalid toml",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/cargo/not-toml.txt",
			},
			wantErrContaining: "could not extract from",
		},
		{
			name: "no packages",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/cargo/empty.lock",
			},
			wantInventory: []*lockfile.Inventory{},
		},
		{
			name: "one package",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/cargo/one-package.lock",
			},
			wantInventory: []*lockfile.Inventory{
				{
					Name:      "addr2line",
					Version:   "0.15.2",
					Locations: []string{"fixtures/cargo/one-package.lock"},
				},
			},
		},
		{
			name: "two packages",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/cargo/two-packages.lock",
			},
			wantInventory: []*lockfile.Inventory{
				{
					Name:      "addr2line",
					Version:   "0.15.2",
					Locations: []string{"fixtures/cargo/two-packages.lock"},
				},
				{
					Name:      "syn",
					Version:   "1.0.73",
					Locations: []string{"fixtures/cargo/two-packages.lock"},
				},
			},
		},
		{
			name: "two packages with local",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/cargo/two-packages-with-local.lock",
			},
			wantInventory: []*lockfile.Inventory{
				{
					Name:      "addr2line",
					Version:   "0.15.2",
					Locations: []string{"fixtures/cargo/two-packages-with-local.lock"},
				},
				{
					Name:      "local-rust-pkg",
					Version:   "0.1.0",
					Locations: []string{"fixtures/cargo/two-packages-with-local.lock"},
				},
			},
		},
		{
			name: "package with build string",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/cargo/package-with-build-string.lock",
			},
			wantInventory: []*lockfile.Inventory{
				{
					Name:      "wasi",
					Version:   "0.10.2+wasi-snapshot-preview1",
					Locations: []string{"fixtures/cargo/package-with-build-string.lock"},
				},
			},
		},
	}
	for i, tt := range tests {
		tt := tt
		i := i
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := lockfile.CargoLockExtractor{}
			wrapper := GenerateScanInputMock(t, tt.inputConfig)
			got, err := e.Extract(context.Background(), &wrapper.ScanInput)
			wrapper.Close()
			if tt.wantErrIs != nil {
				expectErrIs(t, err, tt.wantErrIs)
			}
			if tt.wantErrContaining != "" {
				expectErrContaining(t, err, tt.wantErrContaining)
			}
			FillExtractorField(got, e)
			FillExtractorField(tt.wantInventory, e)
			expectPackages(t, got, tt.wantInventory)
			if t.Failed() {
				t.Errorf("failed running [%d]: %s", i, tt.name)
			}
		})
	}
}

// func TestParseCargoLock_FileDoesNotExist(t *testing.T) {
// 	t.Parallel()

// 	extractor := lockfile.CargoLockExtractor{}
// 	extractor.Extract(context.Background())
// 	packages, err := lockfile.ParseCargoLock("fixtures/cargo/does-not-exist")

// 	expectErrIs(t, err, fs.ErrNotExist)
// 	expectPackages(t, packages, []lockfile.PackageDetails{})
// }

// func TestParseCargoLock_InvalidToml(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfile.ParseCargoLock("fixtures/cargo/not-toml.txt")

// 	expectErrContaining(t, err, "could not extract from")
// 	expectPackages(t, packages, []lockfile.PackageDetails{})
// }

// func TestParseCargoLock_NoPackages(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfile.ParseCargoLock("fixtures/cargo/empty.lock")

// 	if err != nil {
// 		t.Errorf("Got unexpected error: %v", err)
// 	}

// 	expectPackages(t, packages, []lockfile.PackageDetails{})
// }

// func TestParseCargoLock_OnePackage(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfile.ParseCargoLock("fixtures/cargo/one-package.lock")

// 	if err != nil {
// 		t.Errorf("Got unexpected error: %v", err)
// 	}

// 	expectPackages(t, packages, []lockfile.PackageDetails{
// 		{
// 			Name:      "addr2line",
// 			Version:   "0.15.2",
// 			Ecosystem: lockfile.CargoEcosystem,
// 			CompareAs: lockfile.CargoEcosystem,
// 		},
// 	})
// }

// func TestParseCargoLock_TwoPackages(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfile.ParseCargoLock("fixtures/cargo/two-packages.lock")

// 	if err != nil {
// 		t.Errorf("Got unexpected error: %v", err)
// 	}

// 	expectPackages(t, packages, []lockfile.PackageDetails{
// 		{
// 			Name:      "addr2line",
// 			Version:   "0.15.2",
// 			Ecosystem: lockfile.CargoEcosystem,
// 			CompareAs: lockfile.CargoEcosystem,
// 		},
// 		{
// 			Name:      "syn",
// 			Version:   "1.0.73",
// 			Ecosystem: lockfile.CargoEcosystem,
// 			CompareAs: lockfile.CargoEcosystem,
// 		},
// 	})
// }

// func TestParseCargoLock_TwoPackagesWithLocal(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfile.ParseCargoLock("fixtures/cargo/two-packages-with-local.lock")

// 	if err != nil {
// 		t.Errorf("Got unexpected error: %v", err)
// 	}

// 	expectPackages(t, packages, []lockfile.PackageDetails{
// 		{
// 			Name:      "addr2line",
// 			Version:   "0.15.2",
// 			Ecosystem: lockfile.CargoEcosystem,
// 			CompareAs: lockfile.CargoEcosystem,
// 		},
// 		{
// 			Name:      "local-rust-pkg",
// 			Version:   "0.1.0",
// 			Ecosystem: lockfile.CargoEcosystem,
// 			CompareAs: lockfile.CargoEcosystem,
// 		},
// 	})
// }

// func TestParseCargoLock_PackageWithBuildString(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfile.ParseCargoLock("fixtures/cargo/package-with-build-string.lock")

// 	if err != nil {
// 		t.Errorf("Got unexpected error: %v", err)
// 	}

// 	expectPackages(t, packages, []lockfile.PackageDetails{
// 		{
// 			Name:      "wasi",
// 			Version:   "0.10.2+wasi-snapshot-preview1",
// 			Ecosystem: lockfile.CargoEcosystem,
// 			CompareAs: lockfile.CargoEcosystem,
// 		},
// 	})
// }
